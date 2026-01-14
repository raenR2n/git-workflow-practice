import json
import os
import pandas as pd
from datetime import datetime
from google.cloud import storage
from google.cloud import securitycenter


def generate_scc_report(request):
    """
    Cloud Function entry point
    Generates SCC vulnerability reports (VM + K8s)
    for multiple hardcoded GCP projects with pagination support
    """

    # ---------------------------
    # Hardcoded project list
    # ---------------------------
    PROJECT_IDS = [
        "toorak-396910",
        "merchants-396910",
        "shared-infrastructure-396910",
        "network-396910",
        "dev-ops-396910",
        "table-funding",
        "originator-platform-396910"
    ]

    # ---------------------------
    # Environment configuration
    # ---------------------------
    GCS_BUCKET = os.environ.get("GCS_BUCKET")
    if not GCS_BUCKET:
        return "ERROR: GCS_BUCKET environment variable must be set", 500

    FILTER = (
        'state="ACTIVE" '
        'AND NOT mute="MUTED" '
        'AND (severity="CRITICAL" OR severity="HIGH") '
        'AND (category = "SOFTWARE_VULNERABILITY")'
    )

    TIMESTAMP = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    storage_client = storage.Client()
    bucket = storage_client.bucket(GCS_BUCKET)

    # ---------------------------
    # SCC client (NEW)
    # ---------------------------
    ORG_ID = "123456789012"  # 🔴 replace with real org id
    PARENT = f"organizations/{ORG_ID}/sources/-"
    scc_client = securitycenter.SecurityCenterClient()

    summary = []

    # =====================================================
    # NEW: CATEGORY → GCS FOLDER MAPPING
    # =====================================================
    CATEGORY_FOLDER_MAP = {
        "SOFTWARE_VULNERABILITY": "software_vulnerabilities",
        "OS_VULNERABILITY": "OS_vulnerabilities",
    }

    # =====================================================
    # NEW: PROJECT → GCS FOLDER MAPPING
    # =====================================================
    PROJECT_FOLDER_MAP = {
        "dev-ops-396910": "devops",
        "merchants-396910": "mmtc",
        "network-396910": "network",
        "toorak-396910": "tc",
        "shared-infrastructure-396910": "si",
        "table-funding": "tf",
        "originator-platform-396910": "op"
    }

    # ---------------------------
    # Loop through projects
    # ---------------------------
    for PROJECT_ID in PROJECT_IDS:
        try:
            print(f"▶ Processing project: {PROJECT_ID}")

            # ---------------------------
            # Fetch findings (NO pagination code)
            # ---------------------------
            all_data = []

            request_scc = {
                "parent": PARENT,
                "filter": (
                    f'{FILTER} AND '
                    f'resource.project_display_name="{PROJECT_ID}"'
                ),
            }

            for result in scc_client.list_findings(request=request_scc):
                all_data.append({
                    "finding": result.finding,
                    "resource": result.resource,
                })

            print(f"✅ {PROJECT_ID}: Retrieved {len(all_data)} findings")

            if not all_data:
                summary.append(f"{PROJECT_ID}: SUCCESS (No findings)")
                continue

            # ---------------------------
            # Bucket findings by category
            # ---------------------------
            category_buckets = {}
            for item in all_data:
                finding_data = item["finding"]
                category = finding_data.category or "UNKNOWN"
                category_buckets.setdefault(category, []).append(item)

            # ---------------------------
            # Process per category
            # ---------------------------
            for CATEGORY, findings in category_buckets.items():

                # =====================================================
                # NEW: Resolve existing GCS folders (NO creation)
                # =====================================================
                top_level_folder = CATEGORY_FOLDER_MAP.get(CATEGORY)
                project_folder = PROJECT_FOLDER_MAP.get(PROJECT_ID)

                if not top_level_folder or not project_folder:
                    raise ValueError(
                        f"Missing folder mapping for CATEGORY={CATEGORY}, PROJECT_ID={PROJECT_ID}"
                    )

                # ---------------------------
                # Output file paths (local)
                # ---------------------------
                OUTPUT_EXCEL = f"/tmp/scc_{PROJECT_ID}_{CATEGORY}_{TIMESTAMP}.xlsx"
                # OUTPUT_CSV = f"/tmp/scc_{PROJECT_ID}_{CATEGORY}_{TIMESTAMP}.csv"  # CSV commented out

                # ---------------------------
                # Output file paths (GCS)
                # ---------------------------
                GCS_EXCEL_PATH = (
                    f"SCC-Reports/{top_level_folder}/{project_folder}/"
                    f"scc_{PROJECT_ID}_{TIMESTAMP}.xlsx"
                )

                # GCS_CSV_PATH = (  # CSV commented out
                #     f"SCC-Reports/{top_level_folder}/{project_folder}/"
                #     f"scc_{PROJECT_ID}_{TIMESTAMP}.csv"
                # )

                # ---------------------------
                # Process findings
                # ---------------------------
                vms = []
                k8s = []

                for item in findings:
                    finding = item["finding"]
                    resource = item["resource"]

                    resource_type = resource.type
                    vulnerability = finding.vulnerability

                    fixed = vulnerability.fixed_package
                    offending = vulnerability.offending_package

                    base_row = {
                        "severity": finding.severity,
                        "cve_id": vulnerability.cve.id if vulnerability.cve else None,
                        "package_name": (
                            offending.package_name
                            if offending and offending.package_name
                            else fixed.package_name
                        ),
                        "package_type": (
                            offending.package_type
                            if offending and offending.package_type
                            else fixed.package_type
                        ),
                        "offending_package_version": (
                            offending.package_version if offending else None
                        ),
                        "fixed_package_version": (
                            fixed.package_version if fixed else None
                        ),
                    }

                    affected_files_list = []
                    for f in finding.files:
                        if f.path:
                            affected_files_list.append(f.path)

                    base_row["affected_files"] = "\n".join(affected_files_list)

                    if resource_type == "google.compute.Instance":
                        vms.append(
                            {
                                **base_row,
                                "vm_name": resource.display_name,
                                "event_time": finding.event_time,
                            }
                        )

                    elif resource_type == "google.container.Cluster":
                        k8s_objects = finding.kubernetes.objects
                        if not k8s_objects:
                            continue

                        k8s_obj = k8s_objects[0]
                        containers = k8s_obj.containers

                        container_uris = [
                            c.uri for c in containers if c.uri
                        ]
                        image_uri = ", ".join(container_uris)

                        k8s.append(
                            {
                                **base_row,
                                "cluster_name": resource.display_name,
                                "namespace": k8s_obj.ns,
                                "k8s_object_name": k8s_obj.name,
                                "image_uri": image_uri,
                                "event_time": finding.event_time,
                            }
                        )

                # ---------------------------
                # Create DataFrames
                # ---------------------------
                df_vms = pd.DataFrame(vms)
                df_k8s = pd.DataFrame(k8s)

                # ---------------------------
                # Write Excel
                # ---------------------------
                with pd.ExcelWriter(OUTPUT_EXCEL, engine="openpyxl") as writer:
                    df_vms.to_excel(writer, sheet_name="VMs", index=False)
                    df_k8s.to_excel(writer, sheet_name="Kubernetes", index=False)

                # ---------------------------
                # CSV generation commented out
                # ---------------------------
                # df_vms_csv = df_vms.copy()
                # df_vms_csv.insert(0, "resource_type", "VM")

                # df_k8s_csv = df_k8s.copy()
                # df_k8s_csv.insert(0, "resource_type", "Kubernetes")

                # df_combined = pd.concat(
                #     [df_vms_csv, df_k8s_csv], ignore_index=True
                # )
                # df_combined["affected_files"] = df_combined[
                #     "affected_files"
                # ].str.replace("\n", "; ", regex=False)

                # df_combined.to_csv(OUTPUT_CSV, index=False)

                # ---------------------------
                # Upload to GCS (Excel only)
                # ---------------------------
                bucket.blob(GCS_EXCEL_PATH).upload_from_filename(OUTPUT_EXCEL)
                # bucket.blob(GCS_CSV_PATH).upload_from_filename(OUTPUT_CSV)  # CSV upload commented out

                print(
                    f"✅ Uploaded {PROJECT_ID} ({CATEGORY})\n"
                    f"   - {GCS_EXCEL_PATH}\n"
                    # f"   - {GCS_CSV_PATH}\n"  # CSV path commented out
                    f"   (VMs={len(df_vms)}, K8s={len(df_k8s)})"
                )

                # ---------------------------
                # Cleanup
                # ---------------------------
                os.remove(OUTPUT_EXCEL)
                # os.remove(OUTPUT_CSV)  # CSV cleanup commented out

            summary.append(f"{PROJECT_ID}: SUCCESS")

        except Exception as e:
            summary.append(f"{PROJECT_ID}: FAILED ({str(e)})")
            print(str(e))

    # ---------------------------
    # Final response
    # ---------------------------
    return (
        "SCC report generation completed\n\n" + "\n".join(summary),
        200,
    )
