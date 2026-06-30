from __future__ import annotations

import json
from pathlib import Path
import sys

import pandas as pd
import streamlit as st
import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from identityguardx.pipeline import run_pipeline

st.set_page_config(page_title="IdentityGuardX", page_icon="🛡️", layout="wide")

st.title("🛡️ IdentityGuardX")
st.caption("Identity Telemetry Normalization & Threat Detection Platform")

st.markdown(
    """
Upload identity, SaaS, VPN, or security telemetry. IdentityGuardX inspects field names and values, maps them into a unified identity schema, runs threat detections, and generates an AI-style SOC investigation brief.
"""
)

with st.sidebar:
    st.header("Project Flow")
    st.markdown(
        """
1. Drag & drop log file  
2. Auto-detect file type  
3. Infer field mappings  
4. Normalize telemetry  
5. Run detections  
6. Generate SOC summary  
7. Export SIEM-ready outputs
"""
    )
    source = st.selectbox(
        "Source hint",
        ["auto", "microsoft_entra", "okta", "google_workspace", "m365", "github", "slack", "vpn", "custom"],
        index=0,
    )

uploaded_file = st.file_uploader(
    "Drag and drop CSV, JSON, NDJSON, TXT/LOG, or Excel identity/security logs",
    type=["csv", "json", "ndjson", "jsonl", "txt", "log", "xlsx"],
    help="Files with different field names or no headers can still work when values are meaningful, such as timestamps, emails, IPs, countries, apps, MFA values, and outcomes.",
)

sample_col1, sample_col2, sample_col3 = st.columns(3)
with sample_col1:
    st.info("Try: sample_data/entra_signins.csv")
with sample_col2:
    st.info("Try: sample_data/headerless_identity_log.csv")
with sample_col3:
    st.info("Try: sample_data/custom_identity_events.csv")

if uploaded_file is not None:
    temp_dir = ROOT / "temp_uploads"
    temp_dir.mkdir(exist_ok=True)
    safe_name = Path(uploaded_file.name).name
    input_path = temp_dir / safe_name
    input_path.write_bytes(uploaded_file.getbuffer())

    st.success(f"Uploaded: {safe_name}")
    with st.spinner("Normalizing telemetry and running identity threat detections..."):
        result = run_pipeline(str(input_path), source=source, output_dir=str(ROOT / "outputs" / "dashboard_upload"))

    parse_info = result["parse_info"]
    norm_summary = result["normalization_summary"]
    detection_summary = result["detections"]["summary"]
    alerts = result["detections"]["alerts"]

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Rows Parsed", parse_info.get("rows", 0))
    kpi2.metric("Mapped Fields", norm_summary.get("mapped_fields", 0))
    kpi3.metric("Alerts", detection_summary.get("alerts_generated", 0))
    kpi4.metric("Critical/High", detection_summary.get("critical", 0) + detection_summary.get("high", 0))

    tabs = st.tabs([
        "Alerts",
        "AI SOC Brief",
        "Field Mapping",
        "Normalized Events",
        "SIEM Exports",
        "Skipped Detections",
    ])

    with tabs[0]:
        st.subheader("Threat Detection Results")
        if not alerts:
            st.warning("No high-confidence alerts were generated. Check skipped detections and field mapping quality.")
        else:
            for alert in alerts:
                with st.expander(f"{alert['severity']} | {alert['alert_name']} | {alert['user']} | Risk {alert['risk_score']}", expanded=True):
                    st.write("**Evidence**")
                    for e in alert.get("evidence", []):
                        st.write(f"- {e}")
                    st.write("**Recommended Actions**")
                    for action in alert.get("recommended_actions", []):
                        st.write(f"- {action}")
                    st.write("**MITRE ATT&CK**")
                    st.write(", ".join(alert.get("mitre_attack", [])) or "Not mapped")

    with tabs[1]:
        st.subheader("AI Investigation Summarizer")
        st.markdown(result["ai_investigation_brief"])

    with tabs[2]:
        st.subheader("Adaptive Field Mapping")
        mappings = result["mapping_profile"].get("mappings", [])
        if mappings:
            st.dataframe(pd.DataFrame(mappings), use_container_width=True)
        st.write("**Unmapped fields kept as raw context**")
        unmapped = result["mapping_profile"].get("unmapped_fields", [])
        if unmapped:
            st.dataframe(pd.DataFrame(unmapped), use_container_width=True)
        else:
            st.success("No unmapped fields.")

    with tabs[3]:
        st.subheader("Normalized Identity Events")
        st.json(result["normalized_events"][:20])

    with tabs[4]:
        st.subheader("SIEM-Ready Outputs")
        st.write("**Splunk SPL / Microsoft KQL / Elastic KQL**")
        st.json(result["siem_queries"])
        st.write("**OCSF-style findings**")
        st.json(result["ocsf_style_findings"])
        st.write("**Sigma-like rules**")
        st.code(yaml.safe_dump(result["sigma_like_rules"], sort_keys=False), language="yaml")

        st.download_button(
            "Download SOC Investigation Brief",
            data=result["ai_investigation_brief"],
            file_name="soc_investigation_brief.md",
            mime="text/markdown",
        )
        st.download_button(
            "Download Normalized Events JSON",
            data=json.dumps(result["normalized_events"], indent=2, default=str),
            file_name="normalized_events.json",
            mime="application/json",
        )
        st.download_button(
            "Download Mapping Profile YAML",
            data=yaml.safe_dump(result["mapping_profile"], sort_keys=False),
            file_name="mapping_profile.yaml",
            mime="text/yaml",
        )

    with tabs[5]:
        st.subheader("Skipped or Limited Detections")
        skipped = result["detections"].get("skipped_detections", [])
        if skipped:
            for item in skipped:
                st.write(f"- {item}")
        else:
            st.success("All detection modules had enough context to run.")
else:
    st.markdown("---")
    st.subheader("What works with custom files?")
    st.markdown(
        """
- Different field names such as `account`, `source_address`, `geo_location`, `auth_status`, and `service_name`.
- Headerless CSV/Excel files where values reveal meaning, such as email, timestamp, IP, country, app, outcome, and MFA status.
- TXT/LOG files with `key=value` pairs or delimiter-separated values.
- Missing fields are handled safely. Detections are skipped instead of producing fake alerts.
"""
    )
