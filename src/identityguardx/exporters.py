from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .summarizer import build_investigation_brief


def build_ocsf_findings(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    severity_id = {"Low": 2, "Medium": 3, "High": 4, "Critical": 5}
    findings = []
    for idx, alert in enumerate(alerts, 1):
        findings.append({
            "class_name": "Security Finding",
            "category_name": "Identity & Access Activity",
            "activity_name": alert.get("alert_name"),
            "finding_info": {
                "uid": f"igx-{idx:04d}",
                "title": alert.get("alert_name"),
                "desc": "IdentityGuardX normalized telemetry detection finding.",
            },
            "severity": alert.get("severity"),
            "severity_id": severity_id.get(alert.get("severity"), 1),
            "risk_score": alert.get("risk_score"),
            "actor": {"user": {"email_addr": alert.get("user")}},
            "evidences": alert.get("evidence", []),
            "remediation": {"desc": "; ".join(alert.get("recommended_actions", []))},
            "attack": {"tactics": alert.get("mitre_attack", [])},
        })
    return findings


def build_siem_queries(alerts: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
    queries = {"splunk_spl": [], "microsoft_kql": [], "elastic_kql": []}
    for alert in alerts:
        user = alert.get("user", "unknown")
        name = alert.get("alert_name", "Security Alert")
        safe_user = user.replace('"', '')
        queries["splunk_spl"].append({
            "alert": name,
            "query": f'index=identity OR index=o365 OR index=okta user="{safe_user}" | table _time user src_ip src_country app action outcome mfa_result'
        })
        queries["microsoft_kql"].append({
            "alert": name,
            "query": f"SigninLogs | where UserPrincipalName =~ '{safe_user}' | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, ConditionalAccessStatus"
        })
        queries["elastic_kql"].append({
            "alert": name,
            "query": f'user.email : "{safe_user}" and event.category : (authentication or iam)'
        })
    return queries


def build_sigma_like_rules(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rules = []
    for idx, alert in enumerate(alerts, 1):
        rules.append({
            "title": alert.get("alert_name"),
            "id": f"identityguardx-rule-{idx:03d}",
            "status": "experimental",
            "description": "Sigma-like educational rule generated from IdentityGuardX detection output.",
            "logsource": {"category": "identity", "product": "saas"},
            "detection": {
                "selection": {"user.email": alert.get("user")},
                "condition": "selection"
            },
            "level": str(alert.get("severity", "medium")).lower(),
            "tags": alert.get("mitre_attack", []),
        })
    return rules


def write_outputs(output_dir: str, normalized_events: List[Dict[str, Any]], mapping_profile: Dict[str, Any], detection_result: Dict[str, Any]) -> Dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    alerts = detection_result.get("alerts", [])
    paths = {
        "normalized_events": out / "normalized_events.json",
        "mapping_profile": out / "mapping_profile.yaml",
        "alerts": out / "alerts.json",
        "ocsf_style_findings": out / "ocsf_style_findings.json",
        "siem_queries": out / "siem_queries.json",
        "sigma_like_rules": out / "sigma_like_rules.yaml",
        "soc_investigation_brief": out / "soc_investigation_brief.md",
    }
    paths["normalized_events"].write_text(json.dumps(normalized_events, indent=2, default=str), encoding="utf-8")
    paths["mapping_profile"].write_text(yaml.safe_dump(mapping_profile, sort_keys=False), encoding="utf-8")
    paths["alerts"].write_text(json.dumps(detection_result, indent=2, default=str), encoding="utf-8")
    paths["ocsf_style_findings"].write_text(json.dumps(build_ocsf_findings(alerts), indent=2, default=str), encoding="utf-8")
    paths["siem_queries"].write_text(json.dumps(build_siem_queries(alerts), indent=2), encoding="utf-8")
    paths["sigma_like_rules"].write_text(yaml.safe_dump(build_sigma_like_rules(alerts), sort_keys=False), encoding="utf-8")
    brief = build_investigation_brief(alerts, detection_result.get("skipped_detections", []))
    paths["soc_investigation_brief"].write_text(brief, encoding="utf-8")
    return {k: str(v) for k, v in paths.items()}
