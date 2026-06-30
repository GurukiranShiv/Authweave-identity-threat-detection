from __future__ import annotations

from typing import Any, Dict, List


def build_alert_summary(alert: Dict[str, Any]) -> str:
    evidence = alert.get("evidence", [])
    actions = alert.get("recommended_actions", [])
    mitre = alert.get("mitre_attack", [])
    lines = [
        f"### {alert.get('severity', 'Unknown')} — {alert.get('alert_name', 'Security Alert')}",
        "",
        f"**User:** {alert.get('user', 'unknown')}",
        f"**Risk Score:** {alert.get('risk_score', 0)}/100",
        "",
        "**AI Investigation Summary:**",
        f"IdentityGuardX detected {alert.get('alert_name', 'a suspicious identity event')} for {alert.get('user', 'unknown')}. "
        f"The alert is rated {alert.get('severity', 'Unknown')} based on the number and quality of correlated evidence points. "
        "The finding should be reviewed by a SOC analyst before containment actions are applied.",
        "",
        "**Evidence:**",
    ]
    for item in evidence:
        lines.append(f"- {item}")
    lines.extend(["", "**Recommended SOC Actions:**"])
    for action in actions:
        lines.append(f"- {action}")
    if mitre:
        lines.extend(["", "**MITRE ATT&CK Mapping:**"])
        for item in mitre:
            lines.append(f"- {item}")
    return "\n".join(lines)


def build_investigation_brief(alerts: List[Dict[str, Any]], skipped: List[str] | None = None) -> str:
    skipped = skipped or []
    if not alerts:
        lines = [
            "# IdentityGuardX SOC Investigation Brief",
            "",
            "No high-confidence identity threats were detected in the uploaded telemetry.",
            "",
            "This does not prove the activity is safe. It means the available fields and values did not satisfy the current detection rules.",
        ]
        if skipped:
            lines.extend(["", "## Skipped or Limited Detections"])
            for item in skipped:
                lines.append(f"- {item}")
        return "\n".join(lines)

    top = max(alerts, key=lambda a: a.get("risk_score", 0))
    lines = [
        "# IdentityGuardX SOC Investigation Brief",
        "",
        f"IdentityGuardX generated **{len(alerts)} alert(s)** from the uploaded identity/security telemetry.",
        f"The highest-risk finding is **{top.get('alert_name')}** for **{top.get('user')}** with a risk score of **{top.get('risk_score')}/100**.",
        "",
        "## Executive Summary",
        "The uploaded logs were normalized into a unified identity schema and analyzed for risky sign-ins, impossible travel, MFA abuse, OAuth consent risk, privilege changes, mailbox forwarding, dormant account activity, and suspicious SaaS administration. The generated findings below are based on structured detection logic, and this brief summarizes the evidence in analyst-friendly language.",
        "",
    ]
    for alert in alerts:
        lines.append(build_alert_summary(alert))
        lines.append("\n---\n")
    if skipped:
        lines.extend(["## Skipped or Limited Detections"])
        for item in skipped:
            lines.append(f"- {item}")
    return "\n".join(lines)
