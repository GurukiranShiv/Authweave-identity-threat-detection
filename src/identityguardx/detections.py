from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, List, Tuple

from .utils import get_path, haversine_km, is_email, lower_text, parse_time

DANGEROUS_OAUTH_SCOPES = {
    "mail.read", "mail.send", "files.read.all", "offline_access", "user.readwrite.all",
    "directory.readwrite.all", "mail.readwrite", "sites.read.all", "calendars.readwrite",
}


def _alert(alert_name: str, severity: str, risk_score: int, user: str, evidence: List[str], recommendations: List[str], mitre: List[str], raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "alert_name": alert_name,
        "severity": severity,
        "risk_score": risk_score,
        "user": user or "unknown",
        "evidence": evidence,
        "recommended_actions": recommendations,
        "mitre_attack": mitre,
        "event_count": len(raw_events),
        "events": raw_events[:10],
    }


def _severity(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 75:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def _event_time(event: Dict[str, Any]):
    return parse_time(get_path(event, "event.time"))


def _user(event: Dict[str, Any]) -> str:
    return str(get_path(event, "user.email") or get_path(event, "user.name") or "unknown")


def detect_impossible_travel(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    required = ["user.email", "event.time", "src.country"]
    if not any(get_path(e, "src.country") for e in events):
        return [], ["Impossible travel skipped: missing src.country or geo field."]
    if not any(get_path(e, "event.time") for e in events):
        return [], ["Impossible travel skipped: missing event.time field."]

    by_user = defaultdict(list)
    for e in events:
        if lower_text(get_path(e, "event.outcome")) in {"failure", "failed", "denied", "blocked"}:
            continue
        t = _event_time(e)
        country = get_path(e, "src.country")
        user = _user(e)
        if t and country and user != "unknown":
            by_user[user].append((t, country, e))

    alerts = []
    for user, rows in by_user.items():
        rows.sort(key=lambda x: x[0])
        for prev, cur in zip(rows, rows[1:]):
            t1, c1, e1 = prev
            t2, c2, e2 = cur
            if str(c1).lower() == str(c2).lower():
                continue
            hours = max((t2 - t1).total_seconds() / 3600, 0.01)
            dist = haversine_km(str(c1), str(c2))
            if dist is None:
                if hours <= 1.0:
                    score = 82
                else:
                    continue
            else:
                speed = dist / hours
                score = 95 if speed > 1200 else 85 if speed > 900 else 0
                if score == 0:
                    continue
            evidence = [
                f"Successful activity for {user} from {c1} at {t1.isoformat()}",
                f"Successful activity for {user} from {c2} at {t2.isoformat()}",
                f"Time gap: {round(hours * 60)} minutes; countries differ.",
            ]
            if dist:
                evidence.append(f"Estimated travel speed required: {round(dist / hours)} km/h.")
            alerts.append(_alert(
                "Impossible Travel",
                _severity(score),
                score,
                user,
                evidence,
                ["Revoke active sessions", "Reset password", "Review MFA method", "Check OAuth grants", "Escalate to L2 analyst"],
                ["T1078 Valid Accounts", "T1539 Steal Web Session Cookie"],
                [e1, e2]
            ))
    return alerts, []


def detect_mfa_fatigue(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    if not any(get_path(e, "auth.mfa_result") for e in events):
        return [], ["MFA fatigue skipped: missing auth.mfa_result field."]
    by_user = defaultdict(list)
    for e in events:
        t = _event_time(e)
        if t:
            by_user[_user(e)].append((t, lower_text(get_path(e, "auth.mfa_result")), e))
    alerts = []
    for user, rows in by_user.items():
        rows.sort(key=lambda x: x[0])
        for i, (t, result, e) in enumerate(rows):
            window = [(tt, rr, ev) for tt, rr, ev in rows if t <= tt <= t + timedelta(minutes=30)]
            prompts = [ev for tt, rr, ev in window if rr in {"prompted", "denied", "challenge", "required", "rejected"} or "prompt" in rr or "deny" in rr]
            approved = [ev for tt, rr, ev in window if rr in {"approved", "success", "satisfied"} or "approve" in rr]
            if len(prompts) >= 5 and approved:
                score = min(98, 70 + len(prompts) * 4)
                alerts.append(_alert(
                    "MFA Fatigue / Push Bombing Pattern",
                    _severity(score),
                    score,
                    user,
                    [
                        f"{len(prompts)} MFA prompts/denials followed by approval within 30 minutes.",
                        f"First observed at {t.isoformat()} for {user}.",
                    ],
                    ["Revoke sessions", "Reset password", "Move user to phishing-resistant MFA", "Review device and IP history"],
                    ["T1621 Multi-Factor Authentication Request Generation", "T1078 Valid Accounts"],
                    prompts[:5] + approved[:1]
                ))
                break
    return alerts, []


def detect_oauth_abuse(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    if not any(get_path(e, "oauth.scopes") or "oauth" in str(e).lower() or "consent" in str(e).lower() for e in events):
        return [], ["OAuth abuse skipped: no OAuth consent/scope fields detected."]
    alerts = []
    for e in events:
        scopes_raw = str(get_path(e, "oauth.scopes") or get_path(e, "raw.original.permissions") or get_path(e, "raw.original.scope") or "")
        low = scopes_raw.lower()
        dangerous = sorted(scope for scope in DANGEROUS_OAUTH_SCOPES if scope in low)
        text = str(e).lower()
        if dangerous or ("oauth" in text and "consent" in text and any(x in text for x in ["mail", "files", "directory", "offline_access"])):
            score = 92 if dangerous else 78
            user = _user(e)
            app = get_path(e, "oauth.app_name") or get_path(e, "app.name") or "unknown app"
            alerts.append(_alert(
                "Suspicious OAuth Consent / SaaS App Grant",
                _severity(score),
                score,
                user,
                [f"OAuth/SaaS consent activity detected for {app}.", f"Dangerous scopes: {', '.join(dangerous) if dangerous else 'permission pattern matched in raw event'}"],
                ["Revoke suspicious OAuth grant", "Review app publisher", "Search mailbox/file access after consent", "Reset user password if grant was unauthorized"],
                ["T1671 Cloud Application Integration", "T1098 Account Manipulation"],
                [e]
            ))
    return alerts, []


def detect_privilege_escalation(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    if not any(any(word in str(e).lower() for word in ["admin", "role", "privilege", "owner"]) for e in events):
        return [], ["Privilege escalation skipped: no role/admin/privilege fields detected."]
    alerts = []
    for e in events:
        text = str(e).lower()
        role = str(get_path(e, "role.name") or get_path(e, "user.role") or "")
        if any(x in text for x in ["global admin", "super admin", "administrator", "owner", "privileged", "role assigned", "add member to role"]):
            score = 88
            if any(x in text for x in ["global admin", "super admin"]):
                score = 95
            alerts.append(_alert(
                "Suspicious Privilege / Admin Role Change",
                _severity(score),
                score,
                _user(e),
                [f"Privileged role/admin activity detected. Role/context: {role or 'found in raw event'}"],
                ["Validate change ticket", "Review actor and target user", "Remove unauthorized role", "Audit recent admin activity"],
                ["T1098 Account Manipulation", "T1078 Valid Accounts"],
                [e]
            ))
    return alerts, []


def detect_mailbox_forwarding(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    if not any(any(word in str(e).lower() for word in ["forward", "redirect", "mailbox", "inboxrule", "inbox rule"]) for e in events):
        return [], ["Mailbox rule skipped: no forwarding/mailbox rule indicators detected."]
    alerts = []
    for e in events:
        text = str(e).lower()
        dest = str(get_path(e, "mail.forward_to") or "")
        if any(word in text for word in ["forward", "redirect", "inboxrule", "inbox rule"]):
            score = 80
            if dest and is_email(dest):
                user_domain = str(_user(e)).split("@")[-1].lower() if "@" in _user(e) else ""
                dest_domain = dest.split("@")[-1].lower()
                if user_domain and dest_domain and dest_domain != user_domain:
                    score = 92
            alerts.append(_alert(
                "Suspicious Mailbox Forwarding / Inbox Rule",
                _severity(score),
                score,
                _user(e),
                [f"Mailbox rule or forwarding behavior detected. Destination: {dest or 'unknown'}"],
                ["Disable suspicious rule", "Search mail access logs", "Review OAuth grants", "Reset password and revoke sessions"],
                ["T1114 Email Collection", "T1098 Account Manipulation"],
                [e]
            ))
    return alerts, []


def detect_dormant_account_abuse(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    alerts = []
    found_dormant_signal = False
    for e in events:
        raw = get_path(e, "raw.original", {}) or {}
        text = str(raw).lower() + " " + str(e).lower()
        days = None
        for key, value in raw.items():
            lk = str(key).lower()
            if any(x in lk for x in ["inactive", "dormant", "dayssincelast", "days_since_last", "lastseen_days"]):
                found_dormant_signal = True
                try:
                    days = int(float(value))
                    break
                except Exception:
                    pass
        if days is None:
            m = re.search(r"(?:inactive|dormant)[^0-9]{0,10}(\d{2,4})", text)
            if m:
                found_dormant_signal = True
                days = int(m.group(1))
        if days and days >= 60:
            score = 86 if days < 120 else 94
            alerts.append(_alert(
                "Dormant Account Re-Activation / Abuse",
                _severity(score),
                score,
                _user(e),
                [f"Account shows activity after approximately {days} inactive days."],
                ["Disable account pending review", "Validate business need", "Reset password", "Review recent actions and OAuth grants"],
                ["T1078 Valid Accounts"],
                [e]
            ))
    if not found_dormant_signal:
        return [], ["Dormant account detection skipped: no inactive/dormant-days field detected."]
    return alerts, []


def detect_suspicious_saas_activity(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    keywords = ["repo", "secret", "token", "admin", "workspace", "channel", "export", "download", "delete", "owner"]
    if not any(any(k in str(e).lower() for k in keywords) for e in events):
        return [], ["Suspicious SaaS activity skipped: no SaaS/admin/action indicators detected."]
    alerts = []
    for e in events:
        text = str(e).lower()
        app = lower_text(get_path(e, "app.name"))
        if any(app_name in app for app_name in ["github", "slack", "google", "workspace"]) or any(k in text for k in ["repo", "channel", "workspace", "secret", "token"]):
            if any(k in text for k in ["owner", "admin", "delete", "export", "secret", "token", "external"]):
                score = 76
                alerts.append(_alert(
                    "Suspicious SaaS Administrative Activity",
                    _severity(score),
                    score,
                    _user(e),
                    ["SaaS audit event contains admin/high-impact keywords such as owner/admin/delete/export/secret/token/external."],
                    ["Validate actor permissions", "Review related audit trail", "Check for data export or secret access", "Escalate if unauthorized"],
                    ["T1098 Account Manipulation", "T1530 Data from Cloud Storage"],
                    [e]
                ))
    return alerts, []


def run_detections(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    detectors = [
        detect_impossible_travel,
        detect_mfa_fatigue,
        detect_oauth_abuse,
        detect_privilege_escalation,
        detect_mailbox_forwarding,
        detect_dormant_account_abuse,
        detect_suspicious_saas_activity,
    ]
    all_alerts: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for detector in detectors:
        alerts, skip_reasons = detector(events)
        all_alerts.extend(alerts)
        skipped.extend(skip_reasons)
    # Deduplicate very similar alerts by name+user+first evidence.
    unique = []
    seen = set()
    for alert in sorted(all_alerts, key=lambda a: a.get("risk_score", 0), reverse=True):
        key = (alert.get("alert_name"), alert.get("user"), tuple(alert.get("evidence", [])[:2]))
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return {
        "alerts": unique,
        "skipped_detections": skipped,
        "summary": {
            "events_analyzed": len(events),
            "alerts_generated": len(unique),
            "critical": sum(1 for a in unique if a.get("severity") == "Critical"),
            "high": sum(1 for a in unique if a.get("severity") == "High"),
            "medium": sum(1 for a in unique if a.get("severity") == "Medium"),
            "low": sum(1 for a in unique if a.get("severity") == "Low"),
        },
    }
