from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .utils import (
    compact,
    flatten_dict,
    is_country,
    is_email,
    is_failure,
    is_ipv4,
    is_success,
    is_timestamp,
    looks_like_app,
    looks_like_mfa,
    looks_like_oauth,
    looks_like_role,
    normalize_country,
    parse_time,
    sha256_json,
    unflatten_event,
)

NORMALIZED_FIELDS = [
    "event.time",
    "event.type",
    "event.outcome",
    "user.email",
    "user.name",
    "user.id",
    "user.role",
    "src.ip",
    "src.country",
    "src.city",
    "src.device",
    "src.user_agent",
    "app.name",
    "app.vendor",
    "auth.mfa_result",
    "auth.method",
    "oauth.app_name",
    "oauth.scopes",
    "role.action",
    "role.name",
    "mail.rule_action",
    "mail.forward_to",
    "raw.message",
]

FIELD_ALIASES: Dict[str, List[str]] = {
    "event.time": [
        "time", "timestamp", "date", "datetime", "created", "createdat", "eventtime", "event_time",
        "activitydatetime", "logintime", "login_time", "published", "when", "occurred", "event.created",
        "systemtime", "@timestamp"
    ],
    "event.type": [
        "eventtype", "event_type", "operation", "action", "activity", "event", "type", "category",
        "activitytype", "event.action"
    ],
    "event.outcome": [
        "result", "outcome", "status", "authstatus", "auth_status", "loginresult", "login_result",
        "signinstatus", "status.errorcode", "success", "errorcode", "resultcode", "response", "decision"
    ],
    "user.email": [
        "userprincipalname", "user", "username", "account", "email", "actor.alternateid", "actor.email",
        "user.email", "user_name", "user.name", "userid", "user_id", "principal", "identity", "login", "member",
        "targetuser", "target_user", "actor", "upn", "userprincipal", "employeeemail"
    ],
    "user.name": ["display_name", "fullname", "full_name", "actor.displayname"],
    "user.id": ["id", "userid", "user_id", "actor.id", "subject.id", "principalid"],
    "user.role": ["role", "roles", "userrole", "user_role", "privilege", "permission", "isadmin", "admin"],
    "src.ip": [
        "ip", "ipaddress", "ip_address", "sourceip", "source_ip", "srcip", "src_ip", "clientip", "client_ip",
        "client.ipaddress", "sourceaddress", "source_address", "remoteip", "remote_ip", "originip", "origin_ip"
    ],
    "src.country": [
        "country", "countryorregion", "location.countryorregion", "geo.country", "geolocation", "geo_location",
        "client.geographicalcontext.country", "sourcecountry", "source_country", "src_country", "regioncountry"
    ],
    "src.city": ["city", "location.city", "geo.city", "client.geographicalcontext.city", "sourcecity", "source_city"],
    "src.device": [
        "device", "devicename", "device_name", "deviceid", "device_id", "deviceinfo", "device_info",
        "platform", "os", "operatingsystem", "browser", "client", "endpoint"
    ],
    "src.user_agent": ["useragent", "user_agent", "agent", "browserdetails", "client.useragent", "http.user_agent"],
    "app.name": [
        "app", "application", "applicationname", "appname", "app_name", "appdisplayname", "displayname",
        "target.displayname", "application_name", "servicename", "service_name", "service", "resource", "workload", "product"
    ],
    "app.vendor": ["vendor", "provider", "source", "sourcetype", "source_vendor", "platform", "system"],
    "auth.mfa_result": [
        "mfa", "mfaresult", "mfa_result", "mfadetail", "mfa_detail", "mfarequired", "mfa_required",
        "mfastatus", "mfa_status", "factorresult", "factor_result", "secondfactor", "second_factor", "auth.factor"
    ],
    "auth.method": ["authmethod", "auth_method", "authenticationmethod", "method", "protocol", "granttype", "grant_type"],
    "oauth.app_name": ["oauthapp", "oauth_app", "clientapp", "client_app", "appconsented", "consented_app", "serviceprincipal", "clientid"],
    "oauth.scopes": ["scopes", "scope", "permissions", "permission", "oauthscopes", "oauth_scopes", "consentpermissions", "resourceaccess"],
    "role.action": ["roleaction", "role_action", "assignmentaction", "operation", "action"],
    "role.name": ["rolename", "role_name", "assignedrole", "assigned_role", "privilegename", "permissionname"],
    "mail.rule_action": ["ruleaction", "rule_action", "mailrule", "mail_rule", "inboxrule", "inbox_rule", "forwardingrule", "operation"],
    "mail.forward_to": ["forwardto", "forward_to", "redirectto", "redirect_to", "recipient", "externalrecipient", "destination"],
    "raw.message": ["message", "raw", "raw.message", "description", "details", "detail"]
}

TARGET_KEYWORDS: Dict[str, List[str]] = {
    "event.time": ["time", "date", "timestamp", "created", "occurred", "login"],
    "event.type": ["type", "event", "operation", "action", "activity"],
    "event.outcome": ["status", "result", "outcome", "success", "failure", "error", "decision"],
    "user.email": ["user", "email", "account", "principal", "actor", "identity", "login", "upn"],
    "user.role": ["role", "admin", "privilege", "permission"],
    "src.ip": ["ip", "address", "source", "client", "remote", "origin"],
    "src.country": ["country", "geo", "location", "region"],
    "src.city": ["city", "geo", "location"],
    "src.device": ["device", "host", "browser", "os", "platform", "endpoint", "client"],
    "src.user_agent": ["agent", "browser", "useragent"],
    "app.name": ["app", "application", "service", "resource", "workload", "product"],
    "app.vendor": ["vendor", "provider", "source", "platform"],
    "auth.mfa_result": ["mfa", "factor", "push", "challenge", "second"],
    "auth.method": ["method", "auth", "protocol", "grant"],
    "oauth.app_name": ["oauth", "client", "app", "consent", "serviceprincipal"],
    "oauth.scopes": ["scope", "permission", "resourceaccess", "consent"],
    "role.action": ["role", "assignment", "action", "operation"],
    "role.name": ["role", "admin", "privilege", "permission"],
    "mail.rule_action": ["rule", "mail", "inbox", "forward", "redirect"],
    "mail.forward_to": ["forward", "redirect", "recipient", "destination"],
}


def _canonical(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _field_name_score(field: str, target: str) -> Tuple[int, str]:
    cfield = _canonical(field)
    aliases = [_canonical(a) for a in FIELD_ALIASES.get(target, [])]
    if cfield in aliases:
        return 95, "alias"
    for alias in aliases:
        if alias and (alias in cfield or cfield in alias):
            return 82, "partial_alias"
    tokens = TARGET_KEYWORDS.get(target, [])
    hits = sum(1 for token in tokens if token in field.lower().replace("_", "").replace(".", ""))
    if hits:
        return min(75, 45 + hits * 12), "keyword"
    return 0, "none"


def _value_score(values: List[Any], target: str) -> Tuple[int, str]:
    samples = [v for v in values if v is not None and str(v).strip() != ""][:50]
    if not samples:
        return 0, "empty"
    n = len(samples)
    if target == "user.email":
        ratio = sum(is_email(v) for v in samples) / n
        return int(ratio * 92), "value_email" if ratio else "none"
    if target == "src.ip":
        ratio = sum(is_ipv4(v) for v in samples) / n
        return int(ratio * 92), "value_ip" if ratio else "none"
    if target == "event.time":
        ratio = sum(is_timestamp(v) for v in samples) / n
        return int(ratio * 90), "value_timestamp" if ratio else "none"
    if target == "src.country":
        ratio = sum(is_country(v) for v in samples) / n
        return int(ratio * 88), "value_country" if ratio else "none"
    if target == "event.outcome":
        ratio = sum(is_success(v) or is_failure(v) for v in samples) / n
        return int(ratio * 82), "value_outcome" if ratio else "none"
    if target == "auth.mfa_result":
        ratio = sum(looks_like_mfa(v) for v in samples) / n
        return int(ratio * 80), "value_mfa" if ratio else "none"
    if target == "app.name":
        ratio = sum(looks_like_app(v) for v in samples) / n
        return int(ratio * 76), "value_app" if ratio else "none"
    if target == "src.device":
        device_tokens = ["windows", "mac", "linux", "android", "ios", "chrome", "safari", "firefox", "edge", "unknown device", "iphone", "ipad"]
        ratio = sum(any(tok in str(v).lower() for tok in device_tokens) for v in samples) / n
        return int(ratio * 74), "value_device" if ratio else "none"
    if target in {"user.role", "role.name", "role.action"}:
        ratio = sum(looks_like_role(v) for v in samples) / n
        return int(ratio * 76), "value_role" if ratio else "none"
    if target in {"oauth.scopes", "oauth.app_name"}:
        ratio = sum(looks_like_oauth(v) for v in samples) / n
        return int(ratio * 78), "value_oauth" if ratio else "none"
    if target == "mail.forward_to":
        ratio = sum(is_email(v) for v in samples) / n
        return int(ratio * 70), "value_email_destination" if ratio else "none"
    return 0, "none"


def profile_records(records: List[Dict[str, Any]], sample_limit: int = 10) -> Dict[str, Dict[str, Any]]:
    flat_records = [flatten_dict(r) for r in records]
    all_fields = sorted({k for r in flat_records for k in r.keys()})
    profile: Dict[str, Dict[str, Any]] = {}
    for field in all_fields:
        values = [r.get(field) for r in flat_records]
        non_empty = [v for v in values if v is not None and str(v).strip() != ""]
        profile[field] = {
            "source_field": field,
            "sample_values": compact(non_empty, sample_limit),
            "non_empty_count": len(non_empty),
            "unique_count": len({str(v) for v in non_empty}),
        }
    return profile


def infer_source_vendor(profile: Dict[str, Dict[str, Any]], requested: str = "auto") -> str:
    if requested and requested.lower() != "auto":
        return requested.lower()
    all_text = " ".join(profile.keys()).lower() + " " + " ".join(str(v).lower() for p in profile.values() for v in p.get("sample_values", []))
    if "userprincipalname" in _canonical(all_text) or "appdisplayname" in _canonical(all_text) or "microsoft" in all_text or "office365" in all_text:
        return "microsoft_entra_or_m365"
    if "actor.alternateid" in all_text or "okta" in all_text or "client.geographicalcontext" in all_text:
        return "okta"
    if "google" in all_text or "workspace" in all_text or "actor.email" in all_text:
        return "google_workspace"
    if "github" in all_text:
        return "github"
    if "slack" in all_text:
        return "slack"
    if "vpn" in all_text:
        return "vpn"
    return "custom_or_unknown"


def infer_mapping(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    profile = profile_records(records)
    candidates: List[Dict[str, Any]] = []
    for source_field, info in profile.items():
        values = [r.get(source_field) for r in [flatten_dict(x) for x in records]]
        for target in NORMALIZED_FIELDS:
            name_score, name_method = _field_name_score(source_field, target)
            value_score, value_method = _value_score(values, target)
            # Give field-name matches more authority but allow value-only inference for headerless files.
            score = max(name_score, value_score)
            method = name_method if name_score >= value_score else value_method
            if name_score and value_score:
                score = min(99, max(name_score, value_score) + 5)
                method = f"{name_method}+{value_method}"
            if score >= 48:
                candidates.append({
                    "source_field": source_field,
                    "target_field": target,
                    "confidence": score,
                    "method": method,
                    "sample_values": info.get("sample_values", []),
                })

    # Pick the strongest source→target pairs globally. This avoids weaker generic matches
    # such as service_name → user.name winning before stronger service_name → app.name.
    chosen: List[Dict[str, Any]] = []
    used_sources = set()
    used_targets = set()
    for item in sorted(candidates, key=lambda x: (x["confidence"], x["method"]), reverse=True):
        if item["source_field"] in used_sources or item["target_field"] in used_targets:
            continue
        chosen.append(item)
        used_sources.add(item["source_field"])
        used_targets.add(item["target_field"])

    # Also keep unmapped profile for analyst review.
    mapped_sources = {m["source_field"] for m in chosen}
    unmapped = [
        {"source_field": k, "sample_values": v.get("sample_values", []), "reason": "No confident normalized field match"}
        for k, v in profile.items() if k not in mapped_sources
    ]

    return {
        "source_vendor": infer_source_vendor(profile),
        "normalized_schema_version": "identityguardx.v1",
        "mappings": sorted(chosen, key=lambda x: x["target_field"]),
        "unmapped_fields": unmapped,
        "field_profile": profile,
    }


def _normalize_value(target: str, value: Any) -> Any:
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        return None
    if target == "event.time":
        dt = parse_time(text)
        return dt.isoformat().replace("+00:00", "Z") if dt else text
    if target == "src.country":
        return normalize_country(text) or text
    if target == "event.outcome":
        if is_success(text):
            return "success"
        if is_failure(text):
            return "failure"
        return text.lower()
    if target == "auth.mfa_result":
        low = text.lower()
        if "approve" in low or low in {"satisfied", "success", "passed", "true"}:
            return "approved"
        if "deny" in low or "reject" in low or "fail" in low or low == "false":
            return "denied"
        if "prompt" in low or "challenge" in low or "required" in low:
            return "prompted"
        return low
    return value


def infer_event_type(flat: Dict[str, Any]) -> str:
    existing = str(flat.get("event.type") or "").lower()
    raw = " ".join(str(v).lower() for v in flat.values() if v is not None)
    text = f"{existing} {raw}"
    if any(x in text for x in ["login", "signin", "sign-in", "authentication", "vpn"]):
        return "user_login"
    if any(x in text for x in ["mfa", "factor", "push", "challenge"]):
        return "mfa_event"
    if any(x in text for x in ["oauth", "consent", "scope", "serviceprincipal"]):
        return "oauth_consent"
    if any(x in text for x in ["role", "admin", "privilege", "assigned"]):
        return "role_change"
    if any(x in text for x in ["mailbox", "inbox", "forward", "redirect", "mail rule"]):
        return "mailbox_rule"
    if any(x in text for x in ["github", "slack", "workspace", "audit"]):
        return "saas_audit"
    return existing or "security_event"


def transform_records(records: List[Dict[str, Any]], mapping_profile: Dict[str, Any], source_name: str = "auto") -> List[Dict[str, Any]]:
    mappings = mapping_profile.get("mappings", [])
    normalized_events: List[Dict[str, Any]] = []
    for idx, record in enumerate(records, 1):
        flat_source = flatten_dict(record)
        flat_norm: Dict[str, Any] = {}
        for m in mappings:
            source = m["source_field"]
            target = m["target_field"]
            if source in flat_source:
                flat_norm[target] = _normalize_value(target, flat_source.get(source))
        flat_norm.setdefault("event.type", infer_event_type(flat_norm | {"raw": flat_source}))
        flat_norm.setdefault("app.vendor", mapping_profile.get("source_vendor") or source_name)
        flat_norm["metadata.normalization.row_number"] = idx
        flat_norm["metadata.normalization.source_vendor"] = mapping_profile.get("source_vendor") or source_name
        flat_norm["metadata.normalization.source_hash"] = sha256_json(record)
        flat_norm["metadata.normalization.confidence_avg"] = round(
            sum(m.get("confidence", 0) for m in mappings) / max(len(mappings), 1), 2
        )
        event = unflatten_event(flat_norm)
        event["raw"] = {"original": record}
        normalized_events.append(event)
    return normalized_events


def normalize(records: List[Dict[str, Any]], source: str = "auto") -> Dict[str, Any]:
    mapping = infer_mapping(records)
    if source and source.lower() != "auto":
        mapping["source_vendor"] = source.lower()
    events = transform_records(records, mapping, source_name=source)
    return {
        "mapping_profile": mapping,
        "normalized_events": events,
        "summary": {
            "records_received": len(records),
            "events_normalized": len(events),
            "source_vendor": mapping.get("source_vendor"),
            "mapped_fields": len(mapping.get("mappings", [])),
            "unmapped_fields": len(mapping.get("unmapped_fields", [])),
        },
    }
