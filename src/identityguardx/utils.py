from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from math import asin, cos, radians, sin, sqrt
from typing import Any, Dict, Iterable, List, Optional

from dateutil import parser as dt_parser

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")

KNOWN_COUNTRIES = {
    "united states", "usa", "us", "germany", "india", "united kingdom", "uk", "france",
    "canada", "australia", "singapore", "netherlands", "brazil", "china", "japan",
    "ireland", "mexico", "spain", "italy", "sweden", "norway", "poland", "russia",
    "south africa", "united arab emirates", "uae", "turkey", "israel", "indonesia",
    "philippines", "thailand", "vietnam", "malaysia", "south korea"
}

COUNTRY_COORDS = {
    "united states": (39.8283, -98.5795), "usa": (39.8283, -98.5795), "us": (39.8283, -98.5795),
    "germany": (51.1657, 10.4515), "india": (20.5937, 78.9629), "united kingdom": (55.3781, -3.4360),
    "uk": (55.3781, -3.4360), "france": (46.2276, 2.2137), "canada": (56.1304, -106.3468),
    "australia": (-25.2744, 133.7751), "singapore": (1.3521, 103.8198), "netherlands": (52.1326, 5.2913),
    "brazil": (-14.2350, -51.9253), "china": (35.8617, 104.1954), "japan": (36.2048, 138.2529),
    "ireland": (53.1424, -7.6921), "mexico": (23.6345, -102.5528), "spain": (40.4637, -3.7492),
    "italy": (41.8719, 12.5674), "sweden": (60.1282, 18.6435), "norway": (60.4720, 8.4689),
    "poland": (51.9194, 19.1451), "russia": (61.5240, 105.3188), "south africa": (-30.5595, 22.9375),
    "uae": (23.4241, 53.8478), "united arab emirates": (23.4241, 53.8478), "turkey": (38.9637, 35.2433),
    "israel": (31.0461, 34.8516), "indonesia": (-0.7893, 113.9213), "philippines": (12.8797, 121.7740),
    "thailand": (15.8700, 100.9925), "vietnam": (14.0583, 108.2772), "malaysia": (4.2105, 101.9758),
    "south korea": (35.9078, 127.7669)
}

KNOWN_APPS = {
    "office365", "microsoft 365", "m365", "entra", "azure", "okta", "google workspace",
    "gmail", "github", "slack", "salesforce", "vpn", "aws", "jira", "confluence",
    "dropbox", "box", "zoom", "teams", "sharepoint", "onedrive", "workday", "servicenow"
}

SUCCESS_VALUES = {"success", "succeeded", "allow", "allowed", "approved", "pass", "passed", "0", "true", "accepted"}
FAIL_VALUES = {"failure", "failed", "deny", "denied", "blocked", "error", "rejected", "false", "unauthorized", "forbidden"}
MFA_VALUES = {"mfa", "approved", "denied", "push", "prompt", "challenge", "satisfied", "required", "bypass", "sms", "otp"}
ROLE_VALUES = {"admin", "administrator", "global admin", "super admin", "owner", "privileged", "root", "role", "group"}
OAUTH_VALUES = {"oauth", "consent", "scope", "mail.read", "mail.send", "offline_access", "files.read.all", "user.readwrite.all", "directory.readwrite.all"}


def flatten_dict(obj: Dict[str, Any], parent: str = "", sep: str = ".") -> Dict[str, Any]:
    items: Dict[str, Any] = {}
    for key, value in obj.items():
        new_key = f"{parent}{sep}{key}" if parent else str(key)
        if isinstance(value, dict):
            items.update(flatten_dict(value, new_key, sep=sep))
        else:
            items[new_key] = value
    return items


def unflatten_event(flat: Dict[str, Any]) -> Dict[str, Any]:
    nested: Dict[str, Any] = {}
    for key, value in flat.items():
        if value is None or value == "":
            continue
        parts = key.split(".")
        cur = nested
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value
    return nested


def sha256_json(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def is_email(value: Any) -> bool:
    return bool(EMAIL_RE.match(str(value).strip()))


def is_ipv4(value: Any) -> bool:
    return bool(IPV4_RE.match(str(value).strip()))


def parse_time(value: Any) -> Optional[datetime]:
    if value is None or str(value).strip() == "":
        return None
    try:
        dt = dt_parser.parse(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def is_timestamp(value: Any) -> bool:
    return parse_time(value) is not None


def normalize_country(value: Any) -> Optional[str]:
    text = str(value).strip().lower()
    if not text:
        return None
    aliases = {"usa": "United States", "us": "United States", "uk": "United Kingdom", "uae": "United Arab Emirates"}
    if text in aliases:
        return aliases[text]
    if text in KNOWN_COUNTRIES:
        return " ".join(part.capitalize() for part in text.split())
    return None


def is_country(value: Any) -> bool:
    return normalize_country(value) is not None


def is_success(value: Any) -> bool:
    return str(value).strip().lower() in SUCCESS_VALUES


def is_failure(value: Any) -> bool:
    return str(value).strip().lower() in FAIL_VALUES


def looks_like_mfa(value: Any) -> bool:
    text = str(value).strip().lower()
    return any(token in text for token in MFA_VALUES)


def looks_like_role(value: Any) -> bool:
    text = str(value).strip().lower()
    return any(token in text for token in ROLE_VALUES)


def looks_like_oauth(value: Any) -> bool:
    text = str(value).strip().lower()
    return any(token in text for token in OAUTH_VALUES)


def looks_like_app(value: Any) -> bool:
    text = str(value).strip().lower()
    return any(app in text for app in KNOWN_APPS)


def get_path(obj: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def set_path(obj: Dict[str, Any], path: str, value: Any) -> None:
    cur = obj
    parts = path.split(".")
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def haversine_km(country_a: str, country_b: str) -> Optional[float]:
    ca = COUNTRY_COORDS.get(str(country_a).strip().lower())
    cb = COUNTRY_COORDS.get(str(country_b).strip().lower())
    if not ca or not cb:
        return None
    lat1, lon1 = ca
    lat2, lon2 = cb
    r = 6371.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return r * c


def lower_text(value: Any) -> str:
    return str(value or "").strip().lower()


def compact(values: Iterable[Any], limit: int = 5) -> List[str]:
    out = []
    for v in values:
        if v is None or str(v).strip() == "":
            continue
        s = str(v)
        if s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out
