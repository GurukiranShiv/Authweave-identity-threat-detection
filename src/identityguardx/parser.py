from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd

from .utils import is_country, is_email, is_ipv4, is_timestamp

KEY_VALUE_RE = re.compile(r"([A-Za-z0-9_.\-]+)=('[^']*'|\"[^\"]*\"|[^,\s]+)")


def _looks_like_value(cell: Any) -> bool:
    text = str(cell).strip()
    if not text:
        return False
    if is_email(text) or is_ipv4(text) or is_timestamp(text) or is_country(text):
        return True
    if text.lower() in {"success", "failed", "failure", "approved", "denied", "true", "false", "0", "1"}:
        return True
    return False


def _looks_like_header(cell: Any) -> bool:
    text = str(cell).strip()
    if not text:
        return False
    if _looks_like_value(text):
        return False
    # Typical machine-readable field names.
    if re.search(r"[A-Za-z]", text) and not re.search(r"\s{2,}", text):
        return True
    return False


def _has_header(first_row: List[Any]) -> bool:
    if not first_row:
        return True
    header_count = sum(_looks_like_header(c) for c in first_row)
    value_count = sum(_looks_like_value(c) for c in first_row)
    return header_count >= max(1, len(first_row) // 2) and value_count <= len(first_row) // 3


def _records_from_dataframe(df: pd.DataFrame) -> List[Dict[str, Any]]:
    df = df.where(pd.notnull(df), None)
    return df.to_dict(orient="records")


def read_csv(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    # Read first row to decide whether the CSV has headers.
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.reader(f)
        first_row = next(reader, [])
    has_header = _has_header(first_row)
    if has_header:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    else:
        df = pd.read_csv(path, dtype=str, header=None, keep_default_na=False)
        df.columns = [f"col_{i + 1}" for i in range(len(df.columns))]
    return _records_from_dataframe(df), {"file_type": "csv", "header_detected": has_header, "rows": len(df), "columns": list(df.columns)}


def read_excel(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    preview = pd.read_excel(path, dtype=str, header=None, nrows=1, keep_default_na=False)
    first_row = preview.iloc[0].tolist() if not preview.empty else []
    has_header = _has_header(first_row)
    if has_header:
        df = pd.read_excel(path, dtype=str, keep_default_na=False)
    else:
        df = pd.read_excel(path, dtype=str, header=None, keep_default_na=False)
        df.columns = [f"col_{i + 1}" for i in range(len(df.columns))]
    return _records_from_dataframe(df), {"file_type": "xlsx", "header_detected": has_header, "rows": len(df), "columns": list(df.columns)}


def _coerce_json_records(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, list):
        return [x if isinstance(x, dict) else {"value": x} for x in obj]
    if isinstance(obj, dict):
        for key in ["events", "records", "data", "logs", "items", "value"]:
            if isinstance(obj.get(key), list):
                return [x if isinstance(x, dict) else {"value": x} for x in obj[key]]
        return [obj]
    return [{"value": obj}]


def read_json(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    obj = json.loads(raw)
    records = _coerce_json_records(obj)
    return records, {"file_type": "json", "header_detected": True, "rows": len(records), "columns": sorted({k for r in records if isinstance(r, dict) for k in r.keys()})}


def read_ndjson(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            records.extend(_coerce_json_records(obj))
        except json.JSONDecodeError:
            records.append({"raw.message": line})
    return records, {"file_type": "ndjson", "header_detected": True, "rows": len(records), "columns": sorted({k for r in records for k in r.keys()})}


def _parse_text_line(line: str, line_no: int) -> Dict[str, Any]:
    line = line.strip()
    if not line:
        return {}
    try:
        obj = json.loads(line)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    kv_pairs = KEY_VALUE_RE.findall(line)
    if kv_pairs:
        row = {k: v.strip("'\"") for k, v in kv_pairs}
        row["raw.message"] = line
        return row

    # Fallback: split common delimiter logs, then infer from col_n values later.
    if "," in line:
        parts = [p.strip() for p in line.split(",")]
    elif "|" in line:
        parts = [p.strip() for p in line.split("|")]
    else:
        parts = line.split()
    row = {f"col_{i + 1}": part for i, part in enumerate(parts)}
    row["raw.message"] = line
    row["raw.line_number"] = line_no
    return row


def read_txt(path: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    records = []
    for idx, line in enumerate(path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
        parsed = _parse_text_line(line, idx)
        if parsed:
            records.append(parsed)
    return records, {"file_type": "txt", "header_detected": False, "rows": len(records), "columns": sorted({k for r in records for k in r.keys()})}


def load_records(input_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    path = Path(input_path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return read_csv(path)
    if suffix in {".xlsx", ".xls"}:
        return read_excel(path)
    if suffix == ".json":
        return read_json(path)
    if suffix in {".ndjson", ".jsonl"}:
        return read_ndjson(path)
    if suffix in {".txt", ".log"}:
        return read_txt(path)
    raise ValueError(f"Unsupported file type: {suffix}. Supported: csv, json, ndjson, jsonl, txt, log, xlsx")
