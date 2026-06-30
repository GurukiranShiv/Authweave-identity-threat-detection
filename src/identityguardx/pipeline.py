from __future__ import annotations

from typing import Any, Dict

from .detections import run_detections
from .exporters import build_ocsf_findings, build_siem_queries, build_sigma_like_rules, write_outputs
from .normalizer import normalize
from .parser import load_records
from .summarizer import build_investigation_brief


def run_pipeline(input_path: str, source: str = "auto", output_dir: str | None = None) -> Dict[str, Any]:
    records, parse_info = load_records(input_path)
    normalization_result = normalize(records, source=source)
    events = normalization_result["normalized_events"]
    detection_result = run_detections(events)
    outputs = {}
    if output_dir:
        outputs = write_outputs(output_dir, events, normalization_result["mapping_profile"], detection_result)
    alerts = detection_result.get("alerts", [])
    return {
        "parse_info": parse_info,
        "normalization_summary": normalization_result["summary"],
        "mapping_profile": normalization_result["mapping_profile"],
        "normalized_events": events,
        "detections": detection_result,
        "ai_investigation_brief": build_investigation_brief(alerts, detection_result.get("skipped_detections", [])),
        "ocsf_style_findings": build_ocsf_findings(alerts),
        "siem_queries": build_siem_queries(alerts),
        "sigma_like_rules": build_sigma_like_rules(alerts),
        "outputs": outputs,
    }
