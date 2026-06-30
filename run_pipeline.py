from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from identityguardx.pipeline import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="IdentityGuardX adaptive identity telemetry normalization and threat detection pipeline")
    parser.add_argument("--input", required=True, help="Path to CSV, JSON, NDJSON, TXT/LOG, or XLSX file")
    parser.add_argument("--source", default="auto", help="Optional source hint: auto, entra, okta, google_workspace, m365, github, slack, vpn, custom")
    parser.add_argument("--out", default="outputs/run", help="Output directory")
    args = parser.parse_args()

    result = run_pipeline(args.input, source=args.source, output_dir=args.out)
    summary = {
        "parse_info": result["parse_info"],
        "normalization_summary": result["normalization_summary"],
        "detection_summary": result["detections"]["summary"],
        "outputs": result["outputs"],
    }
    print(json.dumps(summary, indent=2))
    print(f"\nSOC investigation brief: {result['outputs'].get('soc_investigation_brief')}")


if __name__ == "__main__":
    main()
