from __future__ import annotations

import tempfile
from pathlib import Path
import sys
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from identityguardx.pipeline import run_pipeline

app = FastAPI(title="IdentityGuardX API", version="1.0.0")


@app.get("/health")
def health():
    return {"status": "ok", "service": "IdentityGuardX"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...), source: Optional[str] = Form("auto")):
    suffix = Path(file.filename or "upload.csv").suffix or ".csv"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name
    output_dir = ROOT / "outputs" / "api_upload"
    result = run_pipeline(tmp_path, source=source or "auto", output_dir=str(output_dir))
    # Keep API response compact.
    return {
        "parse_info": result["parse_info"],
        "normalization_summary": result["normalization_summary"],
        "mapping_profile": result["mapping_profile"],
        "detections": result["detections"],
        "ai_investigation_brief": result["ai_investigation_brief"],
        "outputs": result["outputs"],
    }
