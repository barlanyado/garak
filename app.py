import json
import os
import re
import subprocess
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Garak Scan API")

PROJECT_ROOT = Path(__file__).parent
GARAK_RUNS_DIR = Path.home() / ".local" / "share" / "garak" / "garak_runs"
JOB_ID_PATTERN = re.compile(r"garak\.([0-9a-f\-]{36})\.report\.jsonl")


def _load_env() -> dict:
    env = os.environ.copy()
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().removeprefix("export").strip()
                env[key] = value.strip().strip('"').strip("'")
    env["PYTHONUNBUFFERED"] = "1"
    return env

jobs: dict[str, dict] = {}


class ScanRequest(BaseModel):
    yaml_name: str


def _read_stdout(job_key: str, process: subprocess.Popen, found_event: threading.Event) -> None:
    for line in process.stdout:
        decoded = line.decode("utf-8", errors="replace").rstrip()
        jobs[job_key]["stdout"].append(decoded)
        if not found_event.is_set():
            match = JOB_ID_PATTERN.search(decoded)
            if match:
                job_id = match.group(1)
                jobs[job_key]["job_id"] = job_id
                jobs[job_id] = jobs[job_key]
                found_event.set()
    process.wait()


@app.post("/scan")
def start_scan(req: ScanRequest):
    yaml_path = PROJECT_ROOT / req.yaml_name
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail=f"yaml file not found: {req.yaml_name}")

    process = subprocess.Popen(
        ["uv", "run", "python", "-m", "garak", "--config", req.yaml_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=PROJECT_ROOT,
        env=_load_env(),
    )

    job_key = f"_pending_{process.pid}"
    jobs[job_key] = {"status": "running", "process": process, "stdout": [], "job_id": None}

    found_event = threading.Event()
    thread = threading.Thread(target=_read_stdout, args=(job_key, process, found_event), daemon=True)
    thread.start()

    found_event.wait(timeout=60)

    job_id = jobs[job_key].get("job_id")
    if job_id is None:
        process.kill()
        raise HTTPException(status_code=500, detail="garak did not emit a job ID within timeout")

    return {"job_id": job_id, "status": "running"}


@app.get("/scan/{job_id}/status")
def get_status(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"job not found: {job_id}")

    process: subprocess.Popen = job["process"]
    return_code = process.poll()

    if return_code is None:
        status = "running"
    elif return_code == 0:
        status = "completed"
    else:
        status = "failed"

    return {"job_id": job_id, "status": status, "return_code": return_code}


@app.get("/scan/{job_id}/hitlog")
def get_hitlog(job_id: str):
    hitlog_path = GARAK_RUNS_DIR / f"garak.{job_id}.hitlog.jsonl"
    if not hitlog_path.exists():
        return {"job_id": job_id, "hits": [], "message": "no hitlog found (scan may still be running or produced no hits)"}

    hits = []
    with open(hitlog_path) as f:
        for line in f:
            line = line.strip()
            if line:
                hits.append(json.loads(line))

    return {"job_id": job_id, "hits": hits}

