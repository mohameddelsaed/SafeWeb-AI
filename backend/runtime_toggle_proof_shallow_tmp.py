import json
import os
import time

import requests

BASE = "http://localhost:8000"
LOGIN_URL = f"{BASE}/api/auth/login/"
CREATE_URL = f"{BASE}/api/scan/website/"
ROOT = os.path.dirname(os.path.dirname(__file__))
LOG_PATH = os.path.join(ROOT, "runtime_proof_server_shallow_after_patch.log")
OUT_PATH = os.path.join(ROOT, "runtime_toggle_proof_result_shallow_after_patch.json")

EMAIL = "test@safeweb.ai"
PASSWORD = "testpass123"
TARGET = "https://example.com"

session = requests.Session()
login_resp = session.post(LOGIN_URL, json={"email": EMAIL, "password": PASSWORD}, timeout=30)
login_resp.raise_for_status()
login_data = login_resp.json()
access = login_data.get("access") or (login_data.get("tokens") or {}).get("access")
if not access:
    raise RuntimeError(f"Login missing access token: {login_data}")

headers = {"Authorization": f"Bearer {access}"}


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _read_from(path: str, start_pos: int) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(start_pos)
        return f.read()


def _extract_scan_id(create_json: dict) -> str:
    for key in ("scan_id", "id", "scanId"):
        if create_json.get(key):
            return str(create_json[key])
    data = create_json.get("data") or {}
    for key in ("scan_id", "id", "scanId"):
        if data.get(key):
            return str(data[key])
    raise RuntimeError(f"Could not extract scan id from response: {create_json}")


def _stream_sse(scan_id: str):
    stream_url = f"{BASE}/api/scan/{scan_id}/stream/?token={access}"
    phases = []
    events = []
    progress_points = []

    with session.get(stream_url, headers=headers, stream=True, timeout=None) as r:
        r.raise_for_status()
        start = time.time()
        for raw in r.iter_lines(decode_unicode=True):
            if raw is None:
                continue
            line = raw.strip()
            if not line or not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload in ("[DONE]", "done"):
                break
            try:
                obj = json.loads(payload)
            except Exception:
                continue

            event = obj.get("event") or obj.get("type") or ""
            if event:
                events.append(event)

            phase = (
                obj.get("phase")
                or (obj.get("data") or {}).get("phase")
                or obj.get("current_phase")
                or (obj.get("data") or {}).get("current_phase")
            )
            if event == "phase_change" and phase:
                if not phases or phases[-1] != phase:
                    phases.append(phase)

            progress = obj.get("progress") or (obj.get("data") or {}).get("progress")
            if isinstance(progress, (int, float)):
                progress_points.append(progress)

            status = (obj.get("status") or (obj.get("data") or {}).get("status") or "").lower()
            if event == "completed" or status in ("completed", "failed"):
                break

            if time.time() - start > 3600:
                raise TimeoutError(f"SSE stream timed out for scan {scan_id}")

    return {
        "events": events,
        "phases": phases,
        "progress_points": progress_points,
    }


def _run_case(label: str, control_external_tools: bool):
    payload = {
        "target": TARGET,
        "scanDepth": "shallow",
        "controlExternalTools": control_external_tools,
    }

    log_start = _file_size(LOG_PATH)

    create_resp = session.post(CREATE_URL, headers=headers, json=payload, timeout=60)
    create_resp.raise_for_status()
    create_data = create_resp.json()
    scan_id = _extract_scan_id(create_data)

    sse = _stream_sse(scan_id)

    detail_url = f"{BASE}/api/scan/{scan_id}/"
    detail_resp = session.get(detail_url, headers=headers, timeout=60)
    detail_resp.raise_for_status()
    detail = detail_resp.json()

    time.sleep(1.0)
    log_chunk = _read_from(LOG_PATH, log_start)

    return {
        "label": label,
        "scan_id": scan_id,
        "control_external_tools": control_external_tools,
        "status": detail.get("status") or (detail.get("data") or {}).get("status"),
        "score": detail.get("score") or (detail.get("data") or {}).get("score"),
        "sse": {
            "event_count": len(sse["events"]),
            "events": sse["events"],
            "phase_count": len(sse["phases"]),
            "phases": sse["phases"],
            "progress_min": min(sse["progress_points"]) if sse["progress_points"] else None,
            "progress_max": max(sse["progress_points"]) if sse["progress_points"] else None,
        },
        "log_evidence": {
            "phase_5b_cli": "Phase 5b (CLI)" in log_chunk,
            "phase_5b_skipped": "Phase 5b skipped (external tools disabled for this scan)" in log_chunk,
            "phase_5d_skipped": "Phase 5d skipped (external tools disabled for this scan)" in log_chunk,
            "nuclei_executing": "nuclei: executing" in log_chunk,
            "external_tools_disabled": "external tools disabled for this scan" in log_chunk,
            "unhashable_dict_error": "TypeError: unhashable type: 'dict'" in log_chunk,
        },
    }


on_case = _run_case("ON_shallow", True)
off_case = _run_case("OFF_shallow", False)

summary = {
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "target": TARGET,
    "depth": "shallow",
    "results": [on_case, off_case],
}

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print(json.dumps(summary, indent=2))
print(f"artifact={OUT_PATH}")
