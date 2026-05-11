"""GET /api/jobs/{id}/stream (SSE) y POST /api/jobs/{id}/cancel."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from satoshi_tool.web.jobs import job_manager

router = APIRouter()


@router.get("/api/jobs/{job_id}/stream")
def stream(job_id: str):
    def event_source():
        for ev in job_manager.iter_events(job_id, timeout=60.0):
            yield f"data: {json.dumps(ev.as_dict(), ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/api/jobs/{job_id}/cancel")
def cancel(job_id: str):
    ok = job_manager.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="job no encontrado")
    return {"cancelled": True, "job_id": job_id}
