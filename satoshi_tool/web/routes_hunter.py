"""POST /api/hunter/start — Seed Hunter como job."""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter

from satoshi_tool.blockstream import _summary_single_throttled
from satoshi_tool.config import _HTTP_POOL
from satoshi_tool.derivation import (
    derivar_primera_direccion_por_purpose,
    infer_purpose_from_address,
)
from satoshi_tool.mask import _iter_mnemonics_from_mask
from satoshi_tool.web.jobs import JobEvent, job_manager
from satoshi_tool.web.models import HunterStartRequest, JobStartResponse

router = APIRouter()
BATCH_SIZE = 16


@router.post("/api/hunter/start", response_model=JobStartResponse)
def hunter_start(req: HunterStartRequest):
    target = req.target.strip()
    purpose = infer_purpose_from_address(target) if target else req.purpose
    if purpose not in (44, 49, 84, 86):
        purpose = req.purpose

    def runner(emit, is_cancelled):
        tested = hits = empty = errors = 0
        last_kpi = 0.0
        pending: List[Tuple[str, str, str]] = []

        def maybe_emit_kpi(force: bool = False):
            nonlocal last_kpi
            now = time.time()
            if force or now - last_kpi > 0.2:
                emit(JobEvent(type="kpi", payload={
                    "tested": tested, "hits": hits, "empty": empty, "errors": errors,
                }))
                last_kpi = now

        def check_batch(items: List[Tuple[str, str, str]]):
            nonlocal hits, empty, errors
            futures = {
                _HTTP_POOL.submit(_summary_single_throttled, addr, 2, 10): (mn, path, addr)
                for mn, path, addr in items
            }
            results: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}
            for fut in concurrent.futures.as_completed(futures):
                mn, path, addr = futures[fut]
                try:
                    act = fut.result()
                except Exception as e:
                    errors += 1
                    emit(JobEvent(type="addr", payload={
                        "address": addr, "status": "error", "error": str(e),
                    }))
                    continue
                if act.get("total", 0) > 0 or act.get("ever_received"):
                    hits += 1
                    emit(JobEvent(type="addr", payload={
                        "address": addr, "status": "used",
                        "total_sats": act.get("total", 0),
                    }))
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": mn, "path": path, "address": addr, "act": act,
                    }))
                    results[addr] = (mn, path, act)
                else:
                    empty += 1
            for mn, path, addr in items:
                if addr in results:
                    saved_mn, saved_path, act = results[addr]
                    return saved_mn, saved_path, addr, act
            return None

        try:
            for mnemonic in _iter_mnemonics_from_mask(req.mask):
                if is_cancelled():
                    emit(JobEvent(type="cancelled", payload={}))
                    break
                tested += 1
                maybe_emit_kpi()

                try:
                    derived = derivar_primera_direccion_por_purpose(
                        seed_mode="mnemonic", seed_value=mnemonic, passphrase=req.passphrase,
                        purpose=purpose, account=0, change=0, index=0,
                    )
                except Exception:
                    errors += 1
                    continue

                addr = derived["address"]

                if target:
                    if addr == target:
                        emit(JobEvent(type="hit", payload={
                            "mnemonic": mnemonic, "path": derived["path"], "address": addr,
                            "match": "target",
                        }))
                        break
                    continue

                pending.append((mnemonic, derived["path"], addr))
                if len(pending) >= BATCH_SIZE:
                    hit = check_batch(pending)
                    pending.clear()
                    if hit:
                        break

            if not target and pending and not is_cancelled():
                check_batch(pending)
        finally:
            maybe_emit_kpi(force=True)
            emit(JobEvent(type="done", payload={
                "totals": {"tested": tested, "hits": hits, "empty": empty, "errors": errors},
            }))

    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
