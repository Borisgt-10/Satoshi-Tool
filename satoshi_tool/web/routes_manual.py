"""POST /api/manual/quick — derivación rápida (m/.../0/0) por purpose.
POST /api/manual/full — escaneo HD con gap limit, devuelve job_id."""

from __future__ import annotations

import time
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from mnemonic import Mnemonic

from satoshi_tool.blockstream import _activity_batch
from satoshi_tool.derivation import (
    derive_first_for_all_purposes,
    scan_purpose_with_gap_limit,
)
from satoshi_tool.persistence import _persist_seed_hit
from satoshi_tool.web.jobs import JobEvent, job_manager
from satoshi_tool.web.models import (
    DerivationResult,
    JobStartResponse,
    ManualFullRequest,
    ManualQuickRequest,
    ManualQuickResponse,
)

router = APIRouter()


def _detect_seed_mode(seed: str) -> str:
    s = seed.strip()
    if s.startswith("xprv"):
        return "xprv"
    if (len(s) in (51, 52)) and s[0] in ("5", "K", "L"):
        return "wif"
    return "mnemonic"


@router.post("/api/manual/quick", response_model=ManualQuickResponse)
def manual_quick(req: ManualQuickRequest):
    seed = req.seed.strip()
    seed_mode = _detect_seed_mode(seed)

    if seed_mode == "mnemonic":
        normalized = " ".join(seed.lower().split())
        if not Mnemonic("english").check(normalized):
            raise HTTPException(status_code=400, detail="Mnemónica inválida (checksum BIP-39).")
        seed_value = normalized
        passphrase = req.passphrase
    else:
        seed_value = seed
        passphrase = ""

    derivs = derive_first_for_all_purposes(seed_mode, seed_value, passphrase)
    addresses = [d["data"]["address"] for d in derivs if d["ok"]]
    activity = {a["address"]: a for a in _activity_batch(addresses)} if addresses else {}

    out: List[DerivationResult] = []
    for d in derivs:
        if not d["ok"]:
            out.append(DerivationResult(purpose=d["purpose"], ok=False, error=d["error"]))
            continue
        addr = d["data"]["address"]
        act = activity.get(addr, {})
        out.append(DerivationResult(
            purpose=d["purpose"],
            ok=True,
            path=d["data"]["path"],
            address=addr,
            total_sats=act.get("total", 0),
            ever_received=act.get("ever_received", False),
            ever_spent=act.get("ever_spent", False),
            utxo_count=len(act.get("utxos", [])) if "utxos" in act else act.get("utxo_count", 0),
        ))

    return ManualQuickResponse(seed_mode=seed_mode, derivations=out)


@router.post("/api/manual/full", response_model=JobStartResponse)
def manual_full(req: ManualFullRequest):
    seed = req.seed.strip()
    seed_mode = _detect_seed_mode(seed)
    if seed_mode == "wif":
        raise HTTPException(status_code=400, detail="WIF no soporta escaneo HD.")
    if seed_mode == "mnemonic":
        normalized = " ".join(seed.lower().split())
        if not Mnemonic("english").check(normalized):
            raise HTTPException(status_code=400, detail="Mnemónica inválida.")
        seed_value = normalized
        passphrase = req.passphrase
    else:
        seed_value = seed
        passphrase = ""

    gap_limit = req.gap_limit

    def runner(emit, is_cancelled):
        tested = 0
        hits = 0
        empty = 0
        errors = 0
        last_kpi = 0.0

        def cb(purpose, change, idx, addr, kind, **kw):
            nonlocal tested, hits, empty, errors, last_kpi
            tested += 1
            if kind == "used":
                hits += 1
                act = kw.get("act", {})
                try:
                    _persist_seed_hit(
                        address=addr,
                        activity={
                            "total": act.get("total", 0),
                            "ever_received": act.get("ever_received", False),
                            "ever_spent": act.get("ever_spent", False),
                            "utxo_count": 0,
                        },
                        mnemonic=seed_value if seed_mode == "mnemonic" else "",
                        passphrase=passphrase,
                        path=f"m/{purpose}'/0'/0'/{change}/{idx}",
                    )
                except Exception:
                    pass
                emit(JobEvent(type="addr", payload={
                    "purpose": purpose, "change": change, "index": idx,
                    "address": addr, "status": "used",
                    "total_sats": act.get("total", 0),
                }))
                emit(JobEvent(type="hit", payload={
                    "purpose": purpose, "change": change, "index": idx,
                    "address": addr, "act": act,
                }))
            elif kind == "error":
                errors += 1
                emit(JobEvent(type="addr", payload={
                    "purpose": purpose, "change": change, "index": idx,
                    "address": addr, "status": "error", "error": kw.get("error"),
                }))
            else:  # empty
                empty += 1

            now = time.time()
            if now - last_kpi > 0.2 or kind in ("used", "error"):
                emit(JobEvent(type="kpi", payload={
                    "tested": tested, "hits": hits, "empty": empty, "errors": errors,
                }))
                last_kpi = now

        results: List[Dict[str, Any]] = []
        for purpose in (44, 49, 84, 86):
            if is_cancelled():
                emit(JobEvent(type="cancelled", payload={}))
                break
            res = scan_purpose_with_gap_limit(
                seed_mode=seed_mode, seed_value=seed_value, passphrase=passphrase,
                purpose=purpose, account=0, gap_limit=gap_limit, max_index=200,
                on_progress=cb,
            )
            results.append(res)

        emit(JobEvent(type="done", payload={
            "summary": results,
            "totals": {"tested": tested, "hits": hits, "empty": empty, "errors": errors},
        }))

    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
