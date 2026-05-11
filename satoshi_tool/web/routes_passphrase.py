"""POST /api/passphrase/start — Passphrase Hunter como job."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from mnemonic import Mnemonic

from satoshi_tool.blockstream import _activity_single_with_retry
from satoshi_tool.derivation import (
    derivar_primera_direccion_por_purpose,
    infer_purpose_from_address,
)
from satoshi_tool.persistence import _persist_passphrase_hit
from satoshi_tool.web.jobs import JobEvent, job_manager
from satoshi_tool.web.models import JobStartResponse, PassphraseStartRequest

router = APIRouter()


def _detect_seed_mode(seed: str) -> str:
    s = seed.strip()
    if s.startswith("xprv"):
        return "xprv"
    if (len(s) in (51, 52)) and s[0] in ("5", "K", "L"):
        return "wif"
    return "mnemonic"


@router.post("/api/passphrase/start", response_model=JobStartResponse)
def passphrase_start(req: PassphraseStartRequest):
    seed = req.seed.strip()
    seed_mode = _detect_seed_mode(seed)
    if seed_mode == "mnemonic":
        normalized = " ".join(seed.lower().split())
        if not Mnemonic("english").check(normalized):
            raise HTTPException(status_code=400, detail="Mnemónica inválida.")
        seed_value = normalized
    else:
        seed_value = seed

    target = req.target.strip()
    purpose = infer_purpose_from_address(target) if target else req.purpose
    if purpose not in (44, 49, 84, 86):
        purpose = req.purpose

    def runner(emit, is_cancelled):
        tested = hits = errors = 0
        for pp in req.passphrases:
            if is_cancelled():
                emit(JobEvent(type="cancelled", payload={}))
                break
            tested += 1
            try:
                derived = derivar_primera_direccion_por_purpose(
                    seed_mode=seed_mode, seed_value=seed_value, passphrase=pp,
                    purpose=purpose, account=0, change=0, index=0,
                )
            except Exception:
                errors += 1
                continue

            addr = derived["address"]
            if target:
                if addr == target:
                    try:
                        act = _activity_single_with_retry(addr, tries=2, base_timeout=10)
                    except Exception:
                        act = {"total": 0, "ever_received": False, "ever_spent": False, "utxo_count": 0}
                    try:
                        _persist_passphrase_hit(
                            address=addr,
                            activity={
                                "total": act.get("total", 0),
                                "ever_received": act.get("ever_received", False),
                                "ever_spent": act.get("ever_spent", False),
                                "utxo_count": act.get("utxo_count", 0),
                            },
                            seed_mode=seed_mode,
                            seed_value=seed_value,
                            passphrase=pp,
                            path=derived["path"],
                        )
                    except Exception:
                        pass
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": seed_value if seed_mode == "mnemonic" else None,
                        "passphrase": pp, "path": derived["path"],
                        "address": addr, "act": act, "match": "target",
                    }))
                    hits += 1
                    break
            else:
                try:
                    act = _activity_single_with_retry(addr, tries=2, base_timeout=10)
                except Exception:
                    errors += 1
                    continue
                if act.get("total", 0) > 0 or act.get("ever_received"):
                    try:
                        _persist_passphrase_hit(
                            address=addr,
                            activity={
                                "total": act.get("total", 0),
                                "ever_received": act.get("ever_received", False),
                                "ever_spent": act.get("ever_spent", False),
                                "utxo_count": act.get("utxo_count", 0),
                            },
                            seed_mode=seed_mode,
                            seed_value=seed_value,
                            passphrase=pp,
                            path=derived["path"],
                        )
                    except Exception:
                        pass
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": seed_value if seed_mode == "mnemonic" else None,
                        "passphrase": pp, "path": derived["path"],
                        "address": addr, "act": act,
                    }))
                    hits += 1
                    break

            emit(JobEvent(type="kpi", payload={
                "tested": tested, "hits": hits, "errors": errors,
            }))

        emit(JobEvent(type="done", payload={
            "totals": {"tested": tested, "hits": hits, "errors": errors},
        }))

    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
