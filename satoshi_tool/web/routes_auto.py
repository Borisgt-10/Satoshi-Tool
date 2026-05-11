"""POST /api/auto/start — Modo Auto (genera seeds aleatorias y consulta)."""

from __future__ import annotations

from fastapi import APIRouter

from satoshi_tool.blockstream import _activity_batch
from satoshi_tool.derivation import (
    crear_semilla,
    derivar_direcciones_batch_mnemonic,
)
from satoshi_tool.persistence import _persist_seed_hit
from satoshi_tool.web.jobs import JobEvent, job_manager
from satoshi_tool.web.models import AutoStartRequest, JobStartResponse

router = APIRouter()


@router.post("/api/auto/start", response_model=JobStartResponse)
def auto_start(_: AutoStartRequest):
    def runner(emit, is_cancelled):
        seeds = 0
        addresses_checked = 0
        hits = 0
        errors = 0

        while not is_cancelled():
            seeds += 1
            seed_info = crear_semilla(generate_words=12)
            mnemonic = seed_info["mnemonic"]
            try:
                batch = derivar_direcciones_batch_mnemonic(
                    mnemonic_str=mnemonic, passphrase="", account=0, change=0,
                    start=0, count=3,
                )
            except Exception:
                errors += 1
                continue

            addresses = [it["address"] for it in batch["addresses"]]
            try:
                activity = _activity_batch(addresses, timeout=15)
            except Exception:
                errors += 1
                continue

            hit_found = False
            for it, a in zip(batch["addresses"], activity):
                addresses_checked += 1
                if a.get("total", 0) > 0 or a.get("ever_received"):
                    hits += 1
                    try:
                        _persist_seed_hit(
                            address=it["address"],
                            activity={
                                "total": a.get("total", 0),
                                "ever_received": a.get("ever_received", False),
                                "ever_spent": a.get("ever_spent", False),
                                "utxo_count": len(a.get("utxos", [])),
                            },
                            mnemonic=mnemonic,
                            passphrase="",
                            path=it["path"],
                            root_xprv=batch.get("root_xprv"),
                        )
                    except Exception:
                        pass
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": mnemonic, "path": it["path"],
                        "address": it["address"], "act": a,
                    }))
                    hit_found = True
                    break

            emit(JobEvent(type="kpi", payload={
                "seeds": seeds, "addresses_checked": addresses_checked,
                "hits": hits, "errors": errors,
            }))

            if hit_found:
                break

        emit(JobEvent(type="done", payload={
            "totals": {"seeds": seeds, "addresses": addresses_checked, "hits": hits},
        }))

    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
