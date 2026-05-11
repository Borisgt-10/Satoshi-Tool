"""POST /api/manual/quick — derivación rápida (m/.../0/0) por purpose.
POST /api/manual/full — escaneo HD con gap limit, devuelve job_id (se añade en T13)."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException
from mnemonic import Mnemonic

from satoshi_tool.blockstream import _activity_batch
from satoshi_tool.derivation import derive_first_for_all_purposes
from satoshi_tool.web.models import (
    DerivationResult,
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
