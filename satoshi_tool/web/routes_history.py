"""GET /api/history — devuelve los hits combinados (seed + passphrase)."""

from typing import Optional

from fastapi import APIRouter, Query

from satoshi_tool.config import PASSPHRASE_HITS_FILEPATH, SEED_HITS_FILEPATH
from satoshi_tool.persistence import read_history

router = APIRouter()


@router.get("/api/history")
def history(
    mode: Optional[str] = Query(default=None, description="seed | passphrase"),
    since: Optional[int] = Query(default=None, description="timestamp epoch"),
    until: Optional[int] = Query(default=None, description="timestamp epoch"),
    with_balance: bool = Query(default=False),
):
    items = read_history(
        seed_path=SEED_HITS_FILEPATH,
        passphrase_path=PASSPHRASE_HITS_FILEPATH,
    )
    if mode in ("seed", "passphrase"):
        items = [h for h in items if h["mode"] == mode]
    if since is not None:
        items = [h for h in items if h.get("timestamp", 0) >= since]
    if until is not None:
        items = [h for h in items if h.get("timestamp", 0) <= until]
    if with_balance:
        items = [h for h in items if h.get("total_sats", 0) > 0]
    return {"hits": items, "count": len(items)}
