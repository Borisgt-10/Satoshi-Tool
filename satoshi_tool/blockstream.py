"""Cliente HTTP para la API pública de Blockstream (mainnet)."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests

from satoshi_tool.config import (
    BLOCKSTREAM_BASE,
    _BLOCKSTREAM_LIMITER,
    _HTTP,
)


def address_activity_blockstream_batch(addresses, timeout: int = 15):
    """Para cada dirección (mainnet), devuelve resumen + UTXOs."""
    results = []
    session = requests.Session()
    headers = {"User-Agent": "BTC-Checker/1.0"}

    for addr in addresses:
        try:
            r = session.get(f"{BLOCKSTREAM_BASE}/address/{addr}", headers=headers, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            chain = data.get("chain_stats", {})
            mem = data.get("mempool_stats", {})

            confirmed = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
            unconfirmed = mem.get("funded_txo_sum", 0) - mem.get("spent_txo_sum", 0)
            total = confirmed + unconfirmed

            ever_received = (chain.get("funded_txo_count", 0) + mem.get("funded_txo_count", 0)) > 0
            ever_spent = (chain.get("spent_txo_count", 0) + mem.get("spent_txo_count", 0)) > 0

            r2 = session.get(f"{BLOCKSTREAM_BASE}/address/{addr}/utxo", headers=headers, timeout=timeout)
            r2.raise_for_status()
            utxo_raw = r2.json() if r2.text.strip() else []

            utxos = []
            for u in utxo_raw:
                status = u.get("status", {})
                utxos.append({
                    "txid": u.get("txid"),
                    "vout": u.get("vout"),
                    "value": u.get("value", 0),
                    "confirmed": bool(status.get("confirmed", False)),
                    "block_height": status.get("block_height"),
                    "block_time": status.get("block_time"),
                })

            results.append({
                "address": addr,
                "total": total,
                "ever_received": ever_received,
                "ever_spent": ever_spent,
                "has_unspent": len(utxos) > 0,
                "utxos": utxos,
                "status": "ok",
                "error_msg": None,
                "confirmed": confirmed,
                "unconfirmed": unconfirmed,
            })

        except requests.RequestException as e:
            results.append({
                "address": addr,
                "total": 0,
                "ever_received": False,
                "ever_spent": False,
                "has_unspent": False,
                "utxos": [],
                "status": "error",
                "error_msg": str(e),
                "confirmed": 0,
                "unconfirmed": 0,
            })

    return results


def address_activity_blockstream_single_mainnet(
    address: str, timeout: int = 15, session: Optional[requests.Session] = None,
) -> Dict[str, Any]:
    """Resumen + UTXOs de una sola dirección (2 GETs)."""
    s = session or _HTTP
    r = s.get(f"{BLOCKSTREAM_BASE}/address/{address}", timeout=timeout)
    r.raise_for_status()
    data = r.json()
    chain = data.get("chain_stats", {})
    mem = data.get("mempool_stats", {})

    confirmed = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
    unconfirmed = mem.get("funded_txo_sum", 0) - mem.get("spent_txo_sum", 0)
    total = confirmed + unconfirmed

    ever_received = (chain.get("funded_txo_count", 0) + mem.get("funded_txo_count", 0)) > 0
    ever_spent = (chain.get("spent_txo_count", 0) + mem.get("spent_txo_count", 0)) > 0

    r2 = s.get(f"{BLOCKSTREAM_BASE}/address/{address}/utxo", timeout=timeout)
    r2.raise_for_status()
    utxos = r2.json() if r2.text.strip() else []

    return {
        "total": total,
        "ever_received": ever_received,
        "ever_spent": ever_spent,
        "utxo_count": len(utxos),
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
    }


def _activity_single_with_retry(
    address: str, tries: int = 3, base_timeout: int = 10
) -> Dict[str, Any]:
    """Wrapper retry/backoff de address_activity_blockstream_single_mainnet."""
    for attempt in range(1, tries + 1):
        try:
            t = base_timeout + (attempt - 1) * 5
            return address_activity_blockstream_single_mainnet(address, timeout=t, session=_HTTP)
        except requests.exceptions.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 429:
                wait = 2 ** attempt
                print(f"[Rate limit 429] Esperando {wait}s y reintentando…")
                time.sleep(wait)
                continue
            raise
        except requests.exceptions.ReadTimeout:
            wait = 2 ** attempt
            print(f"[Red] Timeout. Reintento en {wait}s…")
            time.sleep(wait)
        except requests.exceptions.RequestException as e:
            wait = 2 ** attempt
            print(f"[Red] {e}. Reintento en {wait}s…")
            time.sleep(wait)
    raise RuntimeError("No se pudo consultar actividad tras varios intentos.")


def address_summary_only(
    address: str, timeout: int = 15, session: Optional[requests.Session] = None,
) -> Dict[str, Any]:
    """Resumen sin UTXOs (1 GET). Para escaneos amplios donde la mayoría serán vacías."""
    s = session or _HTTP
    r = s.get(f"{BLOCKSTREAM_BASE}/address/{address}", timeout=timeout)
    r.raise_for_status()
    data = r.json()
    chain = data.get("chain_stats", {})
    mem = data.get("mempool_stats", {})

    confirmed = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
    unconfirmed = mem.get("funded_txo_sum", 0) - mem.get("spent_txo_sum", 0)
    total = confirmed + unconfirmed

    ever_received = (chain.get("funded_txo_count", 0) + mem.get("funded_txo_count", 0)) > 0
    ever_spent = (chain.get("spent_txo_count", 0) + mem.get("spent_txo_count", 0)) > 0

    return {
        "total": total,
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "ever_received": ever_received,
        "ever_spent": ever_spent,
    }


def _summary_single_with_retry(
    address: str, tries: int = 3, base_timeout: int = 10
) -> Dict[str, Any]:
    """Wrapper retry/backoff de address_summary_only."""
    for attempt in range(1, tries + 1):
        try:
            t = base_timeout + (attempt - 1) * 5
            return address_summary_only(address, timeout=t, session=_HTTP)
        except requests.exceptions.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 429:
                wait = 2 ** attempt
                print(f"[Rate limit 429] Esperando {wait}s y reintentando…")
                time.sleep(wait)
                continue
            raise
        except requests.exceptions.ReadTimeout:
            wait = 2 ** attempt
            print(f"[Red] Timeout. Reintento en {wait}s…")
            time.sleep(wait)
        except requests.exceptions.RequestException as e:
            wait = 2 ** attempt
            print(f"[Red] {e}. Reintento en {wait}s…")
            time.sleep(wait)
    raise RuntimeError("No se pudo consultar resumen tras varios intentos.")


def _summary_single_throttled(
    address: str, tries: int = 3, base_timeout: int = 10
) -> Dict[str, Any]:
    """Pide token al rate limiter global antes de delegar en _summary_single_with_retry."""
    _BLOCKSTREAM_LIMITER.acquire()
    return _summary_single_with_retry(address, tries=tries, base_timeout=base_timeout)


def _activity_batch(addresses, timeout: int = 15):
    """Wrapper hoy = blockstream batch. Cuando haya nodo personal, el selector vive aquí."""
    return address_activity_blockstream_batch(addresses, timeout=timeout)
