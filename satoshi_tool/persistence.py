"""Persistencia de hits en TXT + JSONL, y lectura combinada para el tab Histórico."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from satoshi_tool.config import PASSPHRASE_HITS_FILEPATH, SEED_HITS_FILEPATH


def _persist_passphrase_hit(
    *,
    address: str,
    activity: Dict[str, Any],
    seed_mode: str,
    seed_value: str,
    passphrase: str,
    path: str,
    outfile: Optional[str] = None,
) -> None:
    """Append un bloque legible + una línea JSONL al fichero de hits de passphrase."""
    out = outfile or PASSPHRASE_HITS_FILEPATH
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)

    ts_human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    ts_epoch = int(time.time())

    lines = [
        "================= PASSPHRASE HIT =================",
        f"Fecha:     {ts_human}",
        f"Dirección: {address}",
        f"Saldo:     {activity.get('total', 0)} sats",
        f"Recibida:  {'Sí' if activity.get('ever_received') else 'No'} | "
        f"Gastada: {'Sí' if activity.get('ever_spent') else 'No'} | "
        f"UTXOs: {activity.get('utxo_count', 0)}",
        f"Path:      {path}",
        "----- Datos sensibles (⚠ GUARDAR CON EXTREMO CUIDADO) -----",
        f"Seed mode: {seed_mode}",
    ]
    if seed_mode == "mnemonic":
        lines.append(f"Mnemonic:  {seed_value}")
        lines.append(f"Passphrase: {passphrase}")
    elif seed_mode == "xprv":
        lines.append(f"xprv:      {seed_value}")
    elif seed_mode == "wif":
        lines.append(f"WIF:       {seed_value}")
    lines.append("")

    with open(out, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        f.write(json.dumps({
            "timestamp": ts_epoch,
            "address": address,
            "total_sats": activity.get("total", 0),
            "ever_received": activity.get("ever_received", False),
            "ever_spent": activity.get("ever_spent", False),
            "utxo_count": activity.get("utxo_count", 0),
            "path": path,
            "seed_mode": seed_mode,
            "seed": seed_value,
            "passphrase": passphrase if seed_mode == "mnemonic" else None,
        }, ensure_ascii=False) + "\n")

    try:
        os.chmod(out, 0o600)
    except Exception:
        pass


def _persist_seed_hit(
    *,
    address: str,
    activity: Dict[str, Any],
    mnemonic: str,
    passphrase: str,
    path: str,
    root_xprv: Optional[str] = None,
    outfile: Optional[str] = None,
) -> None:
    """Append un bloque legible + JSONL al fichero de hits de seed."""
    out = outfile or SEED_HITS_FILEPATH
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)

    ts_human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    ts_epoch = int(time.time())

    header = [
        "================= SEED HIT =================",
        f"Fecha:     {ts_human}",
        f"Dirección: {address}",
        f"Saldo:     {activity.get('total', 0)} sats",
        f"Recibida:  {'Sí' if activity.get('ever_received') else 'No'} | "
        f"Gastada: {'Sí' if activity.get('ever_spent') else 'No'} | "
        f"UTXOs: {activity.get('utxo_count', 0)}",
        "----- Datos sensibles (⚠ GUARDAR CON EXTREMO CUIDADO) -----",
        f"Mnemonic:       {mnemonic}",
        f"Passphrase:     {passphrase if passphrase else '(vacía)'}",
        f"Derivation:     {path}",
    ]
    if root_xprv:
        header.append(f"root xprv:      {root_xprv}")
    header.append("")

    with open(out, "a", encoding="utf-8") as f:
        f.write("\n".join(header) + "\n")
        f.write(json.dumps({
            "timestamp": ts_epoch,
            "address": address,
            "total_sats": activity.get("total", 0),
            "ever_received": activity.get("ever_received", False),
            "ever_spent": activity.get("ever_spent", False),
            "utxo_count": activity.get("utxo_count", 0),
            "mnemonic": mnemonic,
            "passphrase": passphrase,
            "path": path,
            "root_xprv": root_xprv,
        }, ensure_ascii=False) + "\n")

    try:
        os.chmod(out, 0o600)
    except Exception:
        pass


def _read_jsonl(path: str, mode_label: str) -> List[Dict[str, Any]]:
    """Lee un fichero de hits, devuelve lista de dicts marcados con 'mode'."""
    out: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            obj["mode"] = mode_label
            out.append(obj)
    return out


def read_history(
    seed_path: Optional[str] = None,
    passphrase_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Lee ambos ficheros de hits, los combina y ordena por timestamp ascendente."""
    seed_p = seed_path or SEED_HITS_FILEPATH
    pass_p = passphrase_path or PASSPHRASE_HITS_FILEPATH
    items = _read_jsonl(seed_p, "seed") + _read_jsonl(pass_p, "passphrase")
    items.sort(key=lambda x: x.get("timestamp", 0))
    return items
