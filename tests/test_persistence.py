"""Tests de escritura/lectura de los TXT JSONL de hits."""

import json

from satoshi_tool.persistence import (
    _persist_passphrase_hit, _persist_seed_hit, read_history,
)


def test_persist_seed_hit_writes_block_and_jsonl(tmp_path):
    out = tmp_path / "Semillas_Cazadas.txt"
    _persist_seed_hit(
        address="bc1qne7ma6c78u4q6x2hqgknzqfhtm36z99m42r2sd",
        activity={"total": 1234, "ever_received": True, "ever_spent": False, "utxo_count": 1},
        mnemonic="large witness lottery dinner quick video cabin episode alien orbit fish subject",
        passphrase="",
        path="m/84'/0'/0'/0/0",
        outfile=str(out),
    )
    text = out.read_text(encoding="utf-8")
    assert "SEED HIT" in text
    assert "bc1qne7ma6c78u4q6x2hqgknzqfhtm36z99m42r2sd" in text
    last = [ln for ln in text.splitlines() if ln.strip().startswith("{")][-1]
    obj = json.loads(last)
    assert obj["total_sats"] == 1234
    assert obj["address"] == "bc1qne7ma6c78u4q6x2hqgknzqfhtm36z99m42r2sd"


def test_persist_passphrase_hit_includes_passphrase(tmp_path):
    out = tmp_path / "Passphrases_Cazadas.txt"
    _persist_passphrase_hit(
        address="bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        activity={"total": 0, "ever_received": True, "ever_spent": True, "utxo_count": 0},
        seed_mode="mnemonic",
        seed_value="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        passphrase="my-secret",
        path="m/84'/0'/0'/0/0",
        outfile=str(out),
    )
    text = out.read_text(encoding="utf-8")
    last = [ln for ln in text.splitlines() if ln.strip().startswith("{")][-1]
    obj = json.loads(last)
    assert obj["passphrase"] == "my-secret"
    assert obj["seed_mode"] == "mnemonic"


def test_read_history_combines_both_files(tmp_path):
    seed_out = tmp_path / "Semillas_Cazadas.txt"
    pass_out = tmp_path / "Passphrases_Cazadas.txt"
    _persist_seed_hit(
        address="bc1qne7ma6c78u4q6x2hqgknzqfhtm36z99m42r2sd",
        activity={"total": 100, "ever_received": True, "ever_spent": False, "utxo_count": 1},
        mnemonic="large witness lottery dinner quick video cabin episode alien orbit fish subject",
        passphrase="", path="m/84'/0'/0'/0/0", outfile=str(seed_out),
    )
    _persist_passphrase_hit(
        address="bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        activity={"total": 0, "ever_received": True, "ever_spent": True, "utxo_count": 0},
        seed_mode="mnemonic",
        seed_value="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        passphrase="x", path="m/84'/0'/0'/0/0", outfile=str(pass_out),
    )

    hits = read_history(seed_path=str(seed_out), passphrase_path=str(pass_out))
    assert len(hits) == 2
    assert hits[0]["timestamp"] <= hits[1]["timestamp"]
    modes = {h["mode"] for h in hits}
    assert modes == {"seed", "passphrase"}


def test_read_history_handles_missing_files(tmp_path):
    """Si los archivos no existen, devuelve lista vacía sin error."""
    hits = read_history(
        seed_path=str(tmp_path / "no-existe-seed.txt"),
        passphrase_path=str(tmp_path / "no-existe-pass.txt"),
    )
    assert hits == []


def test_read_history_skips_malformed_jsonl(tmp_path):
    """Líneas no-JSON (como las cabeceras legibles) se ignoran."""
    out = tmp_path / "Semillas_Cazadas.txt"
    out.write_text(
        "================= SEED HIT =================\n"
        "Fecha: 2026-05-10 10:00:00\n"
        '{"timestamp": 1700000000, "address": "bc1q...", "total_sats": 0, "mnemonic": "x", "passphrase": "", "path": "m/84"}\n',
        encoding="utf-8"
    )
    hits = read_history(seed_path=str(out), passphrase_path=str(tmp_path / "noexiste.txt"))
    assert len(hits) == 1
    assert hits[0]["mode"] == "seed"
