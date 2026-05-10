"""Tests determinísticos de derivación HD usando vectores BIP-39 públicos."""

from unittest.mock import patch

import pytest

from satoshi_tool.derivation import (
    crear_semilla,
    derivar_primera_direccion_por_purpose,
    derive_first_for_all_purposes,
    infer_purpose_from_address,
    scan_purpose_with_gap_limit,
)


def test_first_address_per_purpose(test_mnemonic_12, expected_test_addrs):
    """Vectores BIP-39 estándar — la primera dirección debe ser la pública conocida."""
    for purpose, expected in expected_test_addrs.items():
        d = derivar_primera_direccion_por_purpose(
            seed_mode="mnemonic",
            seed_value=test_mnemonic_12,
            passphrase="",
            purpose=purpose,
        )
        assert d["address"] == expected, f"BIP{purpose}: esperado {expected}, fue {d['address']}"


def test_xlsx_test_wallet_bip84():
    """Fila de Test_wallets.xlsx — BIP84 m/.../0/0 debe coincidir."""
    mnemonic = "large witness lottery dinner quick video cabin episode alien orbit fish subject"
    expected = "bc1qne7ma6c78u4q6x2hqgknzqfhtm36z99m42r2sd"
    d = derivar_primera_direccion_por_purpose(
        seed_mode="mnemonic", seed_value=mnemonic, passphrase="", purpose=84,
    )
    assert d["address"] == expected


def test_derive_first_for_all_purposes_returns_4(test_mnemonic_12, expected_test_addrs):
    results = derive_first_for_all_purposes("mnemonic", test_mnemonic_12, "")
    assert len(results) == 4
    by_purpose = {r["purpose"]: r for r in results if r["ok"]}
    for purpose, expected in expected_test_addrs.items():
        assert by_purpose[purpose]["data"]["address"] == expected


@pytest.mark.parametrize("address,expected_purpose", [
    ("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", 44),
    ("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", 49),
    ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 84),
    ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", 86),
    ("garbage", None),
    ("", None),
])
def test_infer_purpose(address, expected_purpose):
    assert infer_purpose_from_address(address) == expected_purpose


def test_crear_semilla_12_words_valid():
    s = crear_semilla(12)
    assert len(s["words"]) == 12
    d = derivar_primera_direccion_por_purpose(
        seed_mode="mnemonic", seed_value=s["mnemonic"], passphrase="", purpose=84,
    )
    assert d["address"].startswith("bc1q")


def test_crear_semilla_24_words_valid():
    s = crear_semilla(24)
    assert len(s["words"]) == 24


def test_scan_stops_at_gap_limit_when_all_empty(test_mnemonic_12):
    """Si address_summary_only siempre devuelve vacío, debe parar exactamente en gap_limit."""
    empty = {"total": 0, "confirmed": 0, "unconfirmed": 0,
             "ever_received": False, "ever_spent": False}

    def stub(*_args, **_kwargs):
        return empty

    with patch("satoshi_tool.derivation._summary_single_throttled", side_effect=stub):
        res = scan_purpose_with_gap_limit(
            seed_mode="mnemonic", seed_value=test_mnemonic_12, passphrase="",
            purpose=84, account=0, gap_limit=5, max_index=200,
        )
    assert res["external"]["scanned"] == 5
    assert res["external"]["used"] == []
    assert res["internal"]["scanned"] == 5
    assert res["total_sats"] == 0


def test_scan_reaches_max_index_when_all_used(test_mnemonic_12):
    """Si TODAS las direcciones devuelven 'usada', el gap nunca avanza y el scan
    llega hasta max_index. Verifica que la lógica de reset del contador funciona."""
    used = {"total": 1234, "confirmed": 1234, "unconfirmed": 0,
            "ever_received": True, "ever_spent": False}

    def stub(*_args, **_kwargs):
        return used

    with patch("satoshi_tool.derivation._summary_single_throttled", side_effect=stub):
        res = scan_purpose_with_gap_limit(
            seed_mode="mnemonic", seed_value=test_mnemonic_12, passphrase="",
            purpose=84, account=0, gap_limit=5, max_index=16,
        )
    assert res["external"]["scanned"] == 16
    assert res["internal"]["scanned"] == 16
    assert len(res["external"]["used"]) == 16
    assert len(res["internal"]["used"]) == 16
    assert res["total_sats"] == 1234 * 32


def test_scan_wif_raises():
    with pytest.raises(ValueError, match="WIF"):
        scan_purpose_with_gap_limit(
            seed_mode="wif", seed_value="L4rK1...", passphrase="", purpose=84,
        )
