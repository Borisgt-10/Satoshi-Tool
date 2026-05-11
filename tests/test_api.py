"""Tests de la API FastAPI."""

from mnemonic import Mnemonic


def test_health_returns_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_generator_returns_valid_mnemonic_12(client):
    r = client.post("/api/generator", json={"words": 12})
    assert r.status_code == 200
    body = r.json()
    assert "mnemonic" in body
    assert len(body["mnemonic"].split()) == 12
    assert Mnemonic("english").check(body["mnemonic"])


def test_generator_returns_24_words(client):
    r = client.post("/api/generator", json={"words": 24})
    assert r.status_code == 200
    body = r.json()
    assert len(body["mnemonic"].split()) == 24


def test_generator_rejects_invalid_word_count(client):
    r = client.post("/api/generator", json={"words": 18})
    assert r.status_code == 422


def test_manual_quick_with_test_mnemonic(client, monkeypatch, test_mnemonic_12, expected_test_addrs):
    """Mockea Blockstream para no depender de red. Verifica las 4 direcciones."""
    def fake_batch(addresses, timeout=15):
        return [
            {"address": a, "total": 0, "ever_received": False, "ever_spent": False,
             "has_unspent": False, "utxos": [], "status": "ok", "error_msg": None,
             "confirmed": 0, "unconfirmed": 0, "utxo_count": 0}
            for a in addresses
        ]
    monkeypatch.setattr("satoshi_tool.web.routes_manual._activity_batch", fake_batch)

    r = client.post("/api/manual/quick", json={"seed": test_mnemonic_12})
    assert r.status_code == 200
    body = r.json()
    assert body["seed_mode"] == "mnemonic"
    derivs = {d["purpose"]: d for d in body["derivations"] if d["ok"]}
    for purpose, expected in expected_test_addrs.items():
        assert derivs[purpose]["address"] == expected


def test_manual_quick_invalid_mnemonic(client):
    r = client.post("/api/manual/quick", json={"seed": "not a real mnemonic"})
    assert r.status_code == 400
