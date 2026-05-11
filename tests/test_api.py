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
