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


def test_history_returns_combined_hits(tmp_path, monkeypatch):
    """Crea ambos archivos en tmp_path, monkeypatchea las constantes y verifica /api/history."""
    from satoshi_tool.persistence import _persist_passphrase_hit, _persist_seed_hit
    seed_file = tmp_path / "seed.txt"
    pass_file = tmp_path / "pass.txt"

    _persist_seed_hit(
        address="bc1qne7ma6c78u4q6x2hqgknzqfhtm36z99m42r2sd",
        activity={"total": 100, "ever_received": True, "ever_spent": False, "utxo_count": 1},
        mnemonic="m1", passphrase="", path="m/84'/0'/0'/0/0", outfile=str(seed_file),
    )
    _persist_passphrase_hit(
        address="bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        activity={"total": 0, "ever_received": True, "ever_spent": True, "utxo_count": 0},
        seed_mode="mnemonic", seed_value="m2", passphrase="x",
        path="m/84'/0'/0'/0/0", outfile=str(pass_file),
    )

    monkeypatch.setattr("satoshi_tool.web.routes_history.SEED_HITS_FILEPATH", str(seed_file))
    monkeypatch.setattr("satoshi_tool.web.routes_history.PASSPHRASE_HITS_FILEPATH", str(pass_file))

    from fastapi.testclient import TestClient
    from satoshi_tool.web.app import create_app
    client_local = TestClient(create_app())

    r = client_local.get("/api/history")
    assert r.status_code == 200
    body = r.json()
    assert len(body["hits"]) == 2
    modes = {h["mode"] for h in body["hits"]}
    assert modes == {"seed", "passphrase"}


def test_jobmanager_create_and_consume():
    from satoshi_tool.web.jobs import JobEvent, JobManager
    jm = JobManager(ttl_seconds=5)

    def runner(emit, is_cancelled):
        emit(JobEvent(type="kpi", payload={"tested": 1}))
        emit(JobEvent(type="done", payload={"summary": "ok"}))

    job_id = jm.create(runner)
    events = list(jm.iter_events(job_id, timeout=2.0))
    types = [e.type for e in events]
    assert "kpi" in types
    assert types[-1] == "done"


def test_jobmanager_cancel_stops_runner():
    """El runner debe ver is_cancelled() == True después de cancel."""
    import time
    from satoshi_tool.web.jobs import JobEvent, JobManager

    jm = JobManager(ttl_seconds=5)

    def runner(emit, is_cancelled):
        for i in range(100):
            if is_cancelled():
                emit(JobEvent(type="cancelled", payload={}))
                emit(JobEvent(type="done", payload={"reason": "cancelled"}))
                return
            emit(JobEvent(type="kpi", payload={"tested": i}))
            time.sleep(0.05)

    job_id = jm.create(runner)
    time.sleep(0.1)
    jm.cancel(job_id)
    events = list(jm.iter_events(job_id, timeout=2.0))
    types = [e.type for e in events]
    assert "cancelled" in types
    assert types[-1] == "done"


def test_manual_full_creates_job(client, test_mnemonic_12, monkeypatch):
    """POST /api/manual/full devuelve job_id; el runner emite KPIs y done."""

    def fake_scan(*, seed_mode, seed_value, passphrase, purpose, account, gap_limit, max_index, on_progress):
        if on_progress:
            on_progress(purpose, 0, 0, "fake-addr", "empty")
            on_progress(purpose, 0, 1, "fake-addr-2", "empty")
        return {
            "purpose": purpose, "account": account,
            "external": {"scanned": 2, "used": [], "total_sats": 0, "confirmed": 0, "unconfirmed": 0},
            "internal": {"scanned": 0, "used": [], "total_sats": 0, "confirmed": 0, "unconfirmed": 0},
            "total_sats": 0,
        }

    monkeypatch.setattr("satoshi_tool.web.routes_manual.scan_purpose_with_gap_limit", fake_scan)

    r = client.post("/api/manual/full", json={"seed": test_mnemonic_12, "gap_limit": 5})
    assert r.status_code == 200
    body = r.json()
    assert "job_id" in body


def test_hunter_start_creates_job(client, monkeypatch):
    """Mockea el iterador de candidatos y el cliente blockstream."""

    def fake_iter(mask):
        yield "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    def fake_summary(addr, *_args, **_kwargs):
        return {"total": 0, "ever_received": False, "ever_spent": False,
                "confirmed": 0, "unconfirmed": 0}

    monkeypatch.setattr("satoshi_tool.web.routes_hunter._iter_mnemonics_from_mask", fake_iter)
    monkeypatch.setattr("satoshi_tool.web.routes_hunter._summary_single_throttled", fake_summary)

    r = client.post("/api/hunter/start", json={
        "mask": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
        "purpose": 84,
    })
    assert r.status_code == 200
    assert "job_id" in r.json()
