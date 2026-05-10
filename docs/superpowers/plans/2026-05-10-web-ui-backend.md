# Web UI — Backend (Plan #1: hitos 4.1 + 4.2 + 4.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactorizar el monolito `Satoshi_Tool.py` en un paquete `satoshi_tool/`, montar el backend FastAPI con endpoints REST para los 5 modos + Histórico, y añadir streaming SSE para los modos largos. Todo cubierto por suite pytest. El CLI viejo sigue funcionando como fallback headless.

**Architecture:** Paquete Python con módulos por responsabilidad (`config`, `blockstream`, `derivation`, `mask`, `persistence`, `cli`, `web`). FastAPI montado como subpaquete `satoshi_tool/web/`. Job manager en memoria con `queue.Queue` thread-safe + colas SSE por job. Tests con `pytest` + `TestClient` + monkey-patching del cliente Blockstream para no depender de red.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, `bip_utils`, `mnemonic`, `requests`, pytest, openpyxl, httpx (para tests SSE async).

---

## Pre-requisitos

**Antes de empezar — gestión de versionado.** Aunque el push a GitHub se reserva para el cierre del proyecto, **necesitamos git local** desde el principio para que el ciclo TDD (test → impl → test pasa → commit) funcione. Cada tarea termina con un commit. Sin commits no hay punto de retorno si algo se rompe.

Si Boris prefiere no usar git ni siquiera local, los pasos de commit se sustituyen por etiquetas mentales y se mantiene un ZIP de respaldo cada N tareas. Pero se recomienda fuertemente git local.

## Spec de referencia

`docs/superpowers/specs/2026-05-10-web-ui-design.md`

Este plan implementa las secciones:
- §5 Estructura de ficheros (parcial: sólo backend; el frontend va en Plan #2)
- §7 API + streaming
- §8 Tests

Lo que **no** cubre este plan:
- §6 UI/UX (frontend, plan #2)
- §9 hitos 4.4–4.7 (frontend, PyWebView, pulido, .app)

## Vectores de prueba (constantes que se usan en varias tareas)

```python
# Mnemónica de test estándar BIP-39 (pública, sin fondos privados).
TEST_MNEMONIC_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
EXPECTED_TEST_ADDRS = {
    44: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    49: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
    84: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    86: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
}

# Fila de Test_wallets.xlsx
XLSX_MNEMONIC = "large witness lottery dinner quick video cabin episode alien orbit fish subject"
XLSX_BIP84_ADDR = "bc1qne7ma6c78u4q6x2hqgknzqfhtm36z99m42r2sd"
```

## Estructura final de ficheros tras este plan

```
Satoshi_Tool.py                  # SHIM legacy: importa y llama a satoshi_tool.cli.main()
requirements.txt                 # añade: fastapi, uvicorn[standard]
requirements-dev.txt             # NUEVO: pytest, pytest-asyncio, openpyxl, httpx
pytest.ini                       # NUEVO: config mínima

satoshi_tool/
├── __init__.py                  # exporta versión y constantes
├── config.py                    # paths, BLOCKSTREAM_BASE, _HTTP, RateLimiter, _BLOCKSTREAM_LIMITER, _HTTP_POOL, PURPOSE_LABELS
├── blockstream.py               # cliente API: address_summary_only, address_activity_*, _summary_*, _activity_*
├── derivation.py                # crear_semilla, derive_first_for_all_purposes, derivar_*, scan_purpose_with_gap_limit, infer_purpose_from_address
├── mask.py                      # _parse_mask, _estimate_combinations, _iter_mnemonics_from_mask
├── persistence.py               # _persist_passphrase_hit, _persist_seed_hit, read_history
├── cli.py                       # menú interactivo viejo (run_*_mode, prompt_mode, main)
└── web/
    ├── __init__.py
    ├── app.py                   # FastAPI app + montaje
    ├── jobs.py                  # JobManager (jobs en memoria + colas SSE)
    ├── models.py                # Pydantic schemas de request/response
    ├── routes_manual.py
    ├── routes_hunter.py
    ├── routes_passphrase.py
    ├── routes_auto.py
    ├── routes_generator.py
    ├── routes_history.py
    └── routes_jobs.py

tests/
├── __init__.py
├── conftest.py                  # fixtures comunes (TestClient, mock_blockstream)
├── test_derivation.py
├── test_mask.py
├── test_rate_limiter.py
├── test_persistence.py
└── test_api.py
```

---

## Task 0: Inicializar git + ZIP de respaldo

**Files:**
- Create: `.gitignore` (raíz)

- [ ] **Step 1: Crear ZIP de respaldo del estado actual fuera del proyecto**

```bash
( cd "/Users/boris/Desktop/Programación" && zip -r ~/Desktop/Bitcoin-backup-pre-fase4.zip Bitcoin -x "*.DS_Store" -x "Bitcoin/.superpowers/*" )
ls -lh ~/Desktop/Bitcoin-backup-pre-fase4.zip
```
Expected: ZIP creado, tamaño no-cero. Red de seguridad si algo se rompe. El sub-shell `( ... )` evita cambiar el cwd actual.

- [ ] **Step 2: Inicializar repo git en el directorio del proyecto**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" init
git -C "/Users/boris/Desktop/Programación/Bitcoin" config user.email "boris.garros@ovb.es"
git -C "/Users/boris/Desktop/Programación/Bitcoin" config user.name "Boris GT"
```
Expected: `Initialized empty Git repository`.

- [ ] **Step 3: Crear .gitignore**

```gitignore
# macOS
.DS_Store

# Python
__pycache__/
*.py[cod]
*$py.class
.pytest_cache/
.venv/
venv/

# Brainstorming workspace
.superpowers/

# IDE
.vscode/
.idea/

# Hits files (sensibles — no van a GitHub)
Passphrases_Cazadas.txt
Semillas_Cazadas.txt
```

- [ ] **Step 4: Commit inicial con todo el estado actual**

```bash
git add .gitignore
git add -A
git status   # revisar que NO entren los .txt de hits ni .DS_Store
git commit -m "chore: initial commit (estado tras fase 3)"
```
Expected: commit creado. `git status` después debe mostrar working tree clean.

---

## Task 1: Crear esqueleto del paquete `satoshi_tool/`

**Files:**
- Create: `satoshi_tool/__init__.py`
- Create: `satoshi_tool/config.py`
- Create: `satoshi_tool/blockstream.py` (vacío)
- Create: `satoshi_tool/derivation.py` (vacío)
- Create: `satoshi_tool/mask.py` (vacío)
- Create: `satoshi_tool/persistence.py` (vacío)
- Create: `satoshi_tool/cli.py` (vacío)
- Create: `satoshi_tool/web/__init__.py` (vacío)

- [ ] **Step 1: Crear los directorios y ficheros vacíos**

```bash
mkdir -p satoshi_tool/web
touch satoshi_tool/__init__.py
touch satoshi_tool/blockstream.py
touch satoshi_tool/derivation.py
touch satoshi_tool/mask.py
touch satoshi_tool/persistence.py
touch satoshi_tool/cli.py
touch satoshi_tool/web/__init__.py
```

- [ ] **Step 2: Escribir `satoshi_tool/__init__.py`**

```python
"""Satoshi's Tool — utilidades BIP-39 / HD para Bitcoin mainnet."""

__version__ = "0.4.0"
```

- [ ] **Step 3: Crear `satoshi_tool/config.py` con todas las constantes globales**

```python
"""Constantes y singletons compartidos: paths, sesión HTTP, rate limiter, thread pool."""

from __future__ import annotations

import concurrent.futures
import os
import threading
import time
from pathlib import Path

import requests

# Paths de salida (los hits se guardan en la raíz del proyecto, NO dentro del paquete)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PASSPHRASE_HITS_FILEPATH = str(PROJECT_ROOT / "Passphrases_Cazadas.txt")
SEED_HITS_FILEPATH = str(PROJECT_ROOT / "Semillas_Cazadas.txt")

# API Blockstream
BLOCKSTREAM_BASE = "https://blockstream.info/api"

# Sesión HTTP global (reutiliza conexiones)
_HTTP = requests.Session()
_HTTP.headers.update({"User-Agent": "Satoshi-Tool/0.4"})


class RateLimiter:
    """Token bucket simple y thread-safe.
    Permite hasta 'burst' peticiones inmediatas y luego rellena a 'rate_per_sec'."""

    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last
                self.last = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(wait)


# Throttling y pool global. Reajustables si en el futuro hay nodo personal.
_BLOCKSTREAM_LIMITER = RateLimiter(rate_per_sec=8.0, burst=16)
_HTTP_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="btc-http"
)

# Etiquetas de los purposes BIP (usadas en CLI y en frontend)
PURPOSE_LABELS = {
    44: "BIP44  (Legacy P2PKH, 1...)",
    49: "BIP49  (P2SH-P2WPKH, 3...)",
    84: "BIP84  (P2WPKH bech32, bc1q...)",
    86: "BIP86  (Taproot P2TR, bc1p...)",
}
```

- [ ] **Step 4: Verificar import del paquete**

```bash
python3 -c "import satoshi_tool; print(satoshi_tool.__version__)"
```
Expected: `0.4.0`.

- [ ] **Step 5: Commit**

```bash
git add satoshi_tool/
git commit -m "feat(pkg): crear esqueleto del paquete satoshi_tool con config global"
```

---

## Task 2: Tests + migración de `RateLimiter`

**Files:**
- Create: `requirements-dev.txt`
- Create: `pytest.ini`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/test_rate_limiter.py`

- [ ] **Step 1: Crear `requirements-dev.txt`**

```
pytest>=7.4
pytest-asyncio>=0.21
openpyxl>=3.1
httpx>=0.25
```

- [ ] **Step 2: Crear `pytest.ini`**

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
```

- [ ] **Step 3: Instalar deps de desarrollo**

```bash
python3 -m pip install -r requirements-dev.txt
```
Expected: instalación sin errores.

- [ ] **Step 4: Crear `tests/__init__.py` vacío y `tests/conftest.py`**

```python
# tests/conftest.py
"""Fixtures comunes para todos los tests."""

import pytest


@pytest.fixture
def test_mnemonic_12():
    return (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )


@pytest.fixture
def expected_test_addrs():
    return {
        44: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        49: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        84: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        86: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    }
```

- [ ] **Step 5: Escribir `tests/test_rate_limiter.py` (failing)**

```python
"""Tests del token bucket RateLimiter."""

import threading
import time

from satoshi_tool.config import RateLimiter


def test_burst_no_blocking():
    """Las primeras 'burst' adquisiciones no deben bloquear."""
    rl = RateLimiter(rate_per_sec=8.0, burst=16)
    start = time.monotonic()
    for _ in range(16):
        rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.05, f"burst no debería bloquear, tardó {elapsed:.3f}s"


def test_first_post_burst_blocks():
    """La adquisición 17 (post-burst) debe bloquear ~ 1/rate."""
    rl = RateLimiter(rate_per_sec=8.0, burst=2)
    rl.acquire()
    rl.acquire()
    start = time.monotonic()
    rl.acquire()
    elapsed = time.monotonic() - start
    expected = 1.0 / 8.0
    assert expected * 0.7 < elapsed < expected * 2.0, f"esperado ~{expected}s, fue {elapsed}s"


def test_concurrent_acquires_respect_rate():
    """4 hilos haciendo 25 acquires cada uno = 100 total. A 50/s con burst 5,
    deberían tardar aproximadamente (100-5)/50 = 1.9s."""
    rl = RateLimiter(rate_per_sec=50.0, burst=5)

    def worker():
        for _ in range(25):
            rl.acquire()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    # tolerancia generosa: 1.5–3s
    assert 1.5 < elapsed < 3.0, f"esperado ~1.9s, fue {elapsed:.3f}s"
```

- [ ] **Step 6: Ejecutar tests, deben pasar (RateLimiter ya está en config.py)**

```bash
pytest tests/test_rate_limiter.py -v
```
Expected: 3 PASSED.

- [ ] **Step 7: Commit**

```bash
git add requirements-dev.txt pytest.ini tests/
git commit -m "test(rate-limiter): suite pytest del token bucket"
```

---

## Task 3: Tests + migración de `blockstream.py`

**Files:**
- Modify: `satoshi_tool/blockstream.py` (de vacío a poblado)
- Create: stub usado por `test_api.py` futura (los tests de blockstream puro requieren red real, los omitimos en esta tarea — sólo migramos código).

- [ ] **Step 1: Migrar el contenido de blockstream del fichero monolítico**

Copiar a `satoshi_tool/blockstream.py` (origen: `Satoshi_Tool.py` líneas correspondientes):

```python
"""Cliente HTTP para la API pública de Blockstream (mainnet)."""

from __future__ import annotations

import time
from typing import Any, Dict, List

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
    address: str, timeout: int = 15, session: requests.Session = None
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
    address: str, timeout: int = 15, session: requests.Session = None
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
```

- [ ] **Step 2: Verificar import**

```bash
python3 -c "from satoshi_tool import blockstream; print(blockstream.BLOCKSTREAM_BASE)"
```
Expected: `https://blockstream.info/api`.

- [ ] **Step 3: Commit**

```bash
git add satoshi_tool/blockstream.py
git commit -m "refactor(blockstream): extraer cliente API a su propio módulo"
```

---

## Task 4: Tests + migración de `derivation.py`

**Files:**
- Modify: `satoshi_tool/derivation.py`
- Create: `tests/test_derivation.py`

- [ ] **Step 1: Escribir `tests/test_derivation.py` (failing)**

```python
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
    # Volver a derivar de la semilla generada debe funcionar (checksum BIP-39 válido)
    d = derivar_primera_direccion_por_purpose(
        seed_mode="mnemonic", seed_value=s["mnemonic"], passphrase="", purpose=84,
    )
    assert d["address"].startswith("bc1q")


def test_crear_semilla_24_words_valid():
    s = crear_semilla(24)
    assert len(s["words"]) == 24


def test_scan_stops_at_gap_limit_when_all_empty(test_mnemonic_12):
    """Si address_summary_only siempre devuelve vacío, debe parar exactamente en gap_limit."""
    empty = {"total": 0, "confirmed": 0, "unconfirmed": 0, "ever_received": False, "ever_spent": False}

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
    # max_index=16, batch_size=8 → escanea exactamente 16 en cada cadena.
    assert res["external"]["scanned"] == 16
    assert res["internal"]["scanned"] == 16
    assert len(res["external"]["used"]) == 16
    assert len(res["internal"]["used"]) == 16
    assert res["total_sats"] == 1234 * 32  # 16 ext + 16 int


def test_scan_wif_raises():
    with pytest.raises(ValueError, match="WIF"):
        scan_purpose_with_gap_limit(
            seed_mode="wif", seed_value="L4rK1...", passphrase="", purpose=84,
        )
```

- [ ] **Step 2: Ejecutar tests, deben fallar (módulo aún vacío)**

```bash
pytest tests/test_derivation.py -v
```
Expected: ImportError o equivalente — `satoshi_tool.derivation` no exporta nada todavía.

- [ ] **Step 3: Migrar el código de derivación al módulo**

Copiar a `satoshi_tool/derivation.py`:

```python
"""Derivación HD BIP-39/44/49/84/86 + escaneo con gap limit."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import concurrent.futures

from bip_utils import (
    Bip39Languages, Bip39MnemonicValidator, Bip39SeedGenerator,
    Bip44, Bip44Changes, Bip44Coins,
    Bip49, Bip49Coins,
    Bip84, Bip84Coins,
    Bip86, Bip86Coins,
)
from mnemonic import Mnemonic

from satoshi_tool.blockstream import _summary_single_throttled
from satoshi_tool.config import _HTTP_POOL


def crear_semilla(generate_words: int = 12) -> Dict[str, Any]:
    """Genera una nueva mnemónica BIP-39 (inglés)."""
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=128 if generate_words == 12 else 256)
    return {"mnemonic": mnemonic, "words": mnemonic.split()}


def infer_purpose_from_address(address: str) -> Optional[int]:
    """Devuelve 44/49/84/86 según el prefijo, o None si no se puede inferir."""
    if not address or not isinstance(address, str):
        return None
    a = address.strip().lower()
    if a.startswith("bc1p"):
        return 86
    if a.startswith("bc1q"):
        return 84
    if a.startswith("1"):
        return 44
    if a.startswith("3"):
        return 49
    return None


def derivar_primera_direccion_por_purpose(
    *,
    seed_mode: str,
    seed_value: str,
    passphrase: str = "",
    purpose: int = 84,
    account: int = 0,
    change: int = 0,
    index: int = 0,
) -> Dict[str, Any]:
    """Deriva m/<purpose>'/0'/<account>'/<change>/<index> desde mnemónica/xprv/WIF."""
    if seed_mode not in ("mnemonic", "xprv", "wif"):
        raise ValueError("seed_mode debe ser 'mnemonic', 'xprv' o 'wif'.")
    if purpose not in (44, 49, 84, 86):
        raise ValueError("purpose debe ser 44, 49, 84 o 86.")
    if account < 0 or change not in (0, 1) or index < 0:
        raise ValueError("Parámetros fuera de rango: account>=0, change∈{0,1}, index>=0.")

    if seed_mode == "wif":
        try:
            from bitcoinlib.keys import Key
        except Exception as e:
            raise ImportError(
                "Para WIF necesitas 'bitcoinlib'. Instala: python3 -m pip install bitcoinlib"
            ) from e
        k = Key(import_key=seed_value, network="bitcoin")
        addr_legacy = k.address()
        try:
            addr_segwit = k.address(witness_type="segwit")
        except Exception:
            addr_segwit = None
        address = addr_legacy if purpose == 44 else (addr_segwit or addr_legacy)
        return {
            "path": "(WIF único, sin HD)",
            "address": address,
            "wif": seed_value,
            "pubkey_hex": k.public_hex,
            "account_xpub": None,
            "account_xprv": None,
            "root_xprv": None,
        }

    cls_by_purpose = {44: Bip44, 49: Bip49, 84: Bip84, 86: Bip86}
    coins_by_purpose = {
        44: Bip44Coins.BITCOIN, 49: Bip49Coins.BITCOIN,
        84: Bip84Coins.BITCOIN, 86: Bip86Coins.BITCOIN,
    }
    bip_cls = cls_by_purpose[purpose]
    coin = coins_by_purpose[purpose]

    if seed_mode == "mnemonic":
        validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
        if not validator.IsValid(seed_value):
            raise ValueError("Mnemónica inválida según BIP39.")
        seed_bytes = Bip39SeedGenerator(seed_value).Generate(passphrase)
        ctx = bip_cls.FromSeed(seed_bytes, coin)
    else:  # xprv
        if not seed_value.startswith("xprv"):
            raise ValueError("Se espera xprv (prefijo 'xprv').")
        ctx = bip_cls.FromExtendedKey(seed_value, coin)

    try:
        acct = ctx.Purpose().Coin().Account(account)
    except Exception:
        acct = ctx
    try:
        chain_node = acct.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
    except Exception:
        chain_node = acct
    node = chain_node.AddressIndex(index)

    coin_type_num = 0  # mainnet
    path = f"m/{purpose}'/{coin_type_num}'/{account}'/{change}/{index}"

    try:
        account_xpub = acct.PublicKey().ToExtended()
        account_xprv = acct.PrivateKey().ToExtended()
    except Exception:
        account_xpub = None
        account_xprv = None

    try:
        root_xprv = ctx.PrivateKey().ToExtended() if seed_mode == "mnemonic" else None
    except Exception:
        root_xprv = None

    return {
        "path": path,
        "address": node.PublicKey().ToAddress(),
        "wif": node.PrivateKey().ToWif(),
        "pubkey_hex": node.PublicKey().RawCompressed().ToHex(),
        "account_xpub": account_xpub,
        "account_xprv": account_xprv,
        "root_xprv": root_xprv,
    }


def derive_first_for_all_purposes(
    seed_mode: str, seed_value: str, passphrase: str = ""
) -> List[Dict[str, Any]]:
    """Intenta derivar m/.../0/0 para los 4 purposes. No lanza: marca ok/error por cada uno."""
    results: List[Dict[str, Any]] = []
    for purpose in (44, 49, 84, 86):
        try:
            d = derivar_primera_direccion_por_purpose(
                seed_mode=seed_mode, seed_value=seed_value, passphrase=passphrase,
                purpose=purpose, account=0, change=0, index=0,
            )
            results.append({"purpose": purpose, "ok": True, "data": d})
        except Exception as e:
            results.append({"purpose": purpose, "ok": False, "error": str(e)})
    return results


def scan_purpose_with_gap_limit(
    *,
    seed_mode: str,
    seed_value: str,
    passphrase: str = "",
    purpose: int = 84,
    account: int = 0,
    gap_limit: int = 20,
    max_index: int = 200,
    on_progress=None,
) -> Dict[str, Any]:
    """Escanea cadenas externa (change=0) e interna (change=1) hasta gap_limit consecutivas
    sin actividad. Reutiliza un único contexto BIP por cadena. No aplica a WIF."""
    if seed_mode == "wif":
        raise ValueError("WIF no soporta escaneo HD (es una clave plana).")
    if purpose not in (44, 49, 84, 86):
        raise ValueError("purpose debe ser 44, 49, 84 o 86.")

    cls_by_purpose = {44: Bip44, 49: Bip49, 84: Bip84, 86: Bip86}
    coins_by_purpose = {
        44: Bip44Coins.BITCOIN, 49: Bip49Coins.BITCOIN,
        84: Bip84Coins.BITCOIN, 86: Bip86Coins.BITCOIN,
    }
    bip_cls = cls_by_purpose[purpose]
    coin = coins_by_purpose[purpose]
    coin_type_num = 0  # mainnet

    if seed_mode == "mnemonic":
        validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
        if not validator.IsValid(seed_value):
            raise ValueError("Mnemónica inválida según BIP39.")
        seed_bytes = Bip39SeedGenerator(seed_value).Generate(passphrase)
        ctx = bip_cls.FromSeed(seed_bytes, coin)
    else:  # xprv
        if not seed_value.startswith("xprv"):
            raise ValueError("Se espera xprv (prefijo 'xprv').")
        ctx = bip_cls.FromExtendedKey(seed_value, coin)

    acct = ctx.Purpose().Coin().Account(account)
    summary: Dict[str, Any] = {
        "purpose": purpose, "account": account,
        "external": None, "internal": None,
    }
    batch_size = 8

    for change in (0, 1):
        chain_node = acct.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
        consec_empty = 0
        i = 0
        used: List[Dict[str, Any]] = []
        total = confirmed = unconfirmed = 0

        while consec_empty < gap_limit and i < max_index:
            end = min(i + batch_size, max_index)
            batch: List[Tuple[int, str, str]] = []
            for j in range(i, end):
                node = chain_node.AddressIndex(j)
                addr = node.PublicKey().ToAddress()
                path = f"m/{purpose}'/{coin_type_num}'/{account}'/{change}/{j}"
                batch.append((j, addr, path))

            futures = {
                _HTTP_POOL.submit(_summary_single_throttled, addr, 3, 10): j
                for j, addr, _ in batch
            }
            results: Dict[int, Dict[str, Any]] = {}
            errors: Dict[int, str] = {}
            for fut in concurrent.futures.as_completed(futures):
                j = futures[fut]
                try:
                    results[j] = fut.result()
                except Exception as e:
                    errors[j] = str(e)

            last_processed = i - 1
            cut_in_batch = False
            for j, addr, path in batch:
                last_processed = j
                if j in errors:
                    if on_progress:
                        on_progress(purpose, change, j, addr, "error", error=errors[j])
                    continue
                act = results[j]
                if act["ever_received"] or act["total"] > 0:
                    used.append({
                        "index": j, "path": path, "address": addr,
                        "total": act["total"], "confirmed": act["confirmed"],
                        "unconfirmed": act["unconfirmed"],
                        "ever_received": act["ever_received"], "ever_spent": act["ever_spent"],
                    })
                    total += act["total"]
                    confirmed += act["confirmed"]
                    unconfirmed += act["unconfirmed"]
                    consec_empty = 0
                    if on_progress:
                        on_progress(purpose, change, j, addr, "used", act=act)
                else:
                    consec_empty += 1
                    if on_progress:
                        on_progress(purpose, change, j, addr, "empty")
                    if consec_empty >= gap_limit:
                        cut_in_batch = True
                        break

            i = last_processed + 1
            if cut_in_batch:
                break

        side = "external" if change == 0 else "internal"
        summary[side] = {
            "scanned": i, "used": used,
            "total_sats": total, "confirmed": confirmed, "unconfirmed": unconfirmed,
        }

    summary["total_sats"] = (
        summary["external"]["total_sats"] + summary["internal"]["total_sats"]
    )
    return summary


def derivar_direcciones_batch_mnemonic(
    mnemonic_str: str, passphrase: str = "", account: int = 0,
    change: int = 0, start: int = 0, count: int = 3,
) -> Dict[str, Any]:
    """Deriva 'count' direcciones BIP84 consecutivas (usado por modo Auto)."""
    validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
    if not validator.IsValid(mnemonic_str):
        raise ValueError("Mnemónica inválida según BIP39.")

    seed_bytes = Bip39SeedGenerator(mnemonic_str).Generate(passphrase)
    ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)

    root_xprv = ctx.PrivateKey().ToExtended()
    acct = ctx.Purpose().Coin().Account(account)
    chain_node = acct.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)

    coin_type_num = 0
    addrs: List[Dict[str, str]] = []
    for i in range(start, start + count):
        node = chain_node.AddressIndex(i)
        addrs.append({
            "path": f"m/84'/{coin_type_num}'/{account}'/{change}/{i}",
            "address": node.PublicKey().ToAddress(),
            "wif": node.PrivateKey().ToWif(),
            "pubkey_hex": node.PublicKey().RawCompressed().ToHex(),
        })

    return {
        "root_xprv": root_xprv,
        "account_xpub": acct.PublicKey().ToExtended(),
        "account_xprv": acct.PrivateKey().ToExtended(),
        "account_path": f"m/84'/{coin_type_num}'/{account}'",
        "change_path": f"m/84'/{coin_type_num}'/{account}'/{change}",
        "addresses": addrs,
    }
```

- [ ] **Step 4: Ejecutar tests, deben pasar**

```bash
pytest tests/test_derivation.py -v
```
Expected: 9 PASSED.

- [ ] **Step 5: Commit**

```bash
git add satoshi_tool/derivation.py tests/test_derivation.py
git commit -m "feat(derivation): extraer derivación HD a su módulo + tests con vectores BIP-39"
```

---

## Task 5: Tests + migración de `mask.py`

**Files:**
- Modify: `satoshi_tool/mask.py`
- Create: `tests/test_mask.py`

- [ ] **Step 1: Escribir `tests/test_mask.py` (failing)**

```python
"""Tests del parser de máscaras y generador de candidatos."""

import pytest

from satoshi_tool.mask import (
    _estimate_combinations, _iter_mnemonics_from_mask, _parse_mask,
)


def test_parse_mask_fixed_words():
    tokens, unknowns, prefixes, words = _parse_mask("abandon abandon abandon ?")
    assert tokens == ["abandon", "abandon", "abandon", "?"]
    assert unknowns == [3]
    assert prefixes == {}


def test_parse_mask_with_prefix():
    tokens, unknowns, prefixes, words = _parse_mask("abandon ab* ?")
    assert tokens == ["abandon", "ab*", "?"]
    assert unknowns == [2]
    assert prefixes == {1: "ab"}


def test_estimate_one_unknown():
    tokens, _, prefixes, allowed = _parse_mask(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon ?"
    )
    est = _estimate_combinations(tokens, prefixes, allowed)
    assert est == 2048


def test_estimate_with_prefix():
    tokens, _, prefixes, allowed = _parse_mask(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon ab*"
    )
    est = _estimate_combinations(tokens, prefixes, allowed)
    assert est == sum(1 for w in allowed if w.startswith("ab"))


def test_iter_yields_test_mnemonic_among_valid():
    """Para 'abandon × 11 ?', la mnemónica de test estándar debe estar entre las que pasan checksum."""
    target = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    mask = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?"
    found = False
    for mn in _iter_mnemonics_from_mask(mask):
        if mn == target:
            found = True
            break
    assert found, "la mnemónica de test debería estar en las válidas"


def test_iter_invalid_word_raises():
    with pytest.raises(ValueError):
        list(_iter_mnemonics_from_mask("abandon notaword ? ? ? ? ? ? ? ? ? ?"))


def test_mask_wrong_length_raises():
    with pytest.raises(ValueError, match="12 o 24"):
        list(_iter_mnemonics_from_mask("abandon abandon ?"))
```

- [ ] **Step 2: Ejecutar tests, deben fallar**

```bash
pytest tests/test_mask.py -v
```
Expected: ImportError.

- [ ] **Step 3: Migrar `satoshi_tool/mask.py`**

```python
"""Parser de máscaras tipo 'palabra ? pre*' y generador de candidatos BIP-39 con checksum."""

from __future__ import annotations

from typing import Iterator, List

from mnemonic import Mnemonic


def _parse_mask(mask_str: str):
    """Devuelve (mask_tokens, unknown_positions, prefix_constraints, allowed_words)."""
    tokens = mask_str.strip().split()
    unknown_positions: List[int] = []
    prefix_constraints: dict = {}
    all_words = Mnemonic("english").wordlist

    mask_tokens: List[str] = []
    for idx, tok in enumerate(tokens):
        tok = tok.strip().lower()
        if tok == "?":
            mask_tokens.append("?")
            unknown_positions.append(idx)
        elif tok.endswith("*") and len(tok) > 1:
            prefix = tok[:-1]
            prefix_constraints[idx] = prefix
            mask_tokens.append(tok)
        else:
            mask_tokens.append(tok)

    return mask_tokens, unknown_positions, prefix_constraints, all_words


def _estimate_combinations(mask_tokens, prefix_constraints, allowed_words) -> int:
    """Estima combinaciones antes del filtro de checksum."""
    total = 1
    for idx, tok in enumerate(mask_tokens):
        if tok == "?":
            if idx in prefix_constraints:
                pref = prefix_constraints[idx]
                total *= sum(1 for w in allowed_words if w.startswith(pref))
            else:
                total *= len(allowed_words)
        elif tok.endswith("*") and len(tok) > 1:
            pref = prefix_constraints.get(idx, tok[:-1])
            total *= sum(1 for w in allowed_words if w.startswith(pref))
        # palabra fija: ×1
    return total


def _iter_mnemonics_from_mask(mask_str: str) -> Iterator[str]:
    """Genera mnemónicas (12/24) que cumplen checksum BIP-39, según la máscara."""
    mnemo = Mnemonic("english")
    all_words = mnemo.wordlist
    tokens = mask_str.strip().lower().split()

    if len(tokens) not in (12, 24):
        raise ValueError("La mnemónica debe tener 12 o 24 palabras.")

    choices_per_pos: List[List[str]] = []
    for tok in tokens:
        if tok == "?":
            choices_per_pos.append(all_words)
        elif tok.endswith("*") and len(tok) > 1:
            pref = tok[:-1]
            pool = [w for w in all_words if w.startswith(pref)]
            choices_per_pos.append(pool)
        else:
            if tok not in all_words:
                raise ValueError(f"La palabra fija '{tok}' no está en la lista BIP-39.")
            choices_per_pos.append([tok])

    curr = [""] * len(tokens)

    def bt(i: int):
        if i == len(tokens):
            phrase = " ".join(curr)
            if mnemo.check(phrase):
                yield phrase
            return
        for w in choices_per_pos[i]:
            curr[i] = w
            yield from bt(i + 1)

    yield from bt(0)
```

- [ ] **Step 4: Ejecutar tests, deben pasar**

```bash
pytest tests/test_mask.py -v
```
Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add satoshi_tool/mask.py tests/test_mask.py
git commit -m "feat(mask): extraer parser y generador de máscaras + tests de checksum"
```

---

## Task 6: Tests + migración de `persistence.py` con `read_history`

**Files:**
- Modify: `satoshi_tool/persistence.py`
- Create: `tests/test_persistence.py`

- [ ] **Step 1: Escribir `tests/test_persistence.py` (failing)**

```python
"""Tests de escritura/lectura de los TXT JSONL de hits."""

import json
import os
import tempfile

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
    # La última línea debe ser JSONL parseable
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
    # Orden por timestamp ascendente
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
```

- [ ] **Step 2: Ejecutar tests, deben fallar**

```bash
pytest tests/test_persistence.py -v
```
Expected: ImportError.

- [ ] **Step 3: Migrar `satoshi_tool/persistence.py` (incluye función `read_history` nueva)**

```python
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
```

- [ ] **Step 4: Ejecutar tests, deben pasar**

```bash
pytest tests/test_persistence.py -v
```
Expected: 5 PASSED.

- [ ] **Step 5: Commit**

```bash
git add satoshi_tool/persistence.py tests/test_persistence.py
git commit -m "feat(persistence): extraer hits a su módulo + read_history para el tab Histórico"
```

---

## Task 7: Migrar `cli.py` (CLI viejo) y `Satoshi_Tool.py` shim

**Files:**
- Modify: `satoshi_tool/cli.py`
- Modify: `Satoshi_Tool.py` (sustitución completa, **al final**)

**ORDEN CRÍTICO:** las funciones `run_*_mode` viven todavía en `Satoshi_Tool.py` raíz. Hay que copiarlas a `cli.py` ANTES de sustituir el fichero raíz por el shim. Si inviertes el orden, pierdes el código fuente.

- [ ] **Step 1: Migrar el CLI viejo a `satoshi_tool/cli.py`**

Crear el contenido de `satoshi_tool/cli.py` con la estructura siguiente. La sección "PEGAR FUNCIONES `run_*`" se completa en el step siguiente.

```python
"""Menú interactivo clásico (CLI). Sin cambios funcionales respecto a fase 3.
Sigue siendo punto de entrada headless para uso en remoto/scripts."""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional

from mnemonic import Mnemonic
from bip_utils import Bip39Languages, Bip39MnemonicValidator

from satoshi_tool.blockstream import _activity_batch, _activity_single_with_retry
from satoshi_tool.config import PURPOSE_LABELS, SEED_HITS_FILEPATH
from satoshi_tool.derivation import (
    crear_semilla,
    derivar_direcciones_batch_mnemonic,
    derivar_primera_direccion_por_purpose,
    derive_first_for_all_purposes,
    infer_purpose_from_address,
    scan_purpose_with_gap_limit,
)
from satoshi_tool.mask import (
    _estimate_combinations, _iter_mnemonics_from_mask, _parse_mask,
)
from satoshi_tool.persistence import _persist_passphrase_hit, _persist_seed_hit


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg: str = "Pulsa Enter para continuar...") -> None:
    try:
        input(msg)
    except KeyboardInterrupt:
        print("\nSaliendo...")
        sys.exit(0)


def print_header(title: str) -> None:
    print("========================================")
    print(f"   {title}")
    print("========================================")


def ask_menu_option(prompt: str, valid: set) -> str:
    while True:
        choice = input(prompt).strip()
        if choice.upper() in {v.upper() for v in valid}:
            return choice.upper()
        print("Opción no válida. Intenta de nuevo.\n")


def normalize_mnemonic(s: str) -> str:
    return " ".join(s.strip().lower().split())


def print_banner():
    print(r"""
┏━┓┏━┓╺┳╸┏━┓┏━┓╻ ╻╻╻┏━┓   ╺┳╸┏━┓┏━┓╻
┗━┓┣━┫ ┃ ┃ ┃┗━┓┣━┫┃ ┗━┓    ┃ ┃ ┃┃ ┃┃
┗━┛╹ ╹ ╹ ┗━┛┗━┛╹ ╹╹ ┗━┛    ╹ ┗━┛┗━┛┗━╸

    🚀 Satoshi's Tool
    💻 Created by BorisGT
    🔗 github.com/Borisgt-10
""")


def prompt_mode() -> str:
    print_header("Satoshi's Tool — Modo de Ejecución")
    print("[1] Automático")
    print("[2] Manual")
    print("[3] Passphrase Hunter")
    print("[4] Seed Hunter")
    print("[5] Generador de Semillas")
    print("[Q] Salir")
    return ask_menu_option(
        "\nElige una opción [1/2/3/4/5/Q]: ", {"1", "2", "3", "4", "5", "Q"}
    )


# A continuación: copiar ÍNTEGRO desde el actual Satoshi_Tool.py los siguientes
# bloques de funciones (sin cambios de comportamiento, solo cambian los imports
# de top-level a los módulos del paquete):
#
#   - run_automatic_mode
#   - _manual_quick_scan
#   - _manual_full_scan
#   - run_manual_mode
#   - run_passphrase_mode
#   - run_seed_hunter_mode
#   - run_seed_generator_mode
#
# (Por brevedad del plan: el agente debe copiar estas funciones tal cual,
#  cambiando solo cualquier referencia interna a símbolos no-importados arriba.
#  Verifica con grep que no usen funciones que no estén importadas.)


def main() -> None:
    clear_screen()
    print_banner()
    mode = prompt_mode()

    if mode == "Q":
        print("Hasta luego 👋")
        sys.exit(0)

    if mode == "1":
        clear_screen(); print("Modo AUTOMÁTICO seleccionado.\n"); run_automatic_mode(); pause()
    elif mode == "2":
        clear_screen(); print("Modo MANUAL seleccionado.\n"); run_manual_mode(); pause()
    elif mode == "3":
        clear_screen(); print("Modo PASSPHRASE HUNTER seleccionado.\n"); run_passphrase_mode(); pause()
    elif mode == "4":
        clear_screen(); print("Modo SEED HUNTER seleccionado.\n"); run_seed_hunter_mode(); pause()
    elif mode == "5":
        clear_screen(); print("Modo GENERADOR DE SEMILLAS seleccionado.\n"); run_seed_generator_mode(); pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido. ¡Hasta luego!")
```

- [ ] **Step 2: Pegar las funciones `run_*` del fichero original al cli.py recién creado**

Tomar de `Satoshi_Tool.py` actual (sigue intacto en raíz; cuando se sustituya por el shim será en step 4) las funciones:
- `run_automatic_mode`
- `_manual_quick_scan`
- `_manual_full_scan`
- `run_manual_mode`
- `run_passphrase_mode`
- `run_seed_hunter_mode`
- `run_seed_generator_mode`

Insertarlas en `satoshi_tool/cli.py` justo encima de `def main()`. **Verificar imports**: cualquier referencia a `globals().get("PASSPHRASE_HITS_FILEPATH", ...)` se sustituye por uso directo de la constante importada desde `satoshi_tool.config`. Cualquier llamada a `_persist_seed_hit`/`_persist_passphrase_hit` ya está cubierta por los imports del top.

Backup disponible en el ZIP de Task 0 si necesitas comparar, y `git show HEAD:Satoshi_Tool.py` si necesitas ver el commit inicial.

- [ ] **Step 3: Verificar que `cli.py` arranca y muestra el menú**

```bash
echo "Q" | python3 -m satoshi_tool.cli 2>&1 | tail -5
```
Expected: banner + menú + "Hasta luego 👋", sin tracebacks.

- [ ] **Step 4: Sustituir `Satoshi_Tool.py` raíz por el shim**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Satoshi's Tool — entrypoint legacy. Lanza el CLI clásico.
La interfaz web vive en `python3 -m satoshi_tool.web` (Plan #2)."""

from satoshi_tool.cli import main

if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Verificación: el entrypoint legacy sigue funcionando**

```bash
echo "Q" | python3 Satoshi_Tool.py 2>&1 | tail -5
```
Expected: idéntico al step 3.

- [ ] **Step 6: Verificación: el escaneo rápido del modo Manual funciona**

```bash
printf '2\nabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n\nR\n\nQ\n' | python3 Satoshi_Tool.py 2>&1 | tail -25
```
Expected: las 4 direcciones BIP44/49/84/86 con saldo 0.0, "Usada: Sí" en todas.

- [ ] **Step 7: Commit**

```bash
git add Satoshi_Tool.py satoshi_tool/cli.py
git commit -m "refactor(cli): trasladar menú interactivo a satoshi_tool.cli; entrypoint queda como shim"
```

---

## Task 8: Setup FastAPI base + endpoint `/api/health`

**Files:**
- Modify: `requirements.txt`
- Create: `satoshi_tool/web/app.py`
- Modify: `tests/conftest.py` (añadir fixture `client`)
- Create: `tests/test_api.py`

- [ ] **Step 1: Añadir FastAPI a `requirements.txt`**

```
mnemonic==0.20
bip_utils>=2.8.0
requests>=2.25.0
fastapi>=0.110
uvicorn[standard]>=0.27
```

- [ ] **Step 2: Instalar deps**

```bash
python3 -m pip install -r requirements.txt
```

- [ ] **Step 3: Crear `satoshi_tool/web/app.py`**

```python
"""Aplicación FastAPI: endpoints REST + (en tareas posteriores) SSE."""

from __future__ import annotations

from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(
        title="Satoshi's Tool",
        version="0.4.0",
        description="API local para BIP-39 / HD Bitcoin (mainnet).",
    )

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.4.0"}

    return app


app = create_app()
```

- [ ] **Step 4: Añadir fixture `client` a `tests/conftest.py`**

Añadir al final del fichero:

```python
from fastapi.testclient import TestClient

from satoshi_tool.web.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app())
```

- [ ] **Step 5: Test del endpoint `/api/health`**

Crear `tests/test_api.py`:

```python
"""Tests de la API FastAPI."""


def test_health_returns_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body
```

- [ ] **Step 6: Ejecutar test**

```bash
pytest tests/test_api.py -v
```
Expected: 1 PASSED.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt satoshi_tool/web/app.py tests/conftest.py tests/test_api.py
git commit -m "feat(web): bootstrap FastAPI app con /api/health"
```

---

## Task 9: Endpoint `/api/generator`

**Files:**
- Create: `satoshi_tool/web/models.py`
- Create: `satoshi_tool/web/routes_generator.py`
- Modify: `satoshi_tool/web/app.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test del endpoint (failing)**

Añadir a `tests/test_api.py`:

```python
def test_generator_returns_valid_mnemonic_12(client):
    r = client.post("/api/generator", json={"words": 12})
    assert r.status_code == 200
    body = r.json()
    assert "mnemonic" in body
    assert len(body["mnemonic"].split()) == 12
    # debe ser checksum-válida
    from mnemonic import Mnemonic
    assert Mnemonic("english").check(body["mnemonic"])


def test_generator_returns_24_words(client):
    r = client.post("/api/generator", json={"words": 24})
    assert r.status_code == 200
    body = r.json()
    assert len(body["mnemonic"].split()) == 24


def test_generator_rejects_invalid_word_count(client):
    r = client.post("/api/generator", json={"words": 18})
    assert r.status_code == 422  # validation error
```

```bash
pytest tests/test_api.py::test_generator_returns_valid_mnemonic_12 -v
```
Expected: FAIL (404).

- [ ] **Step 2: Crear `satoshi_tool/web/models.py`**

```python
"""Pydantic schemas compartidos entre rutas."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class GeneratorRequest(BaseModel):
    words: Literal[12, 24] = Field(default=12)


class GeneratorResponse(BaseModel):
    mnemonic: str
    words: list[str]
```

- [ ] **Step 3: Crear `satoshi_tool/web/routes_generator.py`**

```python
"""POST /api/generator — crea una mnemónica BIP-39 nueva."""

from fastapi import APIRouter

from satoshi_tool.derivation import crear_semilla
from satoshi_tool.web.models import GeneratorRequest, GeneratorResponse

router = APIRouter()


@router.post("/api/generator", response_model=GeneratorResponse)
def generator(req: GeneratorRequest):
    s = crear_semilla(req.words)
    return GeneratorResponse(mnemonic=s["mnemonic"], words=s["words"])
```

- [ ] **Step 4: Registrar el router en `app.py`**

Modificar `satoshi_tool/web/app.py`:

```python
from satoshi_tool.web.routes_generator import router as generator_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Satoshi's Tool",
        version="0.4.0",
        description="API local para BIP-39 / HD Bitcoin (mainnet).",
    )

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.4.0"}

    app.include_router(generator_router)
    return app


app = create_app()
```

- [ ] **Step 5: Tests deben pasar**

```bash
pytest tests/test_api.py -v
```
Expected: 4 PASSED.

- [ ] **Step 6: Commit**

```bash
git add satoshi_tool/web/models.py satoshi_tool/web/routes_generator.py satoshi_tool/web/app.py tests/test_api.py
git commit -m "feat(api): POST /api/generator para crear mnemónicas BIP-39"
```

---

## Task 10: Endpoint `/api/manual/quick`

**Files:**
- Create: `satoshi_tool/web/routes_manual.py`
- Modify: `satoshi_tool/web/models.py`
- Modify: `satoshi_tool/web/app.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test del endpoint (failing)**

Añadir a `tests/test_api.py`:

```python
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
```

- [ ] **Step 2: Añadir schemas a `models.py`**

```python
class ManualQuickRequest(BaseModel):
    seed: str
    passphrase: str = ""


class DerivationResult(BaseModel):
    purpose: int
    ok: bool
    error: Optional[str] = None
    path: Optional[str] = None
    address: Optional[str] = None
    total_sats: Optional[int] = None
    ever_received: Optional[bool] = None
    ever_spent: Optional[bool] = None
    utxo_count: Optional[int] = None


class ManualQuickResponse(BaseModel):
    seed_mode: Literal["mnemonic", "xprv", "wif"]
    derivations: list[DerivationResult]
```

- [ ] **Step 3: Crear `satoshi_tool/web/routes_manual.py`**

```python
"""POST /api/manual/quick — derivación rápida (m/.../0/0) por purpose."""

from fastapi import APIRouter, HTTPException
from mnemonic import Mnemonic

from satoshi_tool.blockstream import _activity_batch
from satoshi_tool.derivation import derive_first_for_all_purposes
from satoshi_tool.web.models import (
    DerivationResult, ManualQuickRequest, ManualQuickResponse,
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

    out: list[DerivationResult] = []
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
```

- [ ] **Step 4: Registrar router en `app.py`**

Añadir:
```python
from satoshi_tool.web.routes_manual import router as manual_router
# ...
app.include_router(manual_router)
```

- [ ] **Step 5: Tests deben pasar**

```bash
pytest tests/test_api.py -v
```
Expected: 6 PASSED (previos + 2 nuevos).

- [ ] **Step 6: Commit**

```bash
git add satoshi_tool/web/routes_manual.py satoshi_tool/web/models.py satoshi_tool/web/app.py tests/test_api.py
git commit -m "feat(api): POST /api/manual/quick para derivación rápida"
```

---

## Task 11: Endpoint `/api/history`

**Files:**
- Create: `satoshi_tool/web/routes_history.py`
- Modify: `satoshi_tool/web/app.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test del endpoint (failing)**

Añadir a `tests/test_api.py`:

```python
def test_history_returns_combined_hits(tmp_path, monkeypatch):
    """Crea ambos archivos en tmp_path, monkeypatchea las constantes y verifica /api/history."""
    from satoshi_tool.persistence import _persist_seed_hit, _persist_passphrase_hit
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
    client = TestClient(create_app())

    r = client.get("/api/history")
    assert r.status_code == 200
    body = r.json()
    assert len(body["hits"]) == 2
    modes = {h["mode"] for h in body["hits"]}
    assert modes == {"seed", "passphrase"}
```

- [ ] **Step 2: Crear `satoshi_tool/web/routes_history.py`**

```python
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
```

- [ ] **Step 3: Registrar router**

Añadir en `app.py`:
```python
from satoshi_tool.web.routes_history import router as history_router
app.include_router(history_router)
```

- [ ] **Step 4: Test debe pasar**

```bash
pytest tests/test_api.py -v
```
Expected: 7 PASSED.

- [ ] **Step 5: Commit**

```bash
git add satoshi_tool/web/routes_history.py satoshi_tool/web/app.py tests/test_api.py
git commit -m "feat(api): GET /api/history con filtros mode/since/until/with_balance"
```

---

## Task 12: Crear `satoshi_tool/web/jobs.py` (JobManager)

**Files:**
- Create: `satoshi_tool/web/jobs.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test del JobManager directamente (no API aún)**

Añadir a `tests/test_api.py`:

```python
def test_jobmanager_create_and_consume():
    from satoshi_tool.web.jobs import JobManager, JobEvent
    jm = JobManager(ttl_seconds=5)

    # Crear job
    def runner(emit, is_cancelled):
        emit(JobEvent(type="kpi", payload={"tested": 1}))
        emit(JobEvent(type="done", payload={"summary": "ok"}))

    job_id = jm.create(runner)
    # Consumir eventos
    events = list(jm.iter_events(job_id, timeout=2.0))
    types = [e.type for e in events]
    assert "kpi" in types
    assert types[-1] == "done"


def test_jobmanager_cancel_stops_runner():
    """El runner debe ver is_cancelled() == True después de cancel."""
    import time
    from satoshi_tool.web.jobs import JobManager, JobEvent

    jm = JobManager(ttl_seconds=5)
    consumed = []

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
```

```bash
pytest tests/test_api.py -v
```
Expected: FAIL (jobs no existe).

- [ ] **Step 2: Crear `satoshi_tool/web/jobs.py`**

```python
"""JobManager: jobs en memoria con cola SSE thread-safe."""

from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, Optional


@dataclass
class JobEvent:
    type: str          # 'kpi' | 'addr' | 'hit' | 'done' | 'error' | 'cancelled'
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def as_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "payload": self.payload, "timestamp": self.timestamp}


@dataclass
class _Job:
    id: str
    queue: "queue.Queue[Optional[JobEvent]]"
    cancel_flag: threading.Event
    thread: threading.Thread
    finished_at: Optional[float] = None


# Tipo del runner: recibe (emit, is_cancelled) y emite eventos.
RunnerFn = Callable[[Callable[[JobEvent], None], Callable[[], bool]], None]


class JobManager:
    """Mantiene jobs en memoria, lanza runners en threads daemon, consume eventos vía SSE."""

    def __init__(self, ttl_seconds: int = 60):
        self._jobs: Dict[str, _Job] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def create(self, runner: RunnerFn) -> str:
        job_id = uuid.uuid4().hex
        q: queue.Queue = queue.Queue()
        cancel_flag = threading.Event()

        def emit(event: JobEvent):
            q.put(event)

        def is_cancelled() -> bool:
            return cancel_flag.is_set()

        def thread_target():
            try:
                runner(emit, is_cancelled)
            except Exception as e:
                q.put(JobEvent(type="error", payload={"message": str(e)}))
                q.put(JobEvent(type="done", payload={"reason": "error"}))
            finally:
                q.put(None)  # sentinel
                with self._lock:
                    if job_id in self._jobs:
                        self._jobs[job_id].finished_at = time.time()

        t = threading.Thread(target=thread_target, daemon=True, name=f"job-{job_id[:8]}")
        with self._lock:
            self._jobs[job_id] = _Job(id=job_id, queue=q, cancel_flag=cancel_flag, thread=t)
        t.start()
        return job_id

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return False
        job.cancel_flag.set()
        return True

    def iter_events(self, job_id: str, timeout: float = 30.0) -> Iterator[JobEvent]:
        """Bloquea consumiendo la cola del job. Termina cuando recibe sentinel (None)."""
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return
        while True:
            try:
                ev = job.queue.get(timeout=timeout)
            except queue.Empty:
                return
            if ev is None:
                return
            yield ev

    def cleanup_finished(self) -> None:
        """Elimina jobs cuyo finished_at es anterior a TTL."""
        cutoff = time.time() - self._ttl
        with self._lock:
            stale = [jid for jid, j in self._jobs.items()
                     if j.finished_at is not None and j.finished_at < cutoff]
            for jid in stale:
                del self._jobs[jid]


# Instancia global compartida por todos los routers que crean jobs.
job_manager = JobManager(ttl_seconds=60)
```

- [ ] **Step 3: Tests deben pasar**

```bash
pytest tests/test_api.py -v
```
Expected: 9 PASSED.

- [ ] **Step 4: Commit**

```bash
git add satoshi_tool/web/jobs.py tests/test_api.py
git commit -m "feat(web/jobs): JobManager con runners en threads + cola SSE"
```

---

## Task 13: Endpoint `/api/manual/full` (con job)

**Files:**
- Modify: `satoshi_tool/web/routes_manual.py`
- Modify: `satoshi_tool/web/models.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test (failing) — usa monkey-patch del scan para no tocar red**

Añadir a `tests/test_api.py`:

```python
def test_manual_full_creates_job(client, test_mnemonic_12, monkeypatch):
    """POST /api/manual/full devuelve job_id; el runner emite KPIs y done."""

    def fake_scan(*, seed_mode, seed_value, passphrase, purpose, account, gap_limit, max_index, on_progress):
        # Emitir progreso simulado y devolver resumen vacío
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
```

- [ ] **Step 2: Añadir schemas a `models.py`**

```python
class ManualFullRequest(BaseModel):
    seed: str
    passphrase: str = ""
    gap_limit: int = Field(default=20, ge=1, le=200)


class JobStartResponse(BaseModel):
    job_id: str
```

- [ ] **Step 3: Añadir endpoint a `routes_manual.py`**

Pegar al final de `routes_manual.py`:

```python
from satoshi_tool.derivation import scan_purpose_with_gap_limit
from satoshi_tool.web.jobs import JobEvent, job_manager
from satoshi_tool.web.models import JobStartResponse, ManualFullRequest


@router.post("/api/manual/full", response_model=JobStartResponse)
def manual_full(req: ManualFullRequest):
    seed = req.seed.strip()
    seed_mode = _detect_seed_mode(seed)
    if seed_mode == "wif":
        raise HTTPException(status_code=400, detail="WIF no soporta escaneo HD.")
    if seed_mode == "mnemonic":
        normalized = " ".join(seed.lower().split())
        if not Mnemonic("english").check(normalized):
            raise HTTPException(status_code=400, detail="Mnemónica inválida.")
        seed_value = normalized
        passphrase = req.passphrase
    else:
        seed_value = seed
        passphrase = ""

    def runner(emit, is_cancelled):
        tested = 0
        hits = 0
        empty = 0
        errors = 0
        last_kpi = 0.0

        def cb(purpose, change, idx, addr, kind, **kw):
            nonlocal tested, hits, empty, errors, last_kpi
            tested += 1
            if kind == "used":
                hits += 1
                act = kw.get("act", {})
                emit(JobEvent(type="addr", payload={
                    "purpose": purpose, "change": change, "index": idx,
                    "address": addr, "status": "used",
                    "total_sats": act.get("total", 0),
                }))
                emit(JobEvent(type="hit", payload={
                    "purpose": purpose, "change": change, "index": idx,
                    "address": addr, "act": act,
                }))
            elif kind == "error":
                errors += 1
                emit(JobEvent(type="addr", payload={
                    "purpose": purpose, "change": change, "index": idx,
                    "address": addr, "status": "error", "error": kw.get("error"),
                }))
            else:  # empty
                empty += 1

            now = time.time()
            if now - last_kpi > 0.2 or kind in ("used", "error"):
                emit(JobEvent(type="kpi", payload={
                    "tested": tested, "hits": hits, "empty": empty, "errors": errors,
                }))
                last_kpi = now

        results: list = []
        for purpose in (44, 49, 84, 86):
            if is_cancelled():
                emit(JobEvent(type="cancelled", payload={}))
                break
            res = scan_purpose_with_gap_limit(
                seed_mode=seed_mode, seed_value=seed_value, passphrase=passphrase,
                purpose=purpose, account=0, gap_limit=req.gap_limit, max_index=200,
                on_progress=cb,
            )
            results.append(res)

        emit(JobEvent(type="done", payload={
            "summary": results,
            "totals": {"tested": tested, "hits": hits, "empty": empty, "errors": errors},
        }))

    import time  # local import to keep module top-level lean if not used elsewhere
    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
```

(Mover el `import time` al top del fichero al integrar.)

- [ ] **Step 4: Test debe pasar**

```bash
pytest tests/test_api.py::test_manual_full_creates_job -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add satoshi_tool/web/routes_manual.py satoshi_tool/web/models.py tests/test_api.py
git commit -m "feat(api): POST /api/manual/full crea job de escaneo HD con gap limit"
```

---

## Task 14: Endpoint `/api/hunter/start`

**Files:**
- Create: `satoshi_tool/web/routes_hunter.py`
- Modify: `satoshi_tool/web/models.py`
- Modify: `satoshi_tool/web/app.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test (failing)**

```python
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
```

- [ ] **Step 2: Añadir schema**

A `models.py`:

```python
class HunterStartRequest(BaseModel):
    mask: str
    target: str = ""
    passphrase: str = ""
    purpose: Literal[44, 49, 84, 86] = 84
```

- [ ] **Step 3: Crear `satoshi_tool/web/routes_hunter.py`**

```python
"""POST /api/hunter/start — Seed Hunter como job."""

import concurrent.futures
import time

from fastapi import APIRouter

from satoshi_tool.config import _HTTP_POOL
from satoshi_tool.blockstream import _summary_single_throttled
from satoshi_tool.derivation import (
    derivar_primera_direccion_por_purpose, infer_purpose_from_address,
)
from satoshi_tool.mask import _iter_mnemonics_from_mask
from satoshi_tool.web.jobs import JobEvent, job_manager
from satoshi_tool.web.models import HunterStartRequest, JobStartResponse

router = APIRouter()
BATCH_SIZE = 16


@router.post("/api/hunter/start", response_model=JobStartResponse)
def hunter_start(req: HunterStartRequest):
    target = req.target.strip()
    purpose = infer_purpose_from_address(target) if target else req.purpose
    if purpose not in (44, 49, 84, 86):
        purpose = req.purpose

    def runner(emit, is_cancelled):
        tested = hits = empty = errors = 0
        last_kpi = 0.0
        pending: list = []

        def maybe_emit_kpi(force=False):
            nonlocal last_kpi
            now = time.time()
            if force or now - last_kpi > 0.2:
                emit(JobEvent(type="kpi", payload={
                    "tested": tested, "hits": hits, "empty": empty, "errors": errors,
                }))
                last_kpi = now

        def check_batch(items):
            nonlocal hits, empty, errors
            futures = {
                _HTTP_POOL.submit(_summary_single_throttled, addr, 2, 10): (mn, path, addr)
                for mn, path, addr in items
            }
            results: dict = {}
            for fut in concurrent.futures.as_completed(futures):
                mn, path, addr = futures[fut]
                try:
                    act = fut.result()
                except Exception as e:
                    errors += 1
                    emit(JobEvent(type="addr", payload={
                        "address": addr, "status": "error", "error": str(e),
                    }))
                    continue
                if act.get("total", 0) > 0 or act.get("ever_received"):
                    hits += 1
                    emit(JobEvent(type="addr", payload={
                        "address": addr, "status": "used",
                        "total_sats": act.get("total", 0),
                    }))
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": mn, "path": path, "address": addr, "act": act,
                    }))
                    results[addr] = (mn, path, act)
                else:
                    empty += 1
            # Devuelve el primer hit por orden original
            for mn, path, addr in items:
                if addr in results:
                    return mn, path, addr, results[addr][2]
            return None

        try:
            for mnemonic in _iter_mnemonics_from_mask(req.mask):
                if is_cancelled():
                    emit(JobEvent(type="cancelled", payload={}))
                    break
                tested += 1
                maybe_emit_kpi()

                try:
                    derived = derivar_primera_direccion_por_purpose(
                        seed_mode="mnemonic", seed_value=mnemonic, passphrase=req.passphrase,
                        purpose=purpose, account=0, change=0, index=0,
                    )
                except Exception:
                    errors += 1
                    continue

                addr = derived["address"]

                if target:
                    if addr == target:
                        emit(JobEvent(type="hit", payload={
                            "mnemonic": mnemonic, "path": derived["path"], "address": addr,
                            "match": "target",
                        }))
                        break
                    continue

                pending.append((mnemonic, derived["path"], addr))
                if len(pending) >= BATCH_SIZE:
                    hit = check_batch(pending)
                    pending.clear()
                    if hit:
                        break

            if not target and pending and not is_cancelled():
                check_batch(pending)
        finally:
            maybe_emit_kpi(force=True)
            emit(JobEvent(type="done", payload={
                "totals": {"tested": tested, "hits": hits, "empty": empty, "errors": errors},
            }))

    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
```

- [ ] **Step 4: Registrar router**

En `app.py`:
```python
from satoshi_tool.web.routes_hunter import router as hunter_router
app.include_router(hunter_router)
```

- [ ] **Step 5: Test debe pasar**

```bash
pytest tests/test_api.py::test_hunter_start_creates_job -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add satoshi_tool/web/routes_hunter.py satoshi_tool/web/models.py satoshi_tool/web/app.py tests/test_api.py
git commit -m "feat(api): POST /api/hunter/start con paralelismo de candidatos"
```

---

## Task 15: Endpoints `/api/passphrase/start` y `/api/auto/start`

**Files:**
- Create: `satoshi_tool/web/routes_passphrase.py`
- Create: `satoshi_tool/web/routes_auto.py`
- Modify: `satoshi_tool/web/models.py`
- Modify: `satoshi_tool/web/app.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test failing para passphrase**

```python
def test_passphrase_start_creates_job(client, monkeypatch):
    def fake_summary(addr, *_args, **_kwargs):
        return {"total": 0, "ever_received": False, "ever_spent": False,
                "confirmed": 0, "unconfirmed": 0}
    monkeypatch.setattr("satoshi_tool.web.routes_passphrase._activity_single_with_retry", fake_summary)

    r = client.post("/api/passphrase/start", json={
        "seed": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "purpose": 84,
        "passphrases": ["one", "two", "three"],
    })
    assert r.status_code == 200
    assert "job_id" in r.json()


def test_auto_start_creates_job(client, monkeypatch):
    """Mockeamos _activity_batch para que el runner no toque red, y cancelamos rápido."""
    def fake_batch(addresses, timeout=15):
        return [
            {"address": a, "total": 0, "ever_received": False, "ever_spent": False,
             "has_unspent": False, "utxos": [], "status": "ok", "error_msg": None,
             "confirmed": 0, "unconfirmed": 0}
            for a in addresses
        ]
    monkeypatch.setattr("satoshi_tool.web.routes_auto._activity_batch", fake_batch)

    r = client.post("/api/auto/start", json={})
    assert r.status_code == 200
    body = r.json()
    assert "job_id" in body

    from satoshi_tool.web.jobs import job_manager
    job_manager.cancel(body["job_id"])
```

- [ ] **Step 2: Añadir schemas**

```python
class PassphraseStartRequest(BaseModel):
    seed: str
    target: str = ""
    purpose: Literal[44, 49, 84, 86] = 84
    passphrases: list[str]


class AutoStartRequest(BaseModel):
    pass
```

- [ ] **Step 3: Crear `routes_passphrase.py`**

```python
"""POST /api/passphrase/start — Passphrase Hunter como job."""

from fastapi import APIRouter, HTTPException
from mnemonic import Mnemonic

from satoshi_tool.blockstream import _activity_single_with_retry
from satoshi_tool.derivation import (
    derivar_primera_direccion_por_purpose, infer_purpose_from_address,
)
from satoshi_tool.web.jobs import JobEvent, job_manager
from satoshi_tool.web.models import JobStartResponse, PassphraseStartRequest

router = APIRouter()


def _detect_seed_mode(seed: str) -> str:
    s = seed.strip()
    if s.startswith("xprv"):
        return "xprv"
    if (len(s) in (51, 52)) and s[0] in ("5", "K", "L"):
        return "wif"
    return "mnemonic"


@router.post("/api/passphrase/start", response_model=JobStartResponse)
def passphrase_start(req: PassphraseStartRequest):
    seed = req.seed.strip()
    seed_mode = _detect_seed_mode(seed)
    if seed_mode == "mnemonic":
        normalized = " ".join(seed.lower().split())
        if not Mnemonic("english").check(normalized):
            raise HTTPException(status_code=400, detail="Mnemónica inválida.")
        seed_value = normalized
    else:
        seed_value = seed

    target = req.target.strip()
    purpose = infer_purpose_from_address(target) if target else req.purpose
    if purpose not in (44, 49, 84, 86):
        purpose = req.purpose

    def runner(emit, is_cancelled):
        tested = hits = errors = 0
        for pp in req.passphrases:
            if is_cancelled():
                emit(JobEvent(type="cancelled", payload={}))
                break
            tested += 1
            try:
                derived = derivar_primera_direccion_por_purpose(
                    seed_mode=seed_mode, seed_value=seed_value, passphrase=pp,
                    purpose=purpose, account=0, change=0, index=0,
                )
            except Exception as e:
                errors += 1
                continue

            addr = derived["address"]
            if target:
                if addr == target:
                    try:
                        act = _activity_single_with_retry(addr, tries=2, base_timeout=10)
                    except Exception:
                        act = {"total": 0, "ever_received": False, "ever_spent": False, "utxo_count": 0}
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": seed_value if seed_mode == "mnemonic" else None,
                        "passphrase": pp, "path": derived["path"],
                        "address": addr, "act": act, "match": "target",
                    }))
                    hits += 1
                    break
            else:
                try:
                    act = _activity_single_with_retry(addr, tries=2, base_timeout=10)
                except Exception:
                    errors += 1
                    continue
                if act.get("total", 0) > 0 or act.get("ever_received"):
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": seed_value if seed_mode == "mnemonic" else None,
                        "passphrase": pp, "path": derived["path"],
                        "address": addr, "act": act,
                    }))
                    hits += 1
                    break

            emit(JobEvent(type="kpi", payload={
                "tested": tested, "hits": hits, "errors": errors,
            }))

        emit(JobEvent(type="done", payload={
            "totals": {"tested": tested, "hits": hits, "errors": errors},
        }))

    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
```

- [ ] **Step 4: Crear `routes_auto.py`**

```python
"""POST /api/auto/start — Modo Auto (genera seeds aleatorias y consulta)."""

from fastapi import APIRouter

from satoshi_tool.blockstream import _activity_batch
from satoshi_tool.derivation import (
    crear_semilla, derivar_direcciones_batch_mnemonic,
)
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
            except Exception as e:
                errors += 1
                continue

            addresses = [it["address"] for it in batch["addresses"]]
            try:
                activity = _activity_batch(addresses, timeout=15)
            except Exception as e:
                errors += 1
                continue

            for it, a in zip(batch["addresses"], activity):
                addresses_checked += 1
                if a.get("total", 0) > 0 or a.get("ever_received"):
                    hits += 1
                    emit(JobEvent(type="hit", payload={
                        "mnemonic": mnemonic, "path": it["path"],
                        "address": it["address"], "act": a,
                    }))
                    is_cancelled()  # marcar para cortar
                    break

            emit(JobEvent(type="kpi", payload={
                "seeds": seeds, "addresses_checked": addresses_checked,
                "hits": hits, "errors": errors,
            }))

        emit(JobEvent(type="done", payload={
            "totals": {"seeds": seeds, "addresses": addresses_checked, "hits": hits},
        }))

    job_id = job_manager.create(runner)
    return JobStartResponse(job_id=job_id)
```

- [ ] **Step 5: Registrar routers en `app.py`**

```python
from satoshi_tool.web.routes_passphrase import router as passphrase_router
from satoshi_tool.web.routes_auto import router as auto_router
# ...
app.include_router(passphrase_router)
app.include_router(auto_router)
```

- [ ] **Step 6: Tests deben pasar**

```bash
pytest tests/test_api.py -v
```
Expected: 13 PASSED.

- [ ] **Step 7: Commit**

```bash
git add satoshi_tool/web/routes_passphrase.py satoshi_tool/web/routes_auto.py satoshi_tool/web/models.py satoshi_tool/web/app.py tests/test_api.py
git commit -m "feat(api): POST /api/passphrase/start y /api/auto/start"
```

---

## Task 16: SSE — `/api/jobs/{id}/stream` y `/api/jobs/{id}/cancel`

**Files:**
- Create: `satoshi_tool/web/routes_jobs.py`
- Modify: `satoshi_tool/web/app.py`
- Modify: `tests/test_api.py`

- [ ] **Step 1: Test failing — consume el SSE de un job sintético**

```python
def test_sse_stream_emits_events(client):
    """Crea un job manualmente con runner sintético, consume el stream."""
    from satoshi_tool.web.jobs import JobEvent, job_manager

    def runner(emit, is_cancelled):
        emit(JobEvent(type="kpi", payload={"tested": 1}))
        emit(JobEvent(type="done", payload={"summary": "ok"}))

    job_id = job_manager.create(runner)

    with client.stream("GET", f"/api/jobs/{job_id}/stream") as r:
        assert r.status_code == 200
        events = []
        for raw in r.iter_lines():
            if raw.startswith("data:"):
                import json
                events.append(json.loads(raw[len("data:"):].strip()))
            if events and events[-1].get("type") == "done":
                break
        types = [e["type"] for e in events]
        assert "kpi" in types
        assert types[-1] == "done"


def test_cancel_endpoint(client):
    import time
    from satoshi_tool.web.jobs import JobEvent, job_manager

    def runner(emit, is_cancelled):
        for _ in range(100):
            if is_cancelled():
                emit(JobEvent(type="cancelled", payload={}))
                emit(JobEvent(type="done", payload={"reason": "cancelled"}))
                return
            time.sleep(0.05)

    job_id = job_manager.create(runner)
    time.sleep(0.05)
    r = client.post(f"/api/jobs/{job_id}/cancel")
    assert r.status_code == 200
    assert r.json()["cancelled"] is True
```

- [ ] **Step 2: Crear `satoshi_tool/web/routes_jobs.py`**

```python
"""GET /api/jobs/{id}/stream (SSE) y POST /api/jobs/{id}/cancel."""

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from satoshi_tool.web.jobs import job_manager

router = APIRouter()


@router.get("/api/jobs/{job_id}/stream")
def stream(job_id: str):
    def event_source():
        for ev in job_manager.iter_events(job_id, timeout=60.0):
            yield f"data: {json.dumps(ev.as_dict(), ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/api/jobs/{job_id}/cancel")
def cancel(job_id: str):
    ok = job_manager.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="job no encontrado")
    return {"cancelled": True, "job_id": job_id}
```

- [ ] **Step 3: Registrar en `app.py`**

```python
from satoshi_tool.web.routes_jobs import router as jobs_router
app.include_router(jobs_router)
```

- [ ] **Step 4: Tests deben pasar**

```bash
pytest tests/test_api.py -v
```
Expected: 15 PASSED.

- [ ] **Step 5: Commit**

```bash
git add satoshi_tool/web/routes_jobs.py satoshi_tool/web/app.py tests/test_api.py
git commit -m "feat(api): SSE en /api/jobs/{id}/stream y cancelación en /api/jobs/{id}/cancel"
```

---

## Task 17: Verificación end-to-end con uvicorn

**Files:**
- Modify: ninguno (solo verificación manual)

- [ ] **Step 1: Arrancar el servidor en background**

```bash
python3 -m uvicorn satoshi_tool.web.app:app --host 127.0.0.1 --port 8765 &
sleep 1
```

- [ ] **Step 2: Probar /api/health**

```bash
curl -s http://127.0.0.1:8765/api/health
```
Expected: `{"status":"ok","version":"0.4.0"}`.

- [ ] **Step 3: Probar /api/generator**

```bash
curl -s -X POST http://127.0.0.1:8765/api/generator -H "Content-Type: application/json" -d '{"words":12}'
```
Expected: JSON con mnemónica de 12 palabras.

- [ ] **Step 4: Probar /api/manual/quick (RED REAL — cuenta como verificación, no test)**

```bash
curl -s -X POST http://127.0.0.1:8765/api/manual/quick \
  -H "Content-Type: application/json" \
  -d '{"seed":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}'
```
Expected: las 4 derivaciones con direcciones públicas conocidas, todas con `ever_received=true`.

- [ ] **Step 5: Probar SSE — Hunter con máscara que rinde la mnemónica de test**

```bash
JOB_ID=$(curl -s -X POST http://127.0.0.1:8765/api/hunter/start \
  -H "Content-Type: application/json" \
  -d '{"mask":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?","purpose":84}' | python3 -c "import sys, json; print(json.load(sys.stdin)['job_id'])")
echo "Job: $JOB_ID"
curl -N http://127.0.0.1:8765/api/jobs/$JOB_ID/stream | head -50
```
Expected: stream de eventos `data: {...}` con tipos `kpi`, `addr`, `hit`, `done`.

- [ ] **Step 6: Parar el servidor**

```bash
pkill -f "uvicorn satoshi_tool.web.app:app"
```

- [ ] **Step 7: Commit (no hay cambios de código, pero documentamos en mensaje de commit vacío con hooks o seguimos)**

No hay nada que commitear si todo funcionó. Si algo falló, los fix-ups van con su propio commit en el momento.

---

## Self-review

Revisión final del plan contra el spec:

1. **§5 Estructura de ficheros (backend)** — cubierto: `config.py` (T1), `blockstream.py` (T3), `derivation.py` (T4), `mask.py` (T5), `persistence.py` (T6), `cli.py` (T7), `web/app.py` (T8), `web/jobs.py` (T12), `web/models.py` (T9+T10+T13+T15), `web/routes_*` (T9, T10, T11, T13, T14, T15, T16). Pendiente para Plan #2: `web/static/`.
2. **§7 API + streaming** — cubierto: todos los endpoints REST (T8–T15), SSE y cancel (T16), JobManager (T12).
3. **§8 Tests** — cubierto: `test_rate_limiter.py` (T2), `test_derivation.py` (T4), `test_mask.py` (T5), `test_persistence.py` (T6), `test_api.py` con TestClient (T8 onwards).
4. **§9 hito 4.1** — cubierto: T1–T7. **§9 hito 4.2** — cubierto: T8–T15. **§9 hito 4.3** — cubierto: T16.
5. **Pre-requisito git local** — cubierto: T0.

Tipos consistentes:
- `JobEvent` con campos `type`, `payload`, `timestamp` — usado igual en T12 (definición), T13 (manual full), T14 (hunter), T15 (passphrase, auto), T16 (SSE).
- `JobStartResponse` con `job_id` — usado igual en T13–T15.
- `RateLimiter.acquire()` (sin retorno) — usado igual en config y blockstream.

No quedan placeholders TBD/TODO. Cada paso tiene comando concreto o código completo.
