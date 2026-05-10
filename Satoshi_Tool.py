#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Satoshi Tool — esqueleto base
Arranca, muestra un menú y deja todo listo para ir añadiendo funciones paso a paso.
"""

# ===============================
# IMPORTS BÁSICOS
# ===============================
import os, sys, json, time, threading, requests
import concurrent.futures
from typing import List, Dict, Any, Optional, Tuple
from mnemonic import Mnemonic
from bip_utils import (Bip39MnemonicValidator, Bip39Languages, Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes, Bip44, Bip49, Bip86, Bip44Coins, Bip49Coins, Bip86Coins)

# ===============================
# BACKEND
# ===============================

_BACKEND = None  # "NODE" o "BLOCKSTREAM"

# (Opcional) Comprobación amable de dependencias
def _check_optional_deps():
    missing = []
    try:
        import requests  # noqa: F401
    except Exception:
        missing.append("requests")

    try:
        from mnemonic import Mnemonic  # noqa: F401
    except Exception:
        missing.append("mnemonic")

    try:
        from bip_utils import Bip84  # noqa: F401
    except Exception:
        missing.append("bip-utils")

    if missing:
        print("⚠️  Aviso: faltan dependencias que usaremos después:", ", ".join(missing))
        print("    Instálalas con:")
        print("    python3 -m pip install " + " ".join(missing))
        print()
# ===============================

# ===============================
# UTILIDADES DE I/O
# ===============================

# === Paths de salida para guardar resultados ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PASSPHRASE_HITS_FILEPATH = os.path.join(BASE_DIR, "Passphrases_Cazadas.txt")
SEED_HITS_FILEPATH       = os.path.join(BASE_DIR, "Semillas_Cazadas.txt")

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

def ask_menu_option(prompt: str, valid: set[str]) -> str:
    while True:
        choice = input(prompt).strip()
        # Normalizamos a mayúsculas
        if choice.upper() in {v.upper() for v in valid}:
            return choice.upper()
        print("Opción no válida. Intenta de nuevo.\n")

def normalize_mnemonic(s: str) -> str:
    """Normaliza espacios y minúsculas para frases BIP39."""
    return " ".join(s.strip().lower().split())

# ===============================
# BACKEND SELECTOR
# ===============================
def select_backend() -> str:
    print_header("BTC Checker — Selección de backend")
    print("[1] Nodo personal (Electrum server)")
    print("[2] Blockstream API (por defecto)")
    choice = ask_menu_option("\nElige [1/2]: ", {"1", "2"})
    if choice == "1":
        return "NODE"
    return "BLOCKSTREAM"
# ===============================

# ===============================
# BANNER
# ===============================
def print_banner():
    banner = r"""
┏━┓┏━┓╺┳╸┏━┓┏━┓╻ ╻╻╻┏━┓   ╺┳╸┏━┓┏━┓╻  
┗━┓┣━┫ ┃ ┃ ┃┗━┓┣━┫┃ ┗━┓    ┃ ┃ ┃┃ ┃┃  
┗━┛╹ ╹ ╹ ┗━┛┗━┛╹ ╹╹ ┗━┛    ╹ ┗━┛┗━┛┗━╸

    🚀 Satoshi's Tool
    💻 Created by BorisGT
    🔗 github.com/Borisgt-10
    """
    print(banner)
# ===============================

# ===============================
# HELPER: actividad en batch (hoy: Blockstream; pendiente: nodo personal)
# ===============================
def _activity_batch(addresses, timeout=15):
    return address_activity_blockstream_batch(addresses, timeout=timeout)
# ===============================

# ===============================
# HELPER: derivar primera dirección para 44/49/84/86
# ===============================
def derive_first_for_all_purposes(seed_mode: str, seed_value: str, passphrase: str = "") -> List[Dict[str, Any]]:
    """
    Intenta derivar m/.../0/0 para purposes 44/49/84/86
    Devuelve lista de dicts: {"purpose", "ok", "data" | "error"}
    """
    results: List[Dict[str, Any]] = []
    for purpose in (44, 49, 84, 86):
        try:
            d = derivar_primera_direccion_por_purpose(
                seed_mode=seed_mode,
                seed_value=seed_value,
                passphrase=passphrase,
                purpose=purpose,
                account=0, change=0, index=0,
            )
            results.append({"purpose": purpose, "ok": True, "data": d})
        except Exception as e:
            results.append({"purpose": purpose, "ok": False, "error": str(e)})
    return results
# ===============================

# ============================
# CONSULTAS A BLOCKSTREAM (Mainnet)
# ============================

BLOCKSTREAM_BASE = "https://blockstream.info/api"

def address_activity_blockstream_batch(addresses, timeout: int = 15):
    """
    Para cada dirección (mainnet), devuelve un dict con:
      - address
      - total (sats)
      - ever_received (bool)
      - ever_spent (bool)
      - has_unspent (bool)
      - utxos: lista [{txid, vout, value, confirmed, block_height, block_time}]
      - status: "ok" | "error"
      - error_msg: detalle si status == "error"
      - confirmed, unconfirmed (sats)
    """
    results = []
    session = requests.Session()
    headers = {"User-Agent": "BTC-Checker/1.0"}

    for addr in addresses:
        try:
            # Resumen
            r = session.get(f"{BLOCKSTREAM_BASE}/address/{addr}", headers=headers, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            chain = data.get("chain_stats", {})
            mem   = data.get("mempool_stats", {})

            confirmed   = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
            unconfirmed = mem.get("funded_txo_sum", 0)   - mem.get("spent_txo_sum", 0)
            total       = confirmed + unconfirmed

            ever_received = (chain.get("funded_txo_count", 0) + mem.get("funded_txo_count", 0)) > 0
            ever_spent    = (chain.get("spent_txo_count", 0)  + mem.get("spent_txo_count", 0))  > 0

            # UTXOs
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


# ===============================

# ===============================
# DERIVAR DIRECCIONES
# ===============================
def derivar_direcciones_batch_mnemonic(
    mnemonic_str: str,
    passphrase: str = "",
    account: int = 0,
    change: int = 0,
    start: int = 0,
    count: int = 3,
) -> Dict[str, Any]:
    """
    Deriva 'count' direcciones consecutivas BIP84 (P2WPKH, mainnet) empezando en 'start'.
    Devuelve:
      {
        'root_xprv', 'account_xpub', 'account_xprv',
        'account_path', 'change_path',
        'addresses': [ { 'path','address','wif','pubkey_hex' }, ... ]
      }
    """
    # Validación BIP39
    validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
    if not validator.IsValid(mnemonic_str):
        raise ValueError("Mnemónica inválida según BIP39.")

    # Semilla y contexto BIP84
    seed_bytes = Bip39SeedGenerator(mnemonic_str).Generate(passphrase)
    ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)

    root_xprv = ctx.PrivateKey().ToExtended()
    acct = ctx.Purpose().Coin().Account(account)
    chain = acct.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)

    coin_type_num = 0  # mainnet
    addrs: List[Dict[str, str]] = []
    for i in range(start, start + count):
        node = chain.AddressIndex(i)
        addrs.append({
            "path": f"m/84'/{coin_type_num}'/{account}'/{change}/{i}",
            "address": node.PublicKey().ToAddress(),            # bc1...
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
# ===============================

# ===============================
# CREAR SEMILLA
# ===============================

def crear_semilla(generate_words: int = 12) -> dict:
    """
    Genera una nueva semilla BIP39 (mnemónica).
    """
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=128 if generate_words == 12 else 256)
    return {
        "mnemonic": mnemonic,
        "words": mnemonic.split()
    }

# ===============================
# MODO AUTOMATICO
# ===============================
def run_automatic_mode() -> None:
    """
    Modo automático:
      - Genera seeds de 12 palabras (sin passphrase)
      - Deriva 3 direcciones (m/84'/0'/0'/0/0..2)
      - Consulta actividad/saldo en Blockstream (o el backend que uses)
      - Muestra SIEMPRE en una sola línea:
          Seeds: <n> | <última_dirección> → <sats> | usada: Sí/No
      - Se detiene al primer “hit”: (total>0) o ever_received=True
    """
    per_seed = 3
    seeds_contador = 0
    print("\nIniciando modo automático (12 palabras, sin passphrase, 3 derivaciones por seed). Ctrl+C para detener.\n")

    last_print_len = 0  # para limpiar “sobras” de líneas más largas

    try:
        while True:
            seeds_contador += 1

            # 1) Generar seed de 12 palabras SIN passphrase
            seed_info = crear_semilla(generate_words=12)
            mnemonic = seed_info["mnemonic"]
            PASSPHRASE = ""

            # 2) Derivar 3 direcciones externas m/84'/0'/0'/0/0..2
            batch = derivar_direcciones_batch_mnemonic(
                mnemonic_str=mnemonic,
                passphrase=PASSPHRASE,
                account=0,
                change=0,
                start=0,
                count=per_seed
            )
            addresses = [it["address"] for it in batch["addresses"]]

            # 3) Consultar actividad (una llamada por dirección)
            activity = address_activity_blockstream_batch(addresses, timeout=15)

            # 4) Recorremos las 3 direcciones; vamos mostrando SOLO la última consultada
            hit_found = False
            for it, a in zip(batch["addresses"], activity):
                usada = a["ever_received"] or a["ever_spent"]
                line = f"Seeds: {seeds_contador} | {it['address']} → {a['total']} sats | usada: {'Sí' if usada else 'No'}"

                # limpieza de caracteres sobrantes si la nueva línea es más corta
                pad = " " * max(0, last_print_len - len(line))
                print(line + pad, end="\r", flush=True)
                last_print_len = len(line)

                # ¿HIT?
                if (a["total"] > 0) or a["ever_received"]:
                    print()  # baja línea para el bloque de mensajes del hit
                    print(f"\n¡HIT ENCONTRADO! (seed #{seeds_contador})")
                    try:
                        _persist_seed_hit(
                            address=it["address"],
                            activity={
                                "total": a.get("total", 0),
                                "ever_received": a.get("ever_received", False),
                                "ever_spent": a.get("ever_spent", False),
                                "utxo_count": len(a.get("utxos", [])),
                            },
                            mnemonic=mnemonic,
                            passphrase=PASSPHRASE,
                            path=it["path"],
                            root_xprv=batch.get("root_xprv"),
                            outfile=SEED_HITS_FILEPATH,
                        )
                        print(f"Semilla y claves guardadas en: {SEED_HITS_FILEPATH}")
                    except Exception as e:
                        print(f"[Error] No se pudo guardar el hit: {e}")
                    hit_found = True
                    break  # salimos del bucle de 3 direcciones

            if hit_found:
                return  # fin del modo automático

            # Si no hubo hit, continúa el while para generar una nueva seed
            # (la última línea queda visible hasta que la próxima iteración la sobreescriba)

    except KeyboardInterrupt:
        # Limpieza de la línea de estado si interrumpes con Ctrl+C
        print("\nInterrumpido por el usuario. Volviendo al menú.")
# ===============================

# ===============================
# HELPERS PARA EL MODO MANUAL Y PASSPHRASE
# ===============================

# ------------------------------------------------------------
# Detección del purpose por prefijo de dirección (mainnet)
# ------------------------------------------------------------
def infer_purpose_from_address(address: str) -> Optional[int]:
    """
    Devuelve 44, 49, 84, 86 según el prefijo de la dirección mainnet, o None si no se puede inferir.
    Nota: '3...' puede ser BIP49 (single-sig compat) o multisig (BIP48) → se asume 49.
    """
    if not address or not isinstance(address, str):
        return None
    a = address.strip().lower()

    if a.startswith("bc1p"):  # Taproot
        return 86
    if a.startswith("bc1q"):  # SegWit nativo P2WPKH
        return 84
    if a.startswith("1"):     # Legacy
        return 44
    if a.startswith("3"):     # P2SH compat (o multisig) → asumimos 49
        return 49
    return None


# ------------------------------------------------------------
# Persistencia específica para Passphrase Hunter
# ------------------------------------------------------------
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
    """
    Guarda un bloque de texto + JSONL con la info sensible cuando hay HIT.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out = outfile or globals().get(
        "PASSPHRASE_HITS_FILEPATH",
        os.path.join(base_dir, "Passphrases_Cazadas.txt"),
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)

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


# ------------------------------------------------------------
# Wrapper de actividad con reintentos y backoff (Blockstream)
# ------------------------------------------------------------
# Sesión HTTP global para reducir latencia / timeouts
_HTTP = requests.Session()
_HTTP.headers.update({"User-Agent": "Satoshi-Tool/1.0"})


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


# Throttling y paralelismo globales para Blockstream.
# Si Boris monta un nodo personal en la fase 4, los reajustamos por backend.
_BLOCKSTREAM_LIMITER = RateLimiter(rate_per_sec=8.0, burst=16)
_HTTP_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="btc-http"
)

def address_activity_blockstream_single_mainnet(address: str, timeout: int = 15,
                                                session: requests.Session = None) -> Dict[str, Any]:
    BASE = "https://blockstream.info/api"
    s = session or _HTTP

    r = s.get(f"{BASE}/address/{address}", timeout=timeout)
    r.raise_for_status()
    data = r.json()
    chain = data.get("chain_stats", {})
    mem   = data.get("mempool_stats", {})

    confirmed   = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
    unconfirmed = mem.get("funded_txo_sum", 0)   - mem.get("spent_txo_sum", 0)
    total       = confirmed + unconfirmed

    ever_received = (chain.get("funded_txo_count", 0) + mem.get("funded_txo_count", 0)) > 0
    ever_spent    = (chain.get("spent_txo_count", 0)  + mem.get("spent_txo_count", 0))  > 0

    r2 = s.get(f"{BASE}/address/{address}/utxo", timeout=timeout)
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

def _activity_single_with_retry(address: str, tries: int = 3, base_timeout: int = 10) -> Dict[str, Any]:
    """
    Llama a address_activity_blockstream_single_mainnet(address, timeout=…)
    con reintentos ante ReadTimeout / 429 y backoff exponencial.
    """
    for attempt in range(1, tries + 1):
        try:
            t = base_timeout + (attempt - 1) * 5  # 10s, 15s, 20s...
            return address_activity_blockstream_single_mainnet(address, timeout=t, session=_HTTP)

        except requests.exceptions.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 429:
                wait = 2 ** attempt  # 2s, 4s, 8s...
                print(f"[Rate limit 429] Esperando {wait}s y reintentando…")
                time.sleep(wait)
                continue
            raise  # otros HTTPError: propaga

        except requests.exceptions.ReadTimeout:
            wait = 2 ** attempt
            print(f"[Red] Timeout (t={t}s). Reintento en {wait}s…")
            time.sleep(wait)

        except requests.exceptions.RequestException as e:
            wait = 2 ** attempt
            print(f"[Red] {e}. Reintento en {wait}s…")
            time.sleep(wait)

    raise RuntimeError("No se pudo consultar actividad tras varios intentos.")


# ------------------------------------------------------------
# Resumen ligero (1 GET) — para escaneo HD con gap limit
# ------------------------------------------------------------
def address_summary_only(address: str, timeout: int = 15,
                         session: requests.Session = None) -> Dict[str, Any]:
    """
    Resumen on-chain de una dirección sin pedir UTXOs.
    Una sola llamada HTTP — pensado para escaneos amplios donde la mayoría
    de direcciones serán vacías.
    """
    s = session or _HTTP
    r = s.get(f"{BLOCKSTREAM_BASE}/address/{address}", timeout=timeout)
    r.raise_for_status()
    data = r.json()
    chain = data.get("chain_stats", {})
    mem   = data.get("mempool_stats", {})

    confirmed   = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
    unconfirmed = mem.get("funded_txo_sum", 0)   - mem.get("spent_txo_sum", 0)
    total       = confirmed + unconfirmed

    ever_received = (chain.get("funded_txo_count", 0) + mem.get("funded_txo_count", 0)) > 0
    ever_spent    = (chain.get("spent_txo_count", 0)  + mem.get("spent_txo_count", 0))  > 0

    return {
        "total": total,
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "ever_received": ever_received,
        "ever_spent": ever_spent,
    }


def _summary_single_with_retry(address: str, tries: int = 3,
                               base_timeout: int = 10) -> Dict[str, Any]:
    """Wrapper retry/backoff de address_summary_only ante 429 / timeout / red."""
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


def _summary_single_throttled(address: str, tries: int = 3,
                              base_timeout: int = 10) -> Dict[str, Any]:
    """Pide token al rate limiter global antes de delegar en _summary_single_with_retry."""
    _BLOCKSTREAM_LIMITER.acquire()
    return _summary_single_with_retry(address, tries=tries, base_timeout=base_timeout)


# ------------------------------------------------------------
# Escaneo HD con gap limit (BIP44/49/84/86) — cadenas externa e interna
# ------------------------------------------------------------
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
    """
    Escanea cadenas externa (change=0) e interna (change=1) hasta encontrar
    'gap_limit' direcciones consecutivas sin actividad. Reutiliza un único
    contexto BIP por cadena (no recalcula seed_bytes en cada índice).

    No aplica a WIF (no es HD).

    'on_progress(purpose, change, index, address, kind, **kw)' opcional:
      kind ∈ {"used", "empty", "error"}; kw puede incluir 'act' o 'error'.

    Devuelve:
      {
        "purpose", "account",
        "external": {"scanned", "used":[...], "total_sats", "confirmed", "unconfirmed"},
        "internal": {...},
        "total_sats",
      }
    """
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
        "purpose": purpose,
        "account": account,
        "external": None,
        "internal": None,
    }

    batch_size = 8  # nº direcciones en vuelo por lote (limitado además por _HTTP_POOL)

    for change in (0, 1):
        chain = acct.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
        consec_empty = 0
        i = 0
        used: List[Dict[str, Any]] = []
        total = confirmed = unconfirmed = 0

        while consec_empty < gap_limit and i < max_index:
            end = min(i + batch_size, max_index)
            # Derivar el lote (CPU) y lanzar las consultas en paralelo
            batch: List[Tuple[int, str, str]] = []
            for j in range(i, end):
                node = chain.AddressIndex(j)
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

            # Procesar EN ORDEN ascendente para que gap_limit cuente bien
            last_processed = i - 1
            cut_in_batch = False
            for j, addr, path in batch:
                last_processed = j
                if j in errors:
                    if on_progress:
                        on_progress(purpose, change, j, addr, "error", error=errors[j])
                    # error: no contamos como vacía → el gap no avanza
                    continue

                act = results[j]
                if act["ever_received"] or act["total"] > 0:
                    used.append({
                        "index": j,
                        "path": path,
                        "address": addr,
                        "total": act["total"],
                        "confirmed": act["confirmed"],
                        "unconfirmed": act["unconfirmed"],
                        "ever_received": act["ever_received"],
                        "ever_spent": act["ever_spent"],
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
            "scanned": i,
            "used": used,
            "total_sats": total,
            "confirmed": confirmed,
            "unconfirmed": unconfirmed,
        }

    summary["total_sats"] = (summary["external"]["total_sats"]
                             + summary["internal"]["total_sats"])
    return summary


# ------------------------------------------------------------
# Derivar primera dirección m/purpose'/0'/0'/0/0 desde
#   - mnemónica (+ passphrase opcional)
#   - xprv
#   - WIF (no HD; devuelve una "plana")
# ------------------------------------------------------------
def derivar_primera_direccion_por_purpose(
    *,
    seed_mode: str,            # "mnemonic" | "xprv" | "wif"
    seed_value: str,           # mnemónica | xprv | wif
    passphrase: str = "",      # solo aplica a mnemónica
    purpose: int = 84,         # 44 (legacy), 49 (compat), 84 (segwit nativo), 86 (taproot)
    account: int = 0,
    change: int = 0,
    index: int = 0,
) -> Dict[str, Any]:
    """
    Devuelve:
      {
        "path", "address", "wif", "pubkey_hex",
        "account_xpub", "account_xprv", "root_xprv"
      }
    """
    if seed_mode not in ("mnemonic", "xprv", "wif"):
        raise ValueError("seed_mode debe ser 'mnemonic', 'xprv' o 'wif'.")
    if purpose not in (44, 49, 84, 86):
        raise ValueError("purpose debe ser 44, 49, 84 o 86.")
    if account < 0 or change not in (0, 1) or index < 0:
        raise ValueError("Parámetros fuera de rango: account>=0, change∈{0,1}, index>=0.")

    # WIF → dirección "plana" (no HD)
    if seed_mode == "wif":
        try:
            from bitcoinlib.keys import Key
        except Exception as e:
            raise ImportError(
                "Para WIF necesitas 'bitcoinlib'. Instala:  python3 -m pip install bitcoinlib"
            ) from e
        k = Key(import_key=seed_value, network="bitcoin")
        addr_legacy = k.address()
        try:
            addr_segwit = k.address(witness_type="segwit")
        except Exception:
            addr_segwit = None
        # Escoge según purpose (legacy 44 → '1...'; otros → intenta segwit)
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

    # Mapas BIP por purpose (mainnet)
    cls_by_purpose = {44: Bip44, 49: Bip49, 84: Bip84, 86: Bip86}
    coins_by_purpose = {
        44: Bip44Coins.BITCOIN,
        49: Bip49Coins.BITCOIN,
        84: Bip84Coins.BITCOIN,
        86: Bip86Coins.BITCOIN,
    }
    bip_cls = cls_by_purpose[purpose]
    coin = coins_by_purpose[purpose]

    # Contexto desde mnemónica o xprv
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

    # Intentar posicionarnos en nivel de cuenta; si ya está más profundo, seguirá funcionando
    try:
        acct = ctx.Purpose().Coin().Account(account)
    except Exception:
        acct = ctx
    # Elegir cadena
    try:
        chain = acct.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
    except Exception:
        chain = acct
    # Índice
    node = chain.AddressIndex(index)

    coin_type_num = 0  # mainnet
    path = f"m/{purpose}'/{coin_type_num}'/{account}'/{change}/{index}"
    address = node.PublicKey().ToAddress()
    wif = node.PrivateKey().ToWif()
    pubkey_hex = node.PublicKey().RawCompressed().ToHex()

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
        "address": address,
        "wif": wif,
        "pubkey_hex": pubkey_hex,
        "account_xpub": account_xpub,
        "account_xprv": account_xprv,
        "root_xprv": root_xprv,
    }

# ===============================

# ===============================
# MODO MANUAL
# ===============================
PURPOSE_LABELS = {
    44: "BIP44  (Legacy P2PKH, 1...)",
    49: "BIP49  (P2SH-P2WPKH, 3...)",
    84: "BIP84  (P2WPKH bech32, bc1q...)",
    86: "BIP86  (Taproot P2TR, bc1p...)",
}


def _manual_quick_scan(seed_mode: str, seed_value: str, passphrase: str) -> None:
    """Comportamiento clásico: solo m/.../0/0 por cada purpose."""
    derivs = derive_first_for_all_purposes(seed_mode, seed_value, passphrase)

    addr_map: Dict[int, str] = {}
    for item in derivs:
        if item["ok"]:
            addr_map[item["purpose"]] = item["data"]["address"]

    activities: Dict[str, Dict[str, Any]] = {}
    if addr_map:
        addrs = list(addr_map.values())
        acts = _activity_batch(addrs, timeout=15)
        for a, act in zip(addrs, acts):
            activities[a] = act

    print("\n=== Resultados (escaneo rápido, m/.../0/0) ===")
    for item in derivs:
        p = item["purpose"]
        print(f"\n[{p}] {PURPOSE_LABELS.get(p, '')}")
        if not item["ok"]:
            print(f"  ✗ No disponible: {item['error']}")
            continue
        addr = item["data"]["address"]
        act = activities.get(addr)
        print(f"  Dirección: {addr}")
        if act:
            used = "Sí" if act.get("ever_received", False) else "No"
            print(f"  Saldo: {act.get('total', 0)/1e8:.8f} BTC  | Usada: {used}  "
                  f"| UTXOs: {act.get('utxo_count', 0)}")
        else:
            print("  (sin datos de actividad — no se pudo consultar)")


def _manual_full_scan(seed_mode: str, seed_value: str, passphrase: str,
                      gap_limit: int = 20) -> None:
    """Escaneo HD con gap limit en cadenas externa + interna por cada purpose."""
    print(f"\n=== Resultados (escaneo completo, gap limit {gap_limit}) ===")
    print("Mostrando solo direcciones con actividad. Ctrl+C para abortar.\n")

    def _on_progress(p, change, idx, addr, kind, **kw):
        side = "ext" if change == 0 else "int"
        if kind == "used":
            act = kw.get("act", {})
            print(f"  · {side}/{idx:>3}  {addr}  → {act.get('total', 0)/1e8:.8f} BTC")
        elif kind == "error":
            print(f"  · {side}/{idx:>3}  {addr}  [error: {kw.get('error', '?')}]")
        # 'empty' silencioso para no inundar la pantalla

    grand_total = 0
    grand_used = 0
    for purpose in (44, 49, 84, 86):
        print(f"\n[{purpose}] {PURPOSE_LABELS.get(purpose, '')}")
        try:
            res = scan_purpose_with_gap_limit(
                seed_mode=seed_mode,
                seed_value=seed_value,
                passphrase=passphrase,
                purpose=purpose,
                account=0,
                gap_limit=gap_limit,
                on_progress=_on_progress,
            )
        except Exception as e:
            print(f"  ✗ Error: {e}")
            continue

        ext = res["external"]
        intl = res["internal"]
        n_used = len(ext["used"]) + len(intl["used"])
        grand_total += res["total_sats"]
        grand_used += n_used

        if n_used == 0:
            print(f"  Vacío  (escaneadas: ext {ext['scanned']}, int {intl['scanned']})")
        else:
            print(f"  Resumen: {res['total_sats']/1e8:.8f} BTC  |  "
                  f"{n_used} direcciones usadas  |  "
                  f"escaneadas: ext {ext['scanned']}, int {intl['scanned']}")

    print(f"\nTotal cuenta 0 (todos los purposes): {grand_total/1e8:.8f} BTC  "
          f"|  {grand_used} direcciones con actividad")


def run_manual_mode() -> None:
    """
    Modo manual:
      - Acepta mnemónica (12/24), xprv o WIF.
      - Pregunta tipo de escaneo: rápido (m/.../0/0) o completo (gap limit 20).
      - Para cada purpose 44/49/84/86, consulta saldos y muestra resumen.
    """
    print("\n=== Modo MANUAL ===")
    try:
        seed_input = input("Introduce tu mnemónica (12/24), xprv o WIF: ").strip()

        # Detectar tipo de entrada
        if seed_input.startswith("xprv"):
            seed_mode = "xprv"
            seed_value = seed_input
            passphrase = ""
        elif (len(seed_input) in (51, 52)) and (seed_input[0] in ("5", "K", "L")):
            seed_mode = "wif"
            seed_value = seed_input
            passphrase = ""
        else:
            m = normalize_mnemonic(seed_input)
            mnemo = Mnemonic("english")
            if not mnemo.check(m):
                print("Mnemónica inválida (checksum).")
                return
            validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
            if not validator.IsValid(m):
                print("Mnemónica inválida según bip-utils.")
                return
            seed_mode = "mnemonic"
            seed_value = m
            passphrase = input("Passphrase BIP39 (opcional, Enter = vacío): ").strip()

        # Tipo de escaneo
        if seed_mode == "wif":
            print("\nWIF detectado: se hace escaneo rápido (no es una clave HD).")
            _manual_quick_scan(seed_mode, seed_value, passphrase)
        else:
            print("\nTipo de escaneo:")
            print("  [R] Rápido    → solo m/.../0/0 (1 dirección por purpose)")
            print("  [C] Completo  → gap limit 20 en cadena externa + interna")
            ans = input("Elige [R/C] (Enter=R): ").strip().lower()
            if ans == "c":
                _manual_full_scan(seed_mode, seed_value, passphrase, gap_limit=20)
            else:
                _manual_quick_scan(seed_mode, seed_value, passphrase)

        print("\nFin del modo manual.\n")

    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
    except Exception as e:
        print(f"Error en modo manual: {e}")
# ===============================

# ===============================
# MENÚ PRINCIPAL
# ===============================
def prompt_mode() -> str:
    print_header("Satoshi's Tool — Modo de Ejecución")
    print("[1] Automático")
    print("[2] Manual")
    print("[3] Passphrase Hunter")
    print("[4] Seed Hunter")
    print("[5] Generador de Semillas")
    print("[Q] Salir")
    return ask_menu_option("\nElige una opción [1/2/3/4/5/Q]: ", {"1", "2", "3", "4", "5", "Q"})
# ===============================

# ===============================
# MODO PASSPHRASE HUNTER
# ===============================
def run_passphrase_mode() -> None:
    """
    Flujo:
      1) (Opcional) Dirección objetivo → inferir purpose por prefijo.
      2) Seed base: mnemónica (12/24), xprv o WIF (passphrase solo aplica a mnemónica).
      3) Si no hay purpose inferido, pedir 44/49/84/86.
      4) Bucle: pedir passphrase candidata → derivar m/.../0/0 → comparar con objetivo o consultar actividad.
      5) Si hay HIT (saldo>0 o ever_received), guardar en Passphrases_Cazadas.txt.
    """
    print("\n=== Passphrase Hunter ===")

    # 1) Dirección objetivo (opcional)
    have_addr = input("¿Tienes una dirección objetivo para comparar? [S/N]: ").strip().upper()
    target_address = ""
    inferred_purpose: Optional[int] = None
    if have_addr == "S":
        target_address = input("Pega la dirección objetivo (bc1... / 3... / 1...): ").strip()
        inferred_purpose = infer_purpose_from_address(target_address)
        if inferred_purpose is not None:
            if target_address.startswith("3"):
                print("\nLa dirección empieza por '3'. Puede ser BIP49 (single-sig compat) o multisig (BIP48).")
                ans = input("¿Probamos como BIP49 (compat P2SH-P2WPKH)? [S/n]: ").strip().lower()
                if ans == "n":
                    try:
                        manual = int(input("Elige purpose manual (44/49/84/86): ").strip())
                        if manual in (44, 49, 84, 86):
                            inferred_purpose = manual
                        else:
                            print("Opción inválida, se usará 49 por defecto.")
                            inferred_purpose = 49
                    except Exception:
                        print("Entrada no válida, se usará 49 por defecto.")
                        inferred_purpose = 49
            else:
                print(f"\nPurpose inferido por el prefijo de la dirección: {inferred_purpose}'")
        else:
            print("\nNo se pudo inferir el purpose por el formato de la dirección.")

    # 2) Seed base (sin pedir passphrase aún)
    seed_input = input("\nIntroduce tu seed (mnemónica 12/24, xprv o WIF): ").strip()
    if seed_input.startswith("xprv"):
        seed_mode = "xprv"
        seed_value = seed_input
    elif (len(seed_input) in (51, 52)) and (seed_input[0] in ("5", "K", "L")):
        seed_mode = "wif"
        seed_value = seed_input
    else:
        m = normalize_mnemonic(seed_input)
        mnemo = Mnemonic("english")
        if not mnemo.check(m):
            print("Mnemónica inválida (checksum).")
            return
        validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
        if not validator.IsValid(m):
            print("Mnemónica inválida según bip-utils.")
            return
        seed_mode = "mnemonic"
        seed_value = m

    # 3) Purpose (si no quedó claro)
    if inferred_purpose is None:
        print("\nSelecciona tipo de ruta (purpose):")
        print("  [44] Legacy P2PKH        (1...)    → BIP44")
        print("  [49] Compat P2SH-P2WPKH  (3...)    → BIP49")
        print("  [84] Native P2WPKH       (bc1q...) → BIP84")
        print("  [86] Taproot P2TR        (bc1p...) → BIP86")
        try:
            purpose = int(input("Elige 44 / 49 / 84 / 86 (Enter=84): ").strip() or "84")
            if purpose not in (44, 49, 84, 86):
                raise ValueError
        except Exception:
            print("Opción inválida.")
            return
    else:
        purpose = inferred_purpose

    account, change, index = 0, 0, 0
    outfile = globals().get("PASSPHRASE_HITS_FILEPATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "Passphrases_Cazadas.txt"))

    print("\nEntrando en bucle infinito de prueba de passphrases. Ctrl+C para salir.\n")
    tested = 0
    try:
        while True:
            candidate = input("Passphrase a probar (Enter=vacía): ").strip()
            passphrase = candidate  # puede ser ""

            if seed_mode in ("xprv", "wif") and passphrase:
                print("Aviso: la passphrase solo afecta a mnemónicas BIP39; se ignorará para xprv/WIF.")

            # Derivar m/.../0/0
            try:
                derived = derivar_primera_direccion_por_purpose(
                    seed_mode=seed_mode,
                    seed_value=seed_value,
                    passphrase=passphrase,
                    purpose=purpose,
                    account=account,
                    change=change,
                    index=index,
                )
            except Exception as e:
                print(f"Error derivando con esta passphrase: {e}")
                continue

            tested += 1
            addr = derived["address"]

            if target_address:
                # Comparar con la dirección objetivo
                if addr == target_address:
                    print(f"\n✅ ¡Passphrase encontrada tras {tested} intentos!: «{passphrase}»")
                    try:
                        act = _activity_single_with_retry(addr, tries=3, base_timeout=10)
                    except Exception as e:
                        print(f"[Aviso] No se pudo consultar saldo ahora mismo: {e}")
                        act = {"total": 0, "ever_received": False, "ever_spent": False, "utxo_count": 0}
                    print(f"Dirección: {addr}")
                    print(f"Saldo total: {act.get('total', 0)/1e8:.8f} BTC  | "
                          f"Recibida: {'Sí' if act.get('ever_received') else 'No'}  | "
                          f"Gastada: {'Sí' if act.get('ever_spent') else 'No'}  | "
                          f"UTXOs: {act.get('utxo_count', 0)}")
                    _persist_passphrase_hit(
                        address=addr,
                        activity=act,
                        seed_mode=seed_mode,
                        seed_value=seed_value,
                        passphrase=passphrase,
                        path=derived["path"],
                        outfile=outfile,
                    )
                    print(f"Guardado en: {outfile}")
                else:
                    print("❌ No coincide. Prueba otra passphrase.")
            else:
                # Sin objetivo → buscar actividad on-chain (saldo o histórico)
                try:
                    act = _activity_single_with_retry(addr, tries=3, base_timeout=10)
                except Exception as e:
                    print(f"[Red] No se pudo consultar actividad: {e}")
                    continue

                if (act.get("total", 0) > 0) or act.get("ever_received", False):
                    print(f"\n✅ Actividad detectada tras {tested} intentos.")
                    print(f"Dirección: {addr}  | Path: {derived['path']}")
                    print(f"Saldo total: {act['total']/1e8:.8f} BTC  | UTXOs: {act['utxo_count']}")
                    _persist_passphrase_hit(
                        address=addr,
                        activity=act,
                        seed_mode=seed_mode,
                        seed_value=seed_value,
                        passphrase=passphrase,
                        path=derived["path"],
                        outfile=outfile,
                    )
                    print(f"Guardado en: {outfile}")
                else:
                    print("Sin actividad en la primera dirección (m/.../0/0). Prueba otra passphrase.")

    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario. Saliendo del Passphrase Hunter.")
# ===============================

# ===============================
# MODO SEED HUNTER
# ===============================
# Persister del seed_hit
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
    """
    Guarda en 'Semillas_Cazadas.txt' (o 'outfile' si se pasa) un bloque legible y una línea JSONL con:
      - timestamp, address, total_sats, ever_received, ever_spent, utxo_count
      - mnemonic (12/24), passphrase, path usado, root_xprv (si lo tenemos)
    """
    import time, os, json

    if outfile is None:
        outfile = SEED_HITS_FILEPATH  # ya definido arriba en tu config

    os.makedirs(os.path.dirname(os.path.abspath(outfile)), exist_ok=True)

    ts_human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    ts_epoch = int(time.time())

    header = [
        "================= SEED HIT =================",
        f"Fecha:     {ts_human}",
        f"Dirección: {address}",
        f"Saldo:     {activity.get('total', 0)} sats",
        f"Recibida:  {'Sí' if activity.get('ever_received') else 'No'} | Gastada: {'Sí' if activity.get('ever_spent') else 'No'} | UTXOs: {activity.get('utxo_count', 0)}",
        "----- Datos sensibles (⚠ GUARDAR CON EXTREMO CUIDADO) -----",
        f"Mnemonic:       {mnemonic}",
        f"Passphrase:     {passphrase if passphrase else '(vacía)'}",
        f"Derivation:     {path}",
    ]
    if root_xprv:
        header.append(f"root xprv:      {root_xprv}")
    header.append("")  # línea en blanco

    with open(outfile, "a", encoding="utf-8") as f:
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
        os.chmod(outfile, 0o600)
    except Exception:
        pass
# ===============================
# Seed Hunter
# =========================
# Utilidades para Seed Hunter
# =========================

def _parse_mask(mask_str: str):
    """
    Recibe una máscara tipo:
      "abandon abandon ? pre* about ..."
    Devuelve:
      - mask_tokens: lista de tokens (algunos fijos, otros '?', otros prefijos 'pre*')
      - unknown_positions: índices de tokens que son '?'
      - prefix_constraints: dict {pos: prefijo_sin_asterisco}
      - allowed_words: lista de 2048 palabras BIP39 (inglés)
    """
    tokens = mask_str.strip().split()
    unknown_positions = []
    prefix_constraints = {}

    # Usar la lista oficial BIP-39 desde 'python-mnemonic'
    # (ya tienes `from mnemonic import Mnemonic` importado al inicio del archivo)
    all_words = Mnemonic("english").wordlist  # lista de 2048 palabras

    mask_tokens = []
    for idx, tok in enumerate(tokens):
        tok = tok.strip().lower()
        if tok == "?":
            mask_tokens.append("?")
            unknown_positions.append(idx)
        elif tok.endswith("*") and len(tok) > 1:
            # Prefijo: guardar sin el asterisco
            prefix = tok[:-1]
            prefix_constraints[idx] = prefix
            mask_tokens.append(tok)
        else:
            # Palabra fija (validación suave: dejar que el generador/validator filtre)
            mask_tokens.append(tok)

    return mask_tokens, unknown_positions, prefix_constraints, all_words


def _estimate_combinations(mask_tokens, prefix_constraints, allowed_words):
    """
    Estima combinaciones ANTES de checksum, contando:
      - '?'  → todas las 2048 (o las que cumplan prefijo si lo hay)
      - 'pre*' → todas las que empiecen por 'pre'
      - palabra fija → 1
    """
    total = 1
    for idx, tok in enumerate(mask_tokens):
        if tok == "?":
            # ¿Tiene además prefijo para este índice?
            if idx in prefix_constraints:
                pref = prefix_constraints[idx]
                total *= sum(1 for w in allowed_words if w.startswith(pref))
            else:
                total *= len(allowed_words)
        elif tok.endswith("*") and len(tok) > 1:
            pref = prefix_constraints.get(idx, tok[:-1])
            total *= sum(1 for w in allowed_words if w.startswith(pref))
        else:
            # Palabra fija
            total *= 1
    return total
# --- Generador sencillo: crea mnemónicas que pasan checksum a partir de la máscara ---
from typing import List, Dict, Any, Optional, Iterator  # asegúrate de tener estos imports arriba

def _iter_mnemonics_from_mask(mask_str: str) -> Iterator[str]:
    """
    Genera mnemónicas (12/24) que cumplen el checksum BIP-39 basadas en una máscara.
    Soporta:
      - palabra fija ("abandon")
      - '?' (desconocida)
      - 'pre*' (prefijo)
    """
    mnemo = Mnemonic("english")
    all_words = mnemo.wordlist
    tokens = mask_str.strip().lower().split()

    if len(tokens) not in (12, 24):
        raise ValueError("La mnemónica debe tener 12 o 24 palabras.")

    # Para cada posición construimos el “pool” de opciones
    choices_per_pos: List[List[str]] = []
    for tok in tokens:
        if tok == "?":
            choices_per_pos.append(all_words)
        elif tok.endswith("*") and len(tok) > 1:
            pref = tok[:-1]
            pool = [w for w in all_words if w.startswith(pref)]
            choices_per_pos.append(pool)
        else:
            choices_per_pos.append([tok])

    curr = [""] * len(tokens)

    def bt(i: int):
        if i == len(tokens):
            phrase = " ".join(curr)
            if mnemo.check(phrase):  # sólo emitimos si pasa checksum
                yield phrase
            return
        for w in choices_per_pos[i]:
            curr[i] = w
            yield from bt(i + 1)

    yield from bt(0)


def run_seed_hunter_mode() -> None:
    """
    Seed Hunter:
      - El usuario da una máscara de mnemónica (12/24) con tokens fijos, '?', o prefijos 'pre*'.
      - Opcionalmente da dirección objetivo (para confirmar por coincidencia exacta de la 1ª derivación).
      - Opcionalmente passphrase BIP39.
      - Se generan combinaciones → se filtran por checksum BIP39 → se deriva m/…/0/0 con el purpose inferido/seleccionado.
      - Si hay dirección objetivo: parar al encontrar coincidencia exacta.
        Si no hay dirección objetivo: considerar HIT si (saldo>0 o ever_received).
      - Muestra barra de progreso y ETA (con base en la estimación).
    """
    print("\n=== Seed Hunter ===")

    # (1) Dirección objetivo (opcional)
    have_addr = input("¿Tienes una dirección objetivo para comparar? [S/N]: ").strip().lower()
    target_address = ""
    inferred_purpose: Optional[int] = None
    if have_addr == "s":
        target_address = input("Pega la dirección objetivo (bc1... / 3... / 1...): ").strip()
        inferred_purpose = infer_purpose_from_address(target_address)
        if inferred_purpose:
            print(f"Purpose inferido: {inferred_purpose}'")
        else:
            print("No se pudo inferir el purpose por el formato de la dirección; se pedirá más adelante.")

    # (2) Máscara
    print("\nIntroduce la MÁSCARA de mnemónica (12/24 tokens):")
    print(" - palabra fija (ej: abandon)")
    print(" - '?' para desconocida")
    print(" - 'pre*' para prefijo (ej: ab*)")
    mask_str = input("Máscara: ").strip()

    # Passphrase
    passphrase = input("Passphrase BIP39 (opcional, Enter = vacío): ").strip()

    # Preparar máscara
    mask_tokens, unknown_positions, prefix_constraints, allowed_words = _parse_mask(mask_str)

    # Alertas por tamaño del espacio de búsqueda
    n_unknown = len(unknown_positions)
    if n_unknown == 1:
        print("\nℹ️  Tienes 1 incógnita ('?') → ~2.048 combinaciones (rápido).")
    elif n_unknown == 2:
        print("\n⚠️  Tienes 2 incógnitas ('?') → ~4.2 millones de combinaciones (pesado).")
    elif n_unknown >= 3:
        print("\n⚠️  3 o más incógnitas → espacio explosivo. Se recomienda usar prefijos para reducir.")

    # Estimación previa (sin checksum)
    est_total = _estimate_combinations(mask_tokens, prefix_constraints, allowed_words)
    total_est_str = f"{est_total:,}" if est_total and est_total > 0 else "???"
    print(f"\nCombinaciones estimadas (antes de checksum): {total_est_str}\n")

    # (3) Purpose (si no lo pudimos inferir)
    if not inferred_purpose:
        print("Selecciona tipo de ruta (purpose):")
        print("  [44] Legacy P2PKH        (1...)    → BIP44")
        print("  [49] Compat P2SH-P2WPKH  (3...)    → BIP49")
        print("  [84] Native P2WPKH       (bc1q...) → BIP84")
        print("  [86] Taproot P2TR        (bc1p...) → BIP86")
        try:
            purpose = int(input("Elige 44 / 49 / 84 / 86 (Enter=84): ").strip() or "84")
            if purpose not in (44, 49, 84, 86):
                raise ValueError
        except Exception:
            print("Opción inválida.")
            return
    else:
        purpose = inferred_purpose

    account, change, index = 0, 0, 0

    print("\nProbando mnemónicas válidas (checksum OK). Ctrl+C para abortar.\n")

    # --- Progreso (barra + ETA) ---
    BAR_WIDTH = 28           # ancho de la barra
    UPDATE_EVERY = 200       # refrescar cada N válidas
    start_time = time.time() # para ETA
    tested = 0

    def _fmt_hms(sec: float) -> str:
        sec = max(0, int(sec))
        h, rem = divmod(sec, 3600)
        m, s   = divmod(rem, 60)
        return f"{h:d}:{m:02d}:{s:02d}"

    # total para la barra (usamos la estimación; prefiero mostrar algo a no mostrar nada)
    total_for_bar = est_total if (est_total and est_total > 0) else None
    if total_for_bar:
        print(f"[{' ' * BAR_WIDTH}]  0.00%  0/{total_for_bar:,}  ETA --:--:--", end="\r", flush=True)
    else:
        print(f"[{' ' * BAR_WIDTH}]  --.--%  0/???  ETA --:--:--", end="\r", flush=True)

    outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Semillas_Cazadas.txt")

    BATCH_SIZE = 16  # mnemónicas en vuelo a la vez (sin target_address)

    def _emit_progress():
        elapsed = time.time() - start_time
        if total_for_bar:
            pct = min(1.0, tested / total_for_bar)
            filled = int(round(pct * BAR_WIDTH))
            bar = "█" * filled + "░" * (BAR_WIDTH - filled)
            rate = tested / elapsed if elapsed > 0 else 0.0
            remaining = max(0, total_for_bar - tested)
            eta_sec = (remaining / rate) if rate > 0 else 0
            eta_str = _fmt_hms(eta_sec)
            print(f"[{bar}] {pct*100:6.2f}%  {tested:,}/{total_for_bar:,}  ETA {eta_str}",
                  end="\r", flush=True)
        else:
            elapsed_str = _fmt_hms(elapsed)
            filled = BAR_WIDTH // 4
            bar = "█" * filled + "░" * (BAR_WIDTH - filled)
            print(f"[{bar}]   --.--%  {tested:,}/???  Elapsed {elapsed_str}",
                  end="\r", flush=True)

    def _check_batch(items):
        """items: lista de (mnemonic, path, addr). Devuelve el primer hit por orden o None."""
        if not items:
            return None
        futures = {
            _HTTP_POOL.submit(_summary_single_throttled, addr, 2, 10): (mn, path, addr)
            for mn, path, addr in items
        }
        hits: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}
        for fut in concurrent.futures.as_completed(futures):
            mn, path, addr = futures[fut]
            try:
                act = fut.result()
            except Exception:
                continue
            if act.get("total", 0) > 0 or act.get("ever_received"):
                hits[addr] = (mn, path, act)
        for mn, path, addr in items:
            if addr in hits:
                saved_mn, saved_path, act = hits[addr]
                return saved_mn, saved_path, addr, act
        return None

    pending: List[Tuple[str, str, str]] = []
    hit_data: Optional[Tuple[str, str, str, Dict[str, Any]]] = None

    try:
        for mnemonic in _iter_mnemonics_from_mask(mask_str):
            tested += 1
            if (tested % UPDATE_EVERY) == 0 or tested == 1:
                _emit_progress()

            try:
                derived = derivar_primera_direccion_por_purpose(
                    seed_mode="mnemonic",
                    seed_value=mnemonic,
                    passphrase=passphrase,
                    purpose=purpose,
                    account=account,
                    change=change,
                    index=index,
                )
            except Exception:
                continue

            addr = derived["address"]

            if target_address:
                # CPU-only: comparación de strings, sin red salvo en el hit
                if addr == target_address:
                    print("\n")
                    print("✅ ¡ENCONTRADA!")
                    print(f"Mnemonic:  {mnemonic}")
                    print(f"Path:      {derived['path']}")
                    print(f"Address:   {addr}")
                    try:
                        act = _activity_single_with_retry(addr, tries=2, base_timeout=10)
                    except Exception as e:
                        print(f"[Red] No se pudo consultar saldo: {e}")
                        act = {"total": 0, "ever_received": False, "ever_spent": False, "utxo_count": 0}
                    print(f"Saldo total: {act.get('total', 0)/1e8:.8f} BTC  | "
                          f"Recibida: {'Sí' if act.get('ever_received') else 'No'}  "
                          f"| Gastada: {'Sí' if act.get('ever_spent') else 'No'}  "
                          f"| UTXOs: {act.get('utxo_count', 0)}")
                    _persist_seed_hit(
                        address=addr,
                        activity=act,
                        mnemonic=mnemonic,
                        passphrase=passphrase,
                        path=derived["path"],
                        outfile=outfile,
                    )
                    print(f"Guardado en: {outfile}")
                    pause("Pulsa Enter para continuar...")
                    return
                continue

            # Sin target → encolar para consulta en lote
            pending.append((mnemonic, derived["path"], addr))
            if len(pending) >= BATCH_SIZE:
                hit_data = _check_batch(pending)
                pending = []
                if hit_data:
                    break

        # Vaciar el último lote parcial (sin target)
        if not target_address and pending and not hit_data:
            hit_data = _check_batch(pending)

        if hit_data:
            mn, path, addr, act = hit_data
            print("\n")
            print("✅ ¡ENCONTRADA!")
            print(f"Mnemonic:  {mn}")
            print(f"Path:      {path}")
            print(f"Address:   {addr}")
            print(f"Saldo total: {act.get('total', 0)/1e8:.8f} BTC  | "
                  f"Recibida: {'Sí' if act.get('ever_received') else 'No'}  "
                  f"| Gastada: {'Sí' if act.get('ever_spent') else 'No'}")
            _persist_seed_hit(
                address=addr,
                activity=act,
                mnemonic=mn,
                passphrase=passphrase,
                path=path,
                outfile=outfile,
            )
            print(f"Guardado en: {outfile}")
            pause("Pulsa Enter para continuar...")
            return

        print("\n\nNo se encontró ninguna coincidencia/HIT con las combinaciones evaluadas.")
        pause("Pulsa Enter para continuar...")

    except KeyboardInterrupt:
        print("\n\nInterrumpido por el usuario.")
        pause("Pulsa Enter para continuar...")
# ===============================

# ===============================
# MODO GENERADOR DE SEMILLAS
# ===============================
def run_seed_generator_mode() -> None:
    """
    Generador de Semillas:
      - Pregunta 12/24 palabras, genera mnemónica aleatoria sin passphrase.
      - Calcula xprv (raíz del contexto BIP84) y, para cada purpose 44/49/84/86,
        deriva la primera dirección m/.../0/0, consulta saldo/actividad y lo muestra.
      - Muestra también el WIF de la primera dirección BIP84 (m/84'/0'/0'/0/0).
      - NO guarda nada en disco.
    """
    print("\n=== Generador de Semillas ===")
    try:
        n_words = int(input("¿Cuántas palabras? [12/24] (Enter=12): ").strip() or "12")
        if n_words not in (12, 24):
            print("Valor inválido, usaré 12.")
            n_words = 12
    except Exception:
        print("Entrada no válida, usaré 12.")
        n_words = 12

    # 1) Generar mnemónica aleatoria
    seed_info = crear_semilla(generate_words=n_words)
    mnemonic = seed_info["mnemonic"]
    passphrase = ""  # generador: sin passphrase

    print("\n--- SEMILLA GENERADA ---")
    print("Mnemonic:", mnemonic)

    # 2) xprv (raíz del contexto BIP84)
    try:
        # Reutilizamos derivación BIP84 para obtener el root_xprv del contexto
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        ctx84 = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
        root_xprv = ctx84.PrivateKey().ToExtended()   # Nota: raíz del árbol BIP84 (m/84')
    except Exception as e:
        root_xprv = f"(No disponible: {e})"

    print("xprv (BIP84 root):", root_xprv)

    # 3) Para cada purpose derivamos la primera dirección y consultamos actividad
    purposes = [
        (44, "[44] BIP44  (Legacy P2PKH, 1...)"),
        (49, "[49] BIP49  (P2SH-P2WPKH, 3...)"),
        (84, "[84] BIP84  (P2WPKH bech32, bc1q...)"),
        (86, "[86] BIP86  (Taproot P2TR, bc1p...)"),
    ]

    wif_84 = None  # guardaremos el WIF de la 1ª dirección BIP84 para imprimirlo aparte

    print("\n--- PRIMERA DIRECCIÓN POR DERIVACIÓN ---")
    for purpose, label in purposes:
        try:
            d = derivar_primera_direccion_por_purpose(
                seed_mode="mnemonic",
                seed_value=mnemonic,
                passphrase=passphrase,
                purpose=purpose,
                account=0,
                change=0,
                index=0,
            )
            addr = d["address"]

            # Consulta robusta (con reintentos) del saldo/actividad
            try:
                act = _activity_single_with_retry(addr, tries=3, base_timeout=10)
            except Exception as e:
                print(f"{label}\n  {addr}")
                print(f"  (No se pudo consultar actividad ahora mismo: {e})")
                continue

            print(f"{label}\n  {addr}")
            print(f"  Saldo: {act['total']/1e8:.8f} BTC  | "
                  f"Recibida: {'Sí' if act['ever_received'] else 'No'}  | "
                  f"Gastada: {'Sí' if act['ever_spent'] else 'No'}  | "
                  f"UTXOs: {act['utxo_count']}")

            if purpose == 84:
                wif_84 = d.get("wif")

        except Exception as e:
            print(f"{label}\n  (Error derivando): {e}")

    # 4) WIF de la 1ª dirección BIP84
    if wif_84:
        print("\nWIF (84'/0'/0'/0/0):", wif_84)

    print("\nFin del Generador de Semillas.\n")
# ===============================
# ============================================================
# PUNTO DE ENTRADA
# ============================================================
def main() -> None:
    clear_screen()
    print_banner()
    mode = prompt_mode()

    if mode == "Q":
        print("Hasta luego 👋")
        sys.exit(0)

    if mode == "1":
        clear_screen()
        print("Modo AUTOMÁTICO seleccionado.\n")
        run_automatic_mode()
        pause()

    elif mode == "2":
        clear_screen()
        print("Modo MANUAL seleccionado.\n")
        run_manual_mode()
        pause()

    elif mode == "3":
        clear_screen()
        print("Modo PASSPHRASE HUNTER seleccionado.\n")
        run_passphrase_mode()
        pause()

    elif mode == "4":
        clear_screen()
        print("Modo SEED HUNTER seleccionado.\n")
        run_seed_hunter_mode()
        pause()

    elif mode == "5":
        clear_screen()
        print("Modo GENERADOR DE SEMILLAS seleccionado.\n")
        run_seed_generator_mode()
        pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido. ¡Hasta luego!")

