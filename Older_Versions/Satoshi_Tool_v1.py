#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Satoshi Tool — esqueleto base
Arranca, muestra un menú y deja todo listo para ir añadiendo funciones paso a paso.
"""

# ===============================
# IMPORTS BÁSICOS
# ===============================
import os, sys, json, time, requests
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
# HELPER: intentar usar get_activity_batch si existe, si no Blockstream
# ===============================
def _activity_batch(addresses, timeout=15):
    try:
        # si ya tienes un selector de backend (tu función), úsalo
        return get_activity_batch(addresses, timeout=timeout)  # type: ignore[name-defined]
    except NameError:
        # fallback directo a Blockstream
        return address_activity_blockstream_batch(addresses, timeout=timeout)
# ===============================

# ===============================
# Wrapper: para varios intentos en blockstream
# ===============================
def get_activity_blockstream_single_with_retry(address: str,
                                               retries: int = 3,
                                               first_timeout: int = 10,
                                               backoff_seconds: int = 2) -> Dict[str, Any]:
    """
    Llama a Blockstream con reintentos y backoff incremental.
    """
    for i in range(retries):
        try:
            # timeout crece en cada intento: 10s, 15s, 20s...
            t = first_timeout + i * 5
            return address_activity_blockstream_single_mainnet(address, timeout=t, session=_HTTP)
        except requests.ReadTimeout as e:
            wait = backoff_seconds * (2 ** i)
            print(f"[Red] Timeout (t={t}s). Reintento {i+1}/{retries} en {wait}s…")
            time.sleep(wait)
        except requests.RequestException as e:
            wait = backoff_seconds * (2 ** i)
            print(f"[Red] {e.__class__.__name__}: {e}. Reintento {i+1}/{retries} en {wait}s…")
            time.sleep(wait)

    # Si se agotaron los reintentos, lanza un error claro
    raise RuntimeError("No se pudo consultar la dirección tras varios reintentos a Blockstream.")
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


def address_activity_blockstream_single_mainnet(address: str, timeout: int = 15):
    """
    Consulta rápida (mainnet) para una sola dirección.
    Devuelve: total (sats), ever_received, ever_spent, utxo_count, confirmed, unconfirmed.
    """
    headers = {"User-Agent": "BTC-Checker/1.0"}

    r = requests.get(f"{BLOCKSTREAM_BASE}/address/{address}", timeout=timeout, headers=headers)
    r.raise_for_status()
    data = r.json()
    chain = data.get("chain_stats", {})
    mem   = data.get("mempool_stats", {})

    confirmed   = chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)
    unconfirmed = mem.get("funded_txo_sum", 0)   - mem.get("spent_txo_sum", 0)
    total       = confirmed + unconfirmed

    ever_received = (chain.get("funded_txo_count", 0) + mem.get("funded_txo_count", 0)) > 0
    ever_spent    = (chain.get("spent_txo_count", 0)  + mem.get("spent_txo_count", 0))  > 0

    r2 = requests.get(f"{BLOCKSTREAM_BASE}/address/{address}/utxo", timeout=timeout, headers=headers)
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
                    ok = guardar_wallet(
                        address=it["address"],
                        activity=a,
                        mnemonic_str=mnemonic,
                        passphrase=PASSPHRASE,
                        wif=it["wif"],
                        xprv=batch["root_xprv"],
                        filepath=HITS_FILEPATH,
                    )
                    print(f"\n¡HIT ENCONTRADO! (seed #{seeds_contador})")
                    if ok:
                        print(f"Semilla y claves guardadas en: {HITS_FILEPATH}")
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

def _derivar_desde_wif(wif: str, prefer_segwit: bool = True) -> Dict[str, Any]:
    """
    Convierte un WIF (mainnet) a dirección.
    Requiere bitcoinlib:  python3 -m pip install bitcoinlib
    """
    try:
        from bitcoinlib.keys import Key
    except Exception as e:
        raise ImportError("Falta 'bitcoinlib' para manejar WIF. Instala: python3 -m pip install bitcoinlib") from e

    k = Key(import_key=wif, network="bitcoin")
    # Legacy 1..., SegWit bc1..., (taproot depende de la lib)
    addr_legacy = k.address()
    try:
        addr_segwit = k.address(witness_type="segwit")
    except Exception:
        addr_segwit = None
    address = addr_segwit if (prefer_segwit and addr_segwit) else addr_legacy

    return {
        "path": "(WIF único)",
        "address": address,
        "wif": wif,
        "pubkey_hex": k.public_hex,
        "account_xpub": None,
        "account_xprv": None,
        "root_xprv": None,
    }

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
def run_manual_mode() -> None:
    """
    Dada una mnemónica/xprv/WIF:
      - Deriva la primera dirección para 44/49/84/86 (m/.../0/0)
      - Consulta saldo/actividad
      - Muestra resultados por pantalla
    """
    print("\n=== Modo MANUAL ===")
    try:
        seed_input = input("Introduce tu mnemónica (12/24), xprv o WIF: ").strip()

        # Detectar tipo de entrada
        if seed_input.startswith("xprv"):
            seed_mode = "xprv"
            seed_value = seed_input
            passphrase = ""  # no aplica
        elif (len(seed_input) in (51, 52)) and (seed_input[0] in ("5", "K", "L")):
            seed_mode = "wif"
            seed_value = seed_input
            passphrase = ""  # no aplica
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

        # Derivar primera dirección para todos los purposes
        derivs = derive_first_for_all_purposes(seed_mode, seed_value, passphrase)

        # Reunir direcciones derivadas con éxito
        addr_map: Dict[int, str] = {}
        for item in derivs:
            if item["ok"]:
                addr_map[item["purpose"]] = item["data"]["address"]

        # Consultar actividad en lote (solo de las derivadas ok)
        activities: Dict[str, Dict[str, Any]] = {}
        if addr_map:
            addrs = list(addr_map.values())
            acts = _activity_batch(addrs, timeout=15)
            for a, act in zip(addrs, acts):
                activities[a] = act

        # Mostrar resultados
        print("\n=== Resultados por derivación ===")
        labels = {
            44: "BIP44  (Legacy P2PKH, 1...)",
            49: "BIP49  (P2SH-P2WPKH, 3...)",
            84: "BIP84  (P2WPKH bech32, bc1q...)",
            86: "BIP86  (Taproot P2TR, bc1p...)",
        }

        for item in derivs:
            p = item["purpose"]
            print(f"\n[{p}] {labels.get(p, '')}")
            if not item["ok"]:
                print(f"  ✗ No disponible: {item['error']}")
                continue

            d = item["data"]
            addr = d["address"]
            act = activities.get(addr, None)

            print(f"  Dirección: {addr}")
            if act:
                used = "Sí" if act.get("ever_received", False) else "No"
                print(f"  Saldo: {act.get('total',0)/1e8:.8f} BTC  | Usada: {used}  | UTXOs: {act.get('utxo_count',0)}")
            else:
                print("  (sin datos de actividad — no se pudo consultar o no disponible)")

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
# Generador de combinaciones desde máscara
def _build_slot_candidates(token: str, wordlist: List[str]) -> List[str]:
    """Devuelve la lista de candidatos para un 'token' (palabra fija, '?', o 'pref*')."""
    t = token.strip().lower()
    if t == "?":
        return wordlist[:]  # todas
    if t.endswith("*") and len(t) >= 2:
        prefix = t[:-1]
        return [w for w in wordlist if w.startswith(prefix)]
    # palabra fija: validar que exista en wordlist
    if t not in wordlist:
        raise ValueError(f"La palabra fija '{t}' no está en la lista BIP39.")
    return [t]

def _iter_mnemonics_from_mask(mask_str: str) -> Tuple[int, Any]:
    """
    Recibe una máscara de 12 o 24 tokens separados por espacio con '?', 'pref*' o palabra fija.
    Devuelve (num_combinaciones_estimado, iterador_de_mnemonicas_validas).
    """
    mnemo = Mnemonic("english")
    wordlist = mnemo.wordlist

    tokens = normalize_mnemonic(mask_str).split()
    if len(tokens) not in (12, 24):
        raise ValueError("La máscara debe tener 12 o 24 palabras/tokens.")

    # Candidatos por posición
    slots: List[List[str]] = []
    for tok in tokens:
        slots.append(_build_slot_candidates(tok, wordlist))

    # Estimación de combinaciones totales (antes de checksum)
    import math
    est_total = 1
    for s in slots:
        est_total = est_total * max(1, len(s))
        if est_total > 10**12:
            # protección de cordura
            break

    # Iterador que filtra por checksum
    def _generator():
        from itertools import product
        for combo in product(*slots):
            phrase = " ".join(combo)
            if mnemo.check(phrase):  # checksum OK
                yield phrase

    return est_total, _generator()
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

# --- Wrapper con reintentos para consultar saldo (evita caídas por timeout/429) ---
def _activity_single_with_retry(address: str, tries: int = 3, base_timeout: int = 10) -> Dict[str, Any]:
    """
    Llama a address_activity_blockstream_single_mainnet(address, timeout=…)
    con reintentos ante timeouts o 429 (rate limit).
    """
    for attempt in range(1, tries + 1):
        try:
            return address_activity_blockstream_single_mainnet(address, timeout=base_timeout + (attempt - 1) * 5)
        except requests.exceptions.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 429:
                wait = 2 * attempt
                print(f"[Rate limit 429] Esperando {wait}s y reintentando…")
                time.sleep(wait)
                continue
            raise
        except requests.exceptions.RequestException as e:
            wait = 2 * attempt
            print(f"[Red] {e}. Reintento en {wait}s…")
            time.sleep(wait)
    raise RuntimeError("No se pudo consultar actividad tras varios intentos.")


# --- Guardar “hits” de Seed Hunter en un TXT + JSONL ---
def _persist_seed_hit(
    *,
    address: str,
    activity: Dict[str, Any],
    mnemonic: str,
    passphrase: str,
    path: str,
    outfile: Optional[str] = None,
) -> None:
    """
    Guarda un bloque de texto + JSONL con la info cuando hay HIT (coincidencia con objetivo
    o «saldo>0/ever_received» si no hay objetivo).
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out = outfile or globals().get(
        "SEED_HITS_FILEPATH",
        os.path.join(base_dir, "Semillas_Cazadas.txt"),
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)

    ts_human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    ts_epoch = int(time.time())

    lines = [
        "================= SEED HIT =================",
        f"Fecha:     {ts_human}",
        f"Dirección: {address}",
        f"Saldo:     {activity.get('total', 0)} sats",
        f"Recibida:  {'Sí' if activity.get('ever_received') else 'No'} | "
        f"Gastada: {'Sí' if activity.get('ever_spent') else 'No'} | "
        f"UTXOs: {activity.get('utxo_count', 0)}",
        f"Path:      {path}",
        "----- Datos sensibles (⚠ GUARDAR CON EXTREMO CUIDADO) -----",
        f"Mnemonic:  {mnemonic}",
        f"Passphrase: {passphrase}",
        "",
    ]

    with open(out, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write(json.dumps({
            "timestamp": ts_epoch,
            "address": address,
            "total_sats": activity.get("total", 0),
            "ever_received": activity.get("ever_received", False),
            "ever_spent": activity.get("ever_spent", False),
            "utxo_count": activity.get("utxo_count", 0),
            "path": path,
            "mnemonic": mnemonic,
            "passphrase": passphrase or None,
        }, ensure_ascii=False) + "\n")

    try:
        os.chmod(out, 0o600)
    except Exception:
        pass


        print("\n\nInterrumpido por el usuario.")
        pause("Pulsa Enter para continuar...")

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

    try:
        for mnemonic in _iter_mnemonics_from_mask(mask_str):
            tested += 1

            # — Barra de progreso + ETA —
            if (tested % UPDATE_EVERY) == 0 or tested == 1:
                elapsed = time.time() - start_time
                if total_for_bar:
                    pct = min(1.0, tested / total_for_bar)
                    filled = int(round(pct * BAR_WIDTH))
                    bar = "█" * filled + "░" * (BAR_WIDTH - filled)

                    rate = tested / elapsed if elapsed > 0 else 0.0
                    remaining = max(0, total_for_bar - tested)
                    eta_sec = (remaining / rate) if rate > 0 else 0
                    eta_str = _fmt_hms(eta_sec)

                    print(f"[{bar}] {pct*100:6.2f}%  {tested:,}/{total_for_bar:,}  ETA {eta_str}", end="\r", flush=True)
                else:
                    # sin total exacto: muestra tested y elapsed
                    elapsed_str = _fmt_hms(elapsed)
                    filled = BAR_WIDTH // 4
                    bar = "█" * filled + "░" * (BAR_WIDTH - filled)
                    print(f"[{bar}]   --.--%  {tested:,}/???  Elapsed {elapsed_str}", end="\r", flush=True)

            # Derivar m/.../0/0
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

            # Coincidencia exacta con dirección objetivo
            if target_address:
                if addr == target_address:
                    print("\n")  # soltar la línea de barra
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
            else:
                # Sin dirección → hit si saldo > 0 o recibió alguna vez
                try:
                    act = _activity_single_with_retry(addr, tries=2, base_timeout=10)
                except Exception:
                    continue

                if (act.get("total", 0) > 0) or act.get("ever_received", False):
                    print("\n")  # soltar la línea de barra
                    print("✅ ¡ENCONTRADA!")
                    print(f"Mnemonic:  {mnemonic}")
                    print(f"Path:      {derived['path']}")
                    print(f"Address:   {addr}")
                    print(f"Saldo total: {act['total']/1e8:.8f} BTC  | "
                          f"Recibida: {'Sí' if act['ever_received'] else 'No'}  "
                          f"| Gastada: {'Sí' if act['ever_spent'] else 'No'}  "
                          f"| UTXOs: {act['utxo_count']}")
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

