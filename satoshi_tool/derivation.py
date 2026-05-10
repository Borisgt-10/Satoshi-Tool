"""Derivación HD BIP-39/44/49/84/86 + escaneo con gap limit."""

from __future__ import annotations

import concurrent.futures
from typing import Any, Dict, List, Optional, Tuple

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
    seed_mode: str, seed_value: str, passphrase: str = "",
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
