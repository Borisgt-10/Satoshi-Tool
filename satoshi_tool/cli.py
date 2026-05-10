"""Menú interactivo clásico (CLI). Sin cambios funcionales respecto a fase 3.
Punto de entrada headless para uso en remoto/scripts."""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from mnemonic import Mnemonic
from bip_utils import Bip39Languages, Bip39MnemonicValidator

from satoshi_tool.blockstream import (
    _activity_batch,
    _activity_single_with_retry,
    address_activity_blockstream_batch,
)
from satoshi_tool.config import (
    PASSPHRASE_HITS_FILEPATH,
    PURPOSE_LABELS,
    SEED_HITS_FILEPATH,
)
from satoshi_tool.derivation import (
    crear_semilla,
    derivar_direcciones_batch_mnemonic,
    derivar_primera_direccion_por_purpose,
    derive_first_for_all_purposes,
    infer_purpose_from_address,
    scan_purpose_with_gap_limit,
)
from satoshi_tool.mask import (
    _estimate_combinations,
    _iter_mnemonics_from_mask,
    _parse_mask,
)
from satoshi_tool.persistence import _persist_passphrase_hit, _persist_seed_hit


# ============================================================
# Helpers de I/O del CLI
# ============================================================
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


# ============================================================
# Funciones de modo (run_*) — copiadas del Satoshi_Tool.py monolítico
# de fase 3, con imports apuntando a los nuevos módulos del paquete.
# Lógica idéntica.
# ============================================================
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


# ============================================================
# Punto de entrada del CLI clásico
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
