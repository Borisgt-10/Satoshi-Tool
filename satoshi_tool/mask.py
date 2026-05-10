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
