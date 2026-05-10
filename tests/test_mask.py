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
