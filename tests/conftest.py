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
