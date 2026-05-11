"""Pydantic schemas compartidos entre rutas."""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


# ---- Generator ----
class GeneratorRequest(BaseModel):
    words: Literal[12, 24] = Field(default=12)


class GeneratorResponse(BaseModel):
    mnemonic: str
    words: List[str]


# ---- Manual (quick) ----
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
    derivations: List[DerivationResult]


# ---- Manual (full) y resto de jobs ----
class ManualFullRequest(BaseModel):
    seed: str
    passphrase: str = ""
    gap_limit: int = Field(default=20, ge=1, le=200)


class JobStartResponse(BaseModel):
    job_id: str


# ---- Hunter ----
class HunterStartRequest(BaseModel):
    mask: str
    target: str = ""
    passphrase: str = ""
    purpose: Literal[44, 49, 84, 86] = 84


# ---- Passphrase ----
class PassphraseStartRequest(BaseModel):
    seed: str
    target: str = ""
    purpose: Literal[44, 49, 84, 86] = 84
    passphrases: List[str]


# ---- Auto ----
class AutoStartRequest(BaseModel):
    pass
