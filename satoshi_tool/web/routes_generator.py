"""POST /api/generator — crea una mnemónica BIP-39 nueva."""

from fastapi import APIRouter

from satoshi_tool.derivation import crear_semilla
from satoshi_tool.web.models import GeneratorRequest, GeneratorResponse

router = APIRouter()


@router.post("/api/generator", response_model=GeneratorResponse)
def generator(req: GeneratorRequest):
    s = crear_semilla(req.words)
    return GeneratorResponse(mnemonic=s["mnemonic"], words=s["words"])
