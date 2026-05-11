"""Aplicación FastAPI: endpoints REST + SSE + servidor estático de la SPA."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from satoshi_tool import __version__

from satoshi_tool.web.routes_auto import router as auto_router
from satoshi_tool.web.routes_generator import router as generator_router
from satoshi_tool.web.routes_history import router as history_router
from satoshi_tool.web.routes_hunter import router as hunter_router
from satoshi_tool.web.routes_jobs import router as jobs_router
from satoshi_tool.web.routes_manual import router as manual_router
from satoshi_tool.web.routes_passphrase import router as passphrase_router

STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(
        title="Satoshi's Tool",
        version=__version__,
        description="API local para BIP-39 / HD Bitcoin (mainnet).",
    )

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    app.include_router(generator_router)
    app.include_router(manual_router)
    app.include_router(history_router)
    app.include_router(hunter_router)
    app.include_router(passphrase_router)
    app.include_router(auto_router)
    app.include_router(jobs_router)

    # Servir assets estáticos
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # SPA: ruta raíz devuelve index.html
    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(str(STATIC_DIR / "index.html"))

    return app


app = create_app()
