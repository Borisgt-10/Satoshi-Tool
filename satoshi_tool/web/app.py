"""Aplicación FastAPI: endpoints REST + (en tareas posteriores) SSE."""

from __future__ import annotations

from fastapi import FastAPI

from satoshi_tool.web.routes_generator import router as generator_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Satoshi's Tool",
        version="0.4.0",
        description="API local para BIP-39 / HD Bitcoin (mainnet).",
    )

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.4.0"}

    app.include_router(generator_router)
    return app


app = create_app()
