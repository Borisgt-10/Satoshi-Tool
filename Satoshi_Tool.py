#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Satoshi's Tool — entrypoint principal.

Arranca el backend FastAPI en un thread daemon, espera al health-check,
abre una ventana nativa con PyWebView (WebKit en macOS) cargando la SPA,
y al cerrar la ventana detiene uvicorn limpiamente.

Para uso headless (sin ventana), usar el CLI clásico:
    python3 -m satoshi_tool.cli
"""

from __future__ import annotations

import socket
import sys
import threading
import time

import requests
import uvicorn
import webview

from satoshi_tool.web.app import app as fastapi_app


def _find_free_port() -> int:
    """Devuelve un puerto TCP libre en 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(port: int, timeout: float = 8.0) -> bool:
    """Espera hasta /api/health responda 200 OK o se agote el timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/api/health", timeout=0.5)
            if r.ok and r.json().get("status") == "ok":
                return True
        except requests.RequestException:
            pass
        time.sleep(0.15)
    return False


def main() -> None:
    port = _find_free_port()

    config = uvicorn.Config(
        app=fastapi_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    def run_server():
        try:
            server.run()
        except Exception as e:
            print(f"[uvicorn] error: {e}", file=sys.stderr)

    server_thread = threading.Thread(target=run_server, daemon=True, name="uvicorn-thread")
    server_thread.start()

    if not _wait_for_health(port):
        print("Error: el backend no arrancó a tiempo. Saliendo.", file=sys.stderr)
        sys.exit(1)

    url = f"http://127.0.0.1:{port}"
    window = webview.create_window(
        title="Satoshi's Tool",
        url=url,
        width=1100,
        height=720,
        min_size=(820, 560),
        background_color="#000000",
    )

    def on_window_closed():
        # Pide a uvicorn detenerse cuando la ventana se cierra
        server.should_exit = True

    window.events.closed += on_window_closed
    webview.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrumpido. ¡Hasta luego!")
