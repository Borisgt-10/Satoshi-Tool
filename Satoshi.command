#!/bin/bash
# Wrapper para abrir Satoshi's Tool con doble-click en macOS.
# Cambia al directorio del script y ejecuta el launcher.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
exec /usr/bin/env python3 Satoshi_Tool.py
