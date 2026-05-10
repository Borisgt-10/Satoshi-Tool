#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Satoshi's Tool — entrypoint legacy. Lanza el CLI clásico.
La interfaz web vive en `python3 -m satoshi_tool.web` (Plan #2)."""

from satoshi_tool.cli import main

if __name__ == "__main__":
    main()
