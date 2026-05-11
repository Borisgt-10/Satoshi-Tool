# 🟠 Satoshi's Tool

> Herramienta local en Python para trabajar con **semillas BIP-39** y direcciones Bitcoin (mainnet). Interfaz web nativa con PyWebView, modos múltiples para generación, derivación y recuperación, y persistencia local de hits.

---

## ⚠️ Aviso importante

Esta es una herramienta **local-only**. Las mnemónicas que introduzcas **nunca salen de tu equipo**: la app sirve la interfaz en `127.0.0.1` y se conecta directamente a Blockstream para consultar saldos públicos.

Pensada para **uso educativo y recuperación personal**. No usar con fondos de terceros.

---

## ✨ Características

- **Modo Auto** — genera mnemónicas aleatorias y comprueba actividad on-chain (educativo).
- **Modo Manual** — introduce mnemónica/xprv/WIF, deriva direcciones de los 4 purposes (BIP44/49/84/86) con escaneo rápido o completo (gap limit 20 en cadenas externa e interna).
- **Passphrase Hunter** — prueba una lista de passphrases BIP-39 sobre una seed conocida.
- **Seed Hunter** — recupera mnemónicas con palabras desconocidas usando máscaras con `?` (cualquier palabra) y `pre*` (prefijo).
- **Generador** — crea mnemónicas nuevas y muestra sus direcciones, xprv y WIF.
- **Histórico** — tabla con todos los hits encontrados, filtros y revelado de datos sensibles bajo demanda.
- **Streaming en vivo** — los modos largos muestran dashboard con KPIs (rate, ETA, hits, errors) actualizándose en tiempo real.
- **Rate limiting** y **paralelismo** integrados (8 req/s con burst 16, pool de 8 conexiones HTTP).

---

## 🚀 Instalación

Requisitos: macOS (Linux/Windows pendiente), Python 3.9+, conexión a internet para consultar Blockstream.

```bash
git clone https://github.com/Borisgt-10/Satoshi-Tool.git
cd Satoshi-Tool
python3 -m pip install -r requirements.txt
```

(Opcional, para correr la suite de tests:)

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
```

---

## ▶️ Uso

### Aplicación con ventana nativa (recomendado)

Doble-click sobre `Satoshi.command` en Finder, o desde terminal:

```bash
python3 Satoshi_Tool.py
```

Se abrirá una ventana nativa con la SPA. Usa el sidebar para cambiar entre modos.

### CLI clásico (headless)

Si prefieres el menú interactivo de consola:

```bash
python3 -m satoshi_tool.cli
```

---

## 📂 Ficheros de salida

Cuando un modo encuentra un hit (saldo > 0 o dirección con historial), se persiste en uno de:

- `Semillas_Cazadas.txt` — hits del Modo Auto y Seed Hunter.
- `Passphrases_Cazadas.txt` — hits del Passphrase Hunter.

Ambos guardan un bloque legible + una línea JSONL parseable por cada hit. Permisos `0600` por defecto.

Estos archivos están **excluidos del repositorio git** vía `.gitignore` — nunca van a GitHub aunque hagas commit.

---

## 🏗️ Arquitectura

```
Satoshi_Tool.py           # entrypoint: arranca FastAPI + abre PyWebView
satoshi_tool/             # paquete principal
├── config.py             # paths, sesión HTTP, rate limiter, thread pool
├── blockstream.py        # cliente Blockstream API
├── derivation.py         # derivación HD + scan con gap limit
├── mask.py               # parser de máscaras + iterador de candidatos
├── persistence.py        # escritura JSONL + lectura del histórico
├── cli.py                # menú interactivo legacy
└── web/                  # backend FastAPI + SPA estática
    ├── app.py
    ├── jobs.py           # JobManager con cola SSE
    ├── routes_*.py       # endpoints por modo
    └── static/           # HTML + CSS + Alpine.js de la SPA
tests/                    # suite pytest (45 tests, todos offline)
```

---

## 🧪 Tests

```bash
python3 -m pytest -v
```

Los tests son determinísticos y no dependen de red. Cubren:
- Derivación HD con vectores BIP-39 estándar.
- Parser y generador de máscaras.
- Rate limiter (token bucket).
- Persistencia y lectura del histórico.
- Todos los endpoints REST + SSE de FastAPI.

---

## ⚖️ Disclaimer

🇪🇸 Esta herramienta es únicamente para **uso educativo y de recuperación personal**.  
No debe usarse con fines ilegales ni para acceder a fondos de terceros.  
El autor no se hace responsable del uso indebido que se haga del software.  

🇬🇧 This tool is intended for **educational and personal recovery purposes only**.  
It must not be used for illegal activities or to access third-party funds.  
The author is not responsible for any misuse of this software.

---

## 📜 Licencia

Ver `LICENSE`.

---

**Autor:** [Boris GT](https://github.com/Borisgt-10)
