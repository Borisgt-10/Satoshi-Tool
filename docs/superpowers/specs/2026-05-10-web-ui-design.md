# Satoshi's Tool — diseño de UI web (fase 4)

**Fecha:** 2026-05-10
**Autor:** Boris (BorisGT) + Claude
**Estado:** aprobado por el usuario, pendiente de plan de implementación

---

## 1. Resumen

Convertir `Satoshi_Tool.py` (CLI interactivo de ~1.700 líneas en un único fichero) en una **aplicación de escritorio local** con interfaz web embebida en una ventana nativa de macOS. Mantener intacta la lógica BIP-39/HD que se ha pulido en las fases 1–3 (paralelismo, rate limiting, escaneo gap limit, persistencia). Sustituir el menú de consola y los `input()` por una SPA que se comunica con un FastAPI embebido vía REST + Server-Sent Events.

El objetivo es que Boris (autor) y otras personas técnicas que clonen el repo desde GitHub tengan una herramienta visualmente moderna sin perder la naturaleza local-only y educativa del proyecto.

## 2. Objetivos y no-objetivos

### Objetivos

- Mantener todos los modos actuales: Auto, Manual, Passphrase Hunter, Seed Hunter, Generador.
- Añadir un modo nuevo: **Histórico**, que lee los `.txt` de hits que el sistema ya escribe.
- Vivir en una **ventana nativa** (no una pestaña del navegador), abierta con doble click.
- Mostrar el progreso de los escaneos largos en un **dashboard live** con KPIs.
- Conservar el formato de los `.txt` JSONL existentes (`Passphrases_Cazadas.txt`, `Semillas_Cazadas.txt`) — la app web los lee y escribe igual.
- Ser distribuible **sólo por código fuente** en GitHub (`pip install -r requirements.txt && python3 Satoshi_Tool.py`).

### No-objetivos

- **No** se distribuye binario `.app` firmado/notarizado (requeriría Apple Developer Program, $99/año). El empaquetado `.app` personal de Boris se considera fase 4.7 opcional.
- **No** se sirve nada por internet pública. Toda la app corre en `127.0.0.1`. Las mnemónicas nunca salen del Mac de quien la ejecuta.
- **No** se usa framework pesado de frontend (React, Vue, Svelte). Sin paso de build (Vite/Webpack).
- **No** se reescribe la lógica core en otro lenguaje. Se mantiene Python.
- **No** se cambia el formato de salida de los hits ni el directorio donde se guardan.
- **No** hay tests E2E del frontend en MVP. Sólo tests unitarios/integración del backend.

## 3. Decisiones tomadas (con justificación)

| # | Decisión | Justificación |
|---|---|---|
| 1 | **Local-only**, sin distribución pública en internet | Las mnemónicas BIP-39 son material extremadamente sensible. Un servidor remoto sería un cambio de modelo de amenaza enorme. |
| 2 | **Mantener Python**, no reescribir en Rust/Node/TS | Las fases 1–3 ya pulieron el core en Python. El cuello de botella del Seed Hunter es la red, no la CPU; cambiar de lenguaje no movería la aguja. |
| 3 | **PyWebView** para la ventana nativa | En macOS usa WebKit nativo (sin Chrome ni dependencias externas). Ventana real con título e icono propio. Multiplataforma para futuro Linux/Windows. |
| 4 | **FastAPI embebido + SSE** sobre `js_api` directo de PyWebView | SSE es el patrón estándar para streaming server→cliente y los escaneos largos lo necesitan. `js_api` es síncrono y obligaría a hacks con `evaluate_js`. ~200 KB extra de RAM, ganamos un patrón claro y testeable. |
| 5 | **Alpine.js** + HTML + CSS plano para frontend | 12 KB, sin build step, declarativo. Frameworks pesados serían sobreingeniería para 6 vistas. |
| 6 | **Layout sidebar lateral** | Vista la elección del usuario sobre tabs/dashboard de tarjetas. Siempre ves dónde estás y permite añadir modos sin reorganizar. |
| 7 | **Estética "neón / dashboard cripto"** | Elección del usuario. Negro absoluto, naranja BTC, monoespaciado para datos. Comprometido a usar mono **sólo** para datos numéricos y direcciones, no para texto narrativo (evitar fatiga visual). |
| 8 | **Dashboard con KPIs** para vista de escaneo en marcha | Elección del usuario. Para escaneos de miles de candidatos, los logs en vivo son ruido; los KPIs (% / rate / ETA / hits / errors) son lo que de verdad miras. |
| 9 | **Tab Histórico en sidebar** | Aprovecha el JSONL que ya se escribe. Convierte la app de "CLI con UI" en un sitio donde se acumula tu trabajo. Coste de implementación bajo. |
| 10 | **Distribución por código en GitHub (modelo B-bis)**, sin `.app` distribuible | Cero coste, target adecuado (gente técnica con Python). El `.app` empaquetado se reserva para uso personal del autor en fase posterior. |

## 4. Arquitectura

### Vista alto nivel

```
┌─────────────────────────────────────────────────────────────┐
│  Proceso Python                                              │
│  ┌──────────────────┐         ┌─────────────────────────┐   │
│  │ Thread principal │◀───────▶│ Thread daemon: uvicorn  │   │
│  │ pywebview.start()│  HTTP   │ FastAPI (127.0.0.1:rand)│   │
│  │ ventana WebKit   │  + SSE  │  /api/*                 │   │
│  │                  │         │  /         (SPA)        │   │
│  └──────────────────┘         └─────────────────────────┘   │
│             ▲                            ▲                   │
│             │ render HTML/CSS/JS          │                   │
│             │ (Alpine.js + EventSource)  │                   │
│             ▼                            ▼                   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  satoshi_tool/  (lógica BIP-39 sin tocar)              │ │
│  │   derivation · blockstream · mask · persistence        │ │
│  │   RateLimiter · ThreadPoolExecutor · _summary_throttled│ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Flujo de un escaneo largo (Seed Hunter)

```
1. Usuario rellena formulario → Submit
2. Frontend: fetch POST /api/hunter/start { mask, target, purpose, ... }
3. Backend: crea job_id, lanza el escaneo en un thread,
            registra cola de eventos en JobManager
            responde { job_id }
4. Frontend: abre EventSource /api/jobs/{id}/stream
5. Backend: el on_progress del scan empuja eventos a la cola
            (KPI updates cada N candidatos, hits inmediatos,
             errores, evento "done")
6. Frontend: actualiza el dashboard live, resalta hits
7. Si usuario pulsa STOP → POST /api/jobs/{id}/cancel
   Backend: setea flag, el scan se interrumpe limpiamente
8. Al terminar: backend cierra cola con evento "done",
                frontend cierra EventSource
```

## 5. Estructura de ficheros

```
Satoshi_Tool.py                  # entrypoint: lanza FastAPI thread + abre PyWebView
Satoshi.command                  # wrapper bash para doble-click
requirements.txt                 # mnemonic, bip_utils, requests, fastapi, uvicorn,
                                 # pywebview, pyobjc-framework-WebKit (macOS)
requirements-dev.txt             # pytest, openpyxl, httpx
README.md                        # instalación, ejecución, capturas

satoshi_tool/
├── __init__.py
├── config.py                    # paths, RateLimiter, _HTTP, _HTTP_POOL,
│                                # PURPOSE_LABELS, BLOCKSTREAM_BASE
├── blockstream.py               # cliente API (lo que tenemos hoy):
│                                # address_summary_only, address_activity_*,
│                                # _summary_single_with_retry, _summary_single_throttled,
│                                # _activity_single_with_retry, _activity_batch
├── derivation.py                # crear_semilla, derive_first_for_all_purposes,
│                                # derivar_primera_direccion_por_purpose,
│                                # derivar_direcciones_batch_mnemonic,
│                                # scan_purpose_with_gap_limit,
│                                # infer_purpose_from_address
├── mask.py                      # _parse_mask, _estimate_combinations,
│                                # _iter_mnemonics_from_mask
├── persistence.py               # _persist_passphrase_hit, _persist_seed_hit,
│                                # read_history (nuevo: lee y parsea los .txt)
├── cli.py                       # menú interactivo viejo (opcional, para uso headless)
└── web/
    ├── __init__.py
    ├── app.py                   # FastAPI app + montaje de StaticFiles
    ├── jobs.py                  # JobManager: jobs en memoria + colas SSE
    ├── routes_manual.py         # POST /api/manual/quick, /api/manual/full
    ├── routes_hunter.py         # POST /api/hunter/start
    ├── routes_passphrase.py     # POST /api/passphrase/start
    ├── routes_auto.py           # POST /api/auto/start
    ├── routes_generator.py      # POST /api/generator
    ├── routes_history.py        # GET /api/history
    ├── routes_jobs.py           # GET /api/jobs/{id}/stream (SSE),
    │                            # POST /api/jobs/{id}/cancel
    └── static/
        ├── index.html           # SPA shell (sidebar + outlet)
        ├── theme.css            # design tokens neón
        ├── app.js               # Alpine.js components, helpers, EventSource
        ├── icons/               # SVG (sustituyen a los emojis del mockup)
        └── views/
            ├── auto.html        # fragments cargados con Alpine + fetch
            ├── manual.html
            ├── passphrase.html
            ├── hunter.html
            ├── generator.html
            └── history.html

tests/
├── conftest.py                  # fixtures comunes
├── test_derivation.py           # vectores BIP39 + Test_wallets.xlsx + scan stub
├── test_mask.py                 # parse, iter, prefijos, errores
├── test_rate_limiter.py         # token bucket
├── test_persistence.py          # leer/escribir TXT JSONL
└── test_api.py                  # rutas FastAPI con TestClient

docs/
└── superpowers/specs/
    └── 2026-05-10-web-ui-design.md     # este documento

Older_Versions/                  # se mantiene intacto (histórico)
Passphrases_Cazadas.txt          # se sigue escribiendo y leyendo
Semillas_Cazadas.txt             # idem
Test_wallets.xlsx                # fixture para tests
```

### Lo que se mantiene intacto de las fases 1–3

- Toda la lógica de derivación HD (incluida `scan_purpose_with_gap_limit`).
- El rate limiter, el thread pool, los wrappers throttled.
- El parser de máscaras y el iterador de mnemónicas con checksum.
- El formato JSONL de persistencia.

### Lo que se elimina o aísla

- El menú de consola (`prompt_mode`, `ask_menu_option`) y los `run_*_mode` que dependen de `input()` se mueven a `satoshi_tool/cli.py`. La decisión final (mantener para uso headless o eliminar) se toma en el hito 4.6.
- `print(...)` como mecanismo de progreso → reemplazado por callbacks `on_progress` que ya existen, conectados a las colas SSE.

## 6. UI / UX

### Sidebar (6 ítems + estado)

```
◈ SATOSHI
─────────
⚡ Auto
🔍 Manual
🔑 Passphrase
🎯 Seed Hunter
🆕 Generador
─────────
📜 Histórico
─────────
[barra inferior: backend = Blockstream | rate = 8/s]
```

(Los emojis son placeholders para mockup; en implementación se sustituyen por SVG en `static/icons/`.)

### Comportamiento por modo

**⚡ Auto** — botón `SCAN`. Dashboard live con KPIs (seeds generadas, direcciones consultadas, hits, rate, elapsed) + lista corta de eventos relevantes (direcciones con actividad o errores; las vacías se contabilizan solo en los KPIs para no inundar la lista). Al detectar hit: el modo se detiene, banner naranja con mnemónica + dirección + saldo, persiste en `Semillas_Cazadas.txt`, sonido suave del sistema.

**🔍 Manual** — input grande (mnemónica/xprv/WIF) + radio "rápido" (default) / "completo (gap limit 20)". Si la entrada es mnemónica, segundo input para passphrase opcional. Botón `DERIVAR`.
- Resultado en quick: 4 tarjetas (BIP44/49/84/86) con primera dirección + estado.
- Resultado en full: dashboard de progreso en vivo, al terminar resumen con saldo total, direcciones usadas por purpose, desglose externa/interna.

**🔑 Passphrase** — tres campos: dirección objetivo (opcional), seed base, lista de passphrases (textarea, una por línea). Botón `PROBAR`. Dashboard live mientras itera. Hit → banner + persiste en `Passphrases_Cazadas.txt`.

**🎯 Seed Hunter** — input máscara con preview del nº de combinaciones estimadas. Dirección objetivo opcional. Passphrase opcional. Selector de purpose. Botón `CAZAR`. Dashboard live (KPIs según pregunta 5: progress, rate, ETA, hits, empty, errors + lista corta).

**🆕 Generador** — selector 12/24, botón `GENERAR`. Resultado: bloque grande con la mnemónica (botón "copiar"), las 4 primeras direcciones + saldos, xprv y WIF. Aviso visible: "no guardamos esto en disco".

**📜 Histórico** — tabla con todos los hits combinados de `Passphrases_Cazadas.txt` y `Semillas_Cazadas.txt`. Columnas: fecha, modo (passphrase/seed), dirección, sats, mnemónica/passphrase (botón "revelar/ocultar", oculto por defecto). Filtros simples: por modo, rango de fechas, "tiene saldo > 0". Botón "abrir el .txt" como escape hatch.

### Design tokens

**Paleta:**
- `--bg`: `#000000`
- `--bg-2`: `#070a10` (paneles)
- `--bg-3`: `#0e1320` (rows hover)
- `--border`: `#14202a`
- `--accent`: `#ffb547` (naranja BTC cálido)
- `--accent-glow`: `rgba(255, 181, 71, 0.5)`
- `--text`: `#d6f1ff`
- `--text-2`: `#7ea0b8`
- `--ok`: `#5cf2a4` (verde menta para hits)
- `--warn`: `#ffb547` (= accent)
- `--err`: `#ff8a72` (rojo coral para 429/errores)

**Tipografía:**
- Texto general: `-apple-system, "SF Pro Display", system-ui, sans-serif`
- Datos / direcciones / claves: `ui-monospace, "SF Mono", monospace`
- Tamaños: 10 / 11 / 12 / 14 / 18 px (jerarquía estricta)

**Otros:**
- `border-radius`: 6–10 px (no cuadradas)
- Bordes finos `1px` con `--border`. Sombra interior sutil en acentos.
- Animaciones: solo dos — fade-in 300 ms al cargar resultados; pulse naranja 600 ms al aparecer hit.

### Decisiones UX

- **Paste/drop de mnemónicas**: textarea acepta espacios, saltos de línea, comas. Se normaliza a "12/24 palabras minúsculas separadas por espacio".
- **Validación en vivo**: cada palabra colorea verde (en wordlist), rojo (no), gris (incompleta). Indicador final de checksum BIP-39.
- **Confirmación previa a procesos largos**: máscaras Seed Hunter con >2 incógnitas (>4M combinaciones) → modal inline "¿Seguro? Tardará X horas".
- **Botón STOP** prominente durante cualquier escaneo. Backend recibe la cancelación y para la generación de candidatos limpiamente.
- **Nada de `alert()`/`confirm()`**: toda confirmación es un panel inline en la propia vista.

## 7. API + streaming

### Endpoints REST

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/` | Sirve la SPA (`index.html`) |
| `GET` | `/static/...` | Sirve assets de `web/static/` |
| `POST` | `/api/manual/quick` | Body: `{mnemonic\|xprv\|wif, passphrase?}`. Devuelve 4 derivaciones + actividad. Sin streaming. |
| `POST` | `/api/manual/full` | Body: `{...}`. Crea job de escaneo full y devuelve `{job_id}`. |
| `POST` | `/api/hunter/start` | Body: `{mask, target?, passphrase?, purpose}`. Crea job y devuelve `{job_id}`. |
| `POST` | `/api/passphrase/start` | Body: `{seed, target?, purpose, passphrases:[...]}`. Crea job. |
| `POST` | `/api/auto/start` | Body: `{}`. Crea job. |
| `POST` | `/api/generator` | Body: `{words: 12\|24}`. Devuelve mnemónica + derivaciones + xprv + WIF. |
| `GET` | `/api/history?mode=&since=&until=&with_balance=` | Devuelve lista parseada de hits. |
| `GET` | `/api/jobs/{id}/stream` | SSE: streaming de eventos del job. |
| `POST` | `/api/jobs/{id}/cancel` | Marca el job como cancelado. |
| `GET` | `/api/health` | Status simple. Usado en el arranque para esperar a que uvicorn esté listo antes de abrir PyWebView. |

### Eventos SSE

Cada evento es JSON con tipo y payload. Tipos previstos:

- `kpi` — actualización del dashboard. Payload: `{tested, total?, hits, empty, errors, rate, eta_seconds}`. Frecuencia: ~cada 200 ms o cada 50 candidatos, lo que ocurra antes. Las direcciones vacías se contabilizan **solo aquí**, no como evento individual.
- `addr` — dirección consultada **con resultado relevante**. Payload: `{path, address, status: "used"|"error", total?, error?}`. Se emite únicamente para `used` y `error`; los `empty` no generan evento. Esto alimenta la lista corta del dashboard.
- `hit` — hit confirmado (subconjunto de `addr` con `status="used"`, separado para que el frontend pueda hacer banner + sonido + persistir). Payload completo con mnemónica, passphrase, path, dirección, sats, etc.
- `done` — job terminado. Payload: resumen (totales, duración).
- `error` — error fatal del job. Payload: `{message}`.

### Job manager

- En memoria, dict `{job_id: Job}` protegido con lock.
- Cada `Job` tiene: estado (running/cancelled/done), `queue.Queue` de eventos, thread runner.
- TTL de jobs terminados: 60 s (después se eliminan, evita fugas si el cliente nunca consume el stream).

## 8. Tests

### Cobertura prevista

| Archivo | Qué prueba |
|---|---|
| `test_derivation.py` | Vectores BIP39 estándar para los 4 purposes; fila de `Test_wallets.xlsx`; `scan_purpose_with_gap_limit` con stub de actividad (parar en gap_limit, contar usadas correctamente, manejar errores sin avanzar gap); `infer_purpose_from_address` para los 4 prefijos. |
| `test_mask.py` | `_parse_mask` con todos los tipos de token; iterador rinde la mnemónica de test entre las válidas; tokens inválidos → ValueError. |
| `test_rate_limiter.py` | Burst inicial sin bloqueo; bloqueo del primer acquire post-burst; concurrencia con 4 hilos cuadra con la rate. |
| `test_persistence.py` | Escritura del bloque legible + JSONL parseable; lector parsea N líneas, ignora líneas legibles, devuelve dicts por timestamp. |
| `test_api.py` | Endpoints REST con `TestClient`; `/api/manual/quick` con mnemónica de test mockeando Blockstream; `/api/generator` devuelve mnemónica válida; `/api/history` parsea correctamente; los endpoints de job se testan con runner stub que emite eventos sintéticos a la cola SSE. |

### No testamos en MVP

- Llamadas reales a Blockstream (flaky, lentas, dependen de red).
- Frontend (Alpine.js / HTML). Tests E2E con Playwright se reservan para fase posterior si crece.
- PyWebView en sí (es un wrapper que sólo abre la URL).

## 9. Plan de hitos

| Hito | Contenido | Resultado |
|------|-----------|-----------|
| **4.1 Refactor + tests** | Mover lógica del fichero único a paquete `satoshi_tool/`. Añadir suite pytest. CLI viejo sigue funcionando. | Paquete con tests verdes; red de seguridad. |
| **4.2 Backend FastAPI** | Crear `web/app.py`, rutas REST, JobManager. | Backend probado con `TestClient`, sin frontend. |
| **4.3 Streaming SSE** | Conectar `on_progress` a colas SSE. Endpoints `/api/jobs/{id}/stream` y `/cancel`. | `curl -N` a un job muestra eventos fluyendo. |
| **4.4 Frontend SPA** | HTML + theme.css + Alpine.js. 6 vistas cableadas. Validación en vivo. | App funcional servida por FastAPI; abres `http://localhost:PORT` en Chrome y va. |
| **4.5 PyWebView wrapper** | Entrypoint que arranca uvicorn en thread daemon, espera health-check, abre PyWebView. Cierre limpio. Wrapper `Satoshi.command`. | Doble click → ventana nativa Satoshi. |
| **4.6 Pulido + README** | Iconos SVG, animaciones (fade-in 300 ms, pulse 600 ms), README con instalación + capturas. Decisión sobre CLI viejo. | Listo para subir a GitHub. |
| **4.7 `.app` (opcional, no MVP)** | Empaquetar con `briefcase` para Mac personal. | `Satoshi.app` en `/Applications`. |

## 10. Riesgos y mitigaciones

- **PyWebView en macOS reciente**: en ciertas versiones hace falta `pip install pyobjc-framework-WebKit` además de `pywebview`. Verificar al inicio del hito 4.5 antes de prometer fechas.
- **Cierre limpio**: PyWebView captura el thread principal; al cerrar la ventana hay que detener uvicorn, jobs en curso y el thread pool. Necesita gestión explícita de signals (registrar callback en `webview.start(...)`).
- **`bip_utils` y secp256k1 con `briefcase`**: en el hito 4.7 los empaquetadores macOS pueden complicar la inclusión de extensiones nativas. No bloquea MVP (4.7 es opcional).
- **Tamaño del histórico**: si los `.txt` superan ~10k hits, parsear cada apertura puede notarse. Mitigación: cachear en memoria y refrescar bajo demanda. Sin problema en MVP.
- **Race conditions en JobManager**: lock en el dict de jobs y `queue.Queue` thread-safe son suficientes. Validar con un test que dispara N jobs y consume todos los streams concurrentemente.
- **Compatibilidad Linux/Windows futura**: PyWebView funciona en los tres OS. El `.command` wrapper es solo macOS; un `.bat` y un `.sh` son triviales si se quiere expandir luego. No es objetivo de esta fase.

## 11. Fuera de alcance (decisiones aplazadas)

- **Backend de nodo personal Electrum** (la opción "Nodo personal" del menú original sigue siendo vaporware). Cuando se implemente, será un nuevo módulo `satoshi_tool/electrum.py` y una opción en la barra inferior del sidebar para alternar backends.
- **Múltiples cuentas (`account > 0`)** en el escaneo. Hoy todo asume `account=0`. Añadir un selector cuando se necesite es trivial.
- **Wordlists BIP-39 en otros idiomas**. Hoy solo inglés. `bip_utils` ya soporta más; cambiar el `Bip39Languages.ENGLISH` a un parámetro es trabajo localizado.
- **Tests E2E del frontend** (Playwright/Cypress).
- **Distribución firmada/notarizada** (modelo "C" en el brainstorming).
- **Settings UI** (panel de ajustes para gap limit, rate limit, etc.). Estos parámetros viven hoy como constantes en `config.py`; cuando crezca la audiencia se añade el panel.
