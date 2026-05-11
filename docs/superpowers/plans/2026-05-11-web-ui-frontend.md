# Web UI — Frontend + PyWebView (Plan #2: hitos 4.4 + 4.5 + 4.6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir la SPA con estética neón / dashboard cripto sobre el backend del Plan #1, envolverla en una ventana nativa PyWebView con doble click desde `Satoshi.command`, y dejar el proyecto listo para subir a GitHub con README.

**Architecture:** FastAPI sirve la SPA desde `satoshi_tool/web/static/`. La SPA es una sola página con sidebar lateral (6 ítems) que carga fragments HTML para cada vista. Estado y reactividad con **Alpine.js** (CDN, sin build step). Comunicación con la API REST vía `fetch`; streaming de jobs vía `EventSource` consumiendo SSE. El entrypoint nuevo `Satoshi_Tool.py` lanza uvicorn en un thread daemon, espera al `/api/health`, y abre PyWebView con `http://127.0.0.1:<puerto>`. Cierre limpio al cerrar la ventana.

**Tech Stack:** HTML5, CSS plano (variables CSS), Alpine.js 3.x (CDN), JavaScript vanilla (fetch + EventSource), PyWebView 5.x, pyobjc-framework-WebKit (macOS).

---

## Pre-requisitos

Repo ya está en git desde el Plan #1. Trabajamos en `main` con commits locales. El push a GitHub queda para el final del Plan #2 (no incluido como tarea — Boris hace el push manual cuando decida).

## Spec de referencia

- `docs/superpowers/specs/2026-05-10-web-ui-design.md` — secciones que se implementan:
  - §6 UI / UX (toda) — sidebar, modos, design tokens, decisiones UX
  - §9 hitos 4.4, 4.5, 4.6
- `docs/superpowers/plans/2026-05-10-web-ui-backend.md` — Plan #1 ejecutado, dejó el backend funcional.

## Estructura final de ficheros tras este plan

```
Satoshi_Tool.py                  # AMPLIADO: ya no solo shim del CLI; ahora lanza la app web
Satoshi.command                  # NUEVO: wrapper bash para doble-click en macOS
README.md                        # NUEVO: instalación, ejecución, capturas, modelo B-bis
requirements.txt                 # añade: pywebview, pyobjc-framework-WebKit (sólo macOS)

satoshi_tool/
├── __init__.py                  # bump a "0.4.1"
├── (resto del paquete intacto del Plan #1)
└── web/
    ├── app.py                   # MODIFICADO: monta /static y / → index.html
    └── static/
        ├── index.html           # SPA shell con sidebar + outlet
        ├── theme.css            # design tokens neón (paleta, tipos, espaciado)
        ├── app.js               # Alpine.js + router + helpers API + EventSource
        ├── views/
        │   ├── generator.html
        │   ├── manual.html
        │   ├── history.html
        │   ├── auto.html
        │   ├── hunter.html
        │   └── passphrase.html
        └── icons/
            ├── auto.svg
            ├── manual.svg
            ├── passphrase.svg
            ├── hunter.svg
            ├── generator.svg
            ├── history.svg
            └── logo.svg
```

## Constantes y patrones que se usan en varias tareas

**Paleta CSS (del spec §6):**

```css
:root {
  --bg: #000000;
  --bg-2: #070a10;
  --bg-3: #0e1320;
  --border: #14202a;
  --accent: #ffb547;
  --accent-glow: rgba(255, 181, 71, 0.5);
  --text: #d6f1ff;
  --text-2: #7ea0b8;
  --ok: #5cf2a4;
  --warn: #ffb547;
  --err: #ff8a72;
  --font-sans: -apple-system, "SF Pro Display", "Inter", system-ui, sans-serif;
  --font-mono: ui-monospace, "SF Mono", "Menlo", monospace;
}
```

**Alpine.js component patrón:** cada vista expone un componente Alpine que se monta en su fragment. App.js carga el fragment con `fetch`, lo inyecta en `<main>`, y Alpine se inicializa automáticamente sobre `x-data` attributes.

**SSE pattern:** la app abre un `EventSource(/api/jobs/{id}/stream)`, parsea cada `event.data` como JSON, hace switch sobre `event.type` para actualizar el dashboard.

---

## Task 1: Servir StaticFiles + ruta raíz desde FastAPI

**Files:**
- Modify: `satoshi_tool/web/app.py`
- Create: `satoshi_tool/web/static/index.html` (placeholder mínimo, se infla en tarea siguiente)

- [ ] **Step 1: Crear `index.html` placeholder mínimo para que el endpoint tenga algo que servir**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Satoshi's Tool</title>
</head>
<body>
  <p>SPA en construcción.</p>
</body>
</html>
```

- [ ] **Step 2: Modificar `satoshi_tool/web/app.py` para montar StaticFiles y servir index.html en `/`**

Sustituir el fichero completo por:

```python
"""Aplicación FastAPI: endpoints REST + SSE + servidor estático de la SPA."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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
        version="0.4.1",
        description="API local para BIP-39 / HD Bitcoin (mainnet).",
    )

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.4.1"}

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
    def index():
        return FileResponse(str(STATIC_DIR / "index.html"))

    return app


app = create_app()
```

- [ ] **Step 3: Bump version en `satoshi_tool/__init__.py`**

```python
"""Satoshi's Tool — utilidades BIP-39 / HD para Bitcoin mainnet."""

__version__ = "0.4.1"
```

- [ ] **Step 4: Test rápido — el endpoint health sigue funcionando y `/` devuelve HTML**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -m pytest tests/test_api.py::test_health_returns_ok -v
```
Expected: PASS.

Y verificación manual con uvicorn:

```bash
python3 -m uvicorn satoshi_tool.web.app:app --host 127.0.0.1 --port 8765 --log-level warning &
sleep 1
curl -s http://127.0.0.1:8765/ | head -5
curl -s http://127.0.0.1:8765/static/index.html | head -5
pkill -f "uvicorn satoshi_tool.web.app:app"
```
Expected: ambos curl devuelven el HTML del placeholder.

- [ ] **Step 5: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/app.py satoshi_tool/web/static/index.html satoshi_tool/__init__.py
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(web): servir SPA estática desde FastAPI"
```

---

## Task 2: `theme.css` con design tokens (paleta neón)

**Files:**
- Create: `satoshi_tool/web/static/theme.css`

- [ ] **Step 1: Escribir `theme.css` con paleta + tipografía + utilidades base**

```css
/* === Satoshi's Tool — theme neón / dashboard cripto === */

:root {
  --bg: #000000;
  --bg-2: #070a10;
  --bg-3: #0e1320;
  --border: #14202a;
  --accent: #ffb547;
  --accent-glow: rgba(255, 181, 71, 0.5);
  --text: #d6f1ff;
  --text-2: #7ea0b8;
  --ok: #5cf2a4;
  --warn: #ffb547;
  --err: #ff8a72;
  --font-sans: -apple-system, "SF Pro Display", "Inter", system-ui, sans-serif;
  --font-mono: ui-monospace, "SF Mono", "Menlo", monospace;
  --radius: 8px;
  --radius-sm: 6px;
}

* { box-sizing: border-box; }

html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-sans);
  font-size: 13px;
  line-height: 1.5;
  height: 100vh;
  overflow: hidden;
}

/* Layout principal */
.app {
  display: flex;
  height: 100vh;
}

.sidebar {
  width: 180px;
  background: var(--bg-2);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
}

.sidebar .logo {
  padding: 18px 18px 12px;
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 13px;
  letter-spacing: 0.5px;
  color: var(--accent);
  text-shadow: 0 0 12px var(--accent-glow);
}

.sidebar .nav {
  flex: 1;
  padding: 4px 0;
}

.sidebar .nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 18px;
  cursor: pointer;
  color: var(--text-2);
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
  border-left: 2px solid transparent;
  transition: color 0.15s, background 0.15s;
}

.sidebar .nav-item:hover {
  color: var(--text);
  background: var(--bg-3);
}

.sidebar .nav-item.active {
  color: var(--accent);
  background: linear-gradient(90deg, rgba(255, 181, 71, 0.08), transparent);
  border-left-color: var(--accent);
  box-shadow: inset 0 0 18px rgba(255, 181, 71, 0.06);
}

.sidebar .nav-item .icon {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
  opacity: 0.8;
}

.sidebar .nav-divider {
  border-top: 1px solid var(--border);
  margin: 6px 0;
}

.sidebar .footer {
  padding: 10px 18px;
  font-size: 10px;
  color: var(--text-2);
  border-top: 1px solid var(--border);
  font-family: var(--font-mono);
}

main {
  flex: 1;
  padding: 24px 28px;
  overflow-y: auto;
}

/* Tipografía */
h1 { font-size: 18px; font-weight: 600; margin: 0 0 4px; color: var(--accent); text-transform: uppercase; letter-spacing: 1px; font-family: var(--font-mono); }
h2 { font-size: 14px; font-weight: 600; margin: 16px 0 8px; color: var(--accent); font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.5px; }
p.subtitle { font-size: 11px; opacity: 0.6; margin: 0 0 16px; font-family: var(--font-mono); }
.label { display: block; font-size: 10px; color: var(--text-2); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; font-family: var(--font-mono); }
.mono { font-family: var(--font-mono); }
.muted { color: var(--text-2); }
.ok-text { color: var(--ok); }
.err-text { color: var(--err); }

/* Inputs y botones */
input, textarea, select {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 12px;
  outline: none;
  transition: border-color 0.15s;
}

input:focus, textarea:focus, select:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 1px var(--accent-glow);
}

textarea { min-height: 60px; resize: vertical; }

button {
  background: transparent;
  border: 1px solid var(--accent);
  color: var(--accent);
  padding: 7px 18px;
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  cursor: pointer;
  transition: background 0.15s, color 0.15s;
}

button:hover:not(:disabled) {
  background: var(--accent);
  color: var(--bg);
}

button:disabled { opacity: 0.4; cursor: not-allowed; }

button.danger { border-color: var(--err); color: var(--err); }
button.danger:hover:not(:disabled) { background: var(--err); color: var(--bg); }

button.ghost { border-color: var(--border); color: var(--text-2); }
button.ghost:hover:not(:disabled) { background: var(--bg-3); color: var(--text); border-color: var(--text-2); }

/* Tarjetas / paneles */
.panel {
  background: var(--bg-2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 16px;
  margin-bottom: 12px;
}

.panel .panel-title {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent);
  margin: 0 0 8px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; font-family: var(--font-mono); font-size: 11px; border-bottom: 1px dashed var(--border); }
.row:last-child { border-bottom: none; }
.row .ad { color: var(--text-2); }
.row .em { color: var(--text-2); opacity: 0.5; }

/* Tags */
.tag {
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 9px;
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.tag.ok { color: var(--ok); border-color: #1a4a2c; background: rgba(92, 242, 164, 0.06); }
.tag.warn { color: var(--warn); border-color: #4a3a1a; background: rgba(255, 181, 71, 0.06); }
.tag.err { color: var(--err); border-color: #4a1a1a; background: rgba(255, 138, 114, 0.06); }

/* Dashboard de KPIs */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
  margin-bottom: 12px;
}

.kpi {
  background: var(--bg-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
}

.kpi .kpi-lbl { color: var(--text-2); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; font-family: var(--font-mono); }
.kpi .kpi-val { color: var(--accent); font-size: 20px; font-weight: 700; margin-top: 2px; font-family: var(--font-mono); }
.kpi .kpi-sub { color: var(--text-2); font-size: 9px; opacity: 0.6; margin-top: 1px; font-family: var(--font-mono); }
.kpi.ok .kpi-val { color: var(--ok); }
.kpi.err .kpi-val { color: var(--err); }
.kpi.neutral .kpi-val { color: var(--text); }

/* Barra de progreso */
.bar { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin: 4px 0 6px; }
.bar > div { height: 100%; background: linear-gradient(90deg, var(--accent), #ff5f56); box-shadow: 0 0 8px var(--accent-glow); transition: width 0.2s; }

/* Validación palabra-a-palabra de mnemónicas */
.word-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 6px;
  margin: 8px 0;
}
.word {
  padding: 6px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: 11px;
  text-align: center;
  border: 1px solid var(--border);
  background: var(--bg-2);
  color: var(--text-2);
}
.word.valid { color: var(--ok); border-color: rgba(92, 242, 164, 0.3); }
.word.invalid { color: var(--err); border-color: rgba(255, 138, 114, 0.3); }
.word.partial { color: var(--warn); border-color: rgba(255, 181, 71, 0.3); }

/* Banner de hit */
.hit-banner {
  background: linear-gradient(90deg, rgba(255, 181, 71, 0.18), rgba(255, 181, 71, 0.05));
  border: 1px solid var(--accent);
  border-radius: var(--radius);
  padding: 14px 16px;
  margin-bottom: 12px;
  box-shadow: 0 0 18px var(--accent-glow);
}
.hit-banner h3 { color: var(--accent); margin: 0 0 6px; font-family: var(--font-mono); font-size: 13px; letter-spacing: 0.5px; }

/* Animaciones */
@keyframes fadein { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
@keyframes pulse { 0% { background: rgba(255, 181, 71, 0.25); } 100% { background: transparent; } }
.fade-in { animation: fadein 0.3s ease-out; }
.pulse { animation: pulse 0.6s ease-out; }

/* Scrollbars */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-2); }
```

- [ ] **Step 2: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/theme.css
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): theme.css con design tokens neón (paleta y tipografía)"
```

---

## Task 3: `index.html` — shell de la SPA con sidebar y outlet

**Files:**
- Modify: `satoshi_tool/web/static/index.html` (sustitución completa)

- [ ] **Step 1: Sustituir `index.html` por la shell de la SPA**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Satoshi's Tool</title>
  <link rel="stylesheet" href="/static/theme.css">
  <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
  <script defer src="/static/app.js"></script>
</head>
<body>
  <div class="app" x-data="satoshiApp()" x-init="init()">

    <aside class="sidebar">
      <div class="logo">◈ SATOSHI</div>
      <nav class="nav">
        <div class="nav-item" :class="{active: view === 'auto'}" @click="navigate('auto')">
          <span class="icon">⚡</span> Auto
        </div>
        <div class="nav-item" :class="{active: view === 'manual'}" @click="navigate('manual')">
          <span class="icon">🔍</span> Manual
        </div>
        <div class="nav-item" :class="{active: view === 'passphrase'}" @click="navigate('passphrase')">
          <span class="icon">🔑</span> Passphrase
        </div>
        <div class="nav-item" :class="{active: view === 'hunter'}" @click="navigate('hunter')">
          <span class="icon">🎯</span> Hunter
        </div>
        <div class="nav-item" :class="{active: view === 'generator'}" @click="navigate('generator')">
          <span class="icon">🆕</span> Generador
        </div>
        <div class="nav-divider"></div>
        <div class="nav-item" :class="{active: view === 'history'}" @click="navigate('history')">
          <span class="icon">📜</span> Histórico
        </div>
      </nav>
      <div class="footer">
        backend: <span class="ok-text">Blockstream</span><br>
        rate: 8 req/s
      </div>
    </aside>

    <main>
      <div id="outlet" x-html="fragmentHtml" class="fade-in" :key="view"></div>
    </main>

  </div>
</body>
</html>
```

- [ ] **Step 2: Commit (la app aún no se monta — falta app.js, va en T4)**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/index.html
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): index.html con sidebar y outlet Alpine"
```

---

## Task 4: `app.js` base — Alpine.js + router + helpers API/SSE

**Files:**
- Create: `satoshi_tool/web/static/app.js`

- [ ] **Step 1: Escribir `app.js` completo**

```javascript
/* === Satoshi's Tool — Alpine.js app, router de vistas y helpers === */

// Helpers de API REST
const api = {
  async get(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`GET ${url} → ${r.status}`);
    return r.json();
  },
  async post(url, body) {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    if (!r.ok) {
      const detail = await r.json().catch(() => ({}));
      throw new Error(detail.detail || `POST ${url} → ${r.status}`);
    }
    return r.json();
  },
};

// Consumidor SSE: abre EventSource y enruta eventos a handlers
function openJobStream(jobId, handlers) {
  const es = new EventSource(`/api/jobs/${jobId}/stream`);
  es.onmessage = (e) => {
    let ev;
    try { ev = JSON.parse(e.data); } catch { return; }
    const h = handlers[ev.type];
    if (h) h(ev.payload);
    if (ev.type === "done" || ev.type === "error") es.close();
  };
  es.onerror = () => {
    es.close();
    if (handlers.connectionLost) handlers.connectionLost();
  };
  return es;
}

// Formateo
function fmtBTC(sats) {
  return (sats / 1e8).toFixed(8) + " BTC";
}
function fmtHMS(seconds) {
  if (!isFinite(seconds) || seconds <= 0) return "--:--:--";
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  return `${h}:${m.toString().padStart(2, "0")}:${ss.toString().padStart(2, "0")}`;
}

// Validación de mnemónicas (palabra a palabra, lista BIP-39 mínima en memoria)
// Cargamos la lista de palabras una sola vez con un fetch a un endpoint:
// usamos el primer GET /api/manual/quick con una mnemónica vacía sólo si hace falta.
// Para validación local rápida, embebemos el wordlist en una variable global.
// Como el wordlist son 2048 palabras (~17KB), lo cargamos asíncrono al inicio.
let WORDLIST = null;
async function ensureWordlist() {
  if (WORDLIST) return WORDLIST;
  // Wordlist BIP-39 inglés sirviendo desde /static/bip39-en.json (creado en T5).
  // Si no existe, fallback inline. Por ahora intentamos fetch.
  try {
    const r = await fetch("/static/bip39-en.json");
    if (r.ok) {
      WORDLIST = new Set(await r.json());
      return WORDLIST;
    }
  } catch {}
  // Fallback: validación deshabilitada
  WORDLIST = null;
  return null;
}

function validateMnemonicWords(text) {
  const tokens = text.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!WORDLIST) return tokens.map(t => ({ word: t, state: "neutral" }));
  return tokens.map(t => {
    if (WORDLIST.has(t)) return { word: t, state: "valid" };
    const matches = [...WORDLIST].some(w => w.startsWith(t));
    return { word: t, state: matches ? "partial" : "invalid" };
  });
}

// Componente Alpine raíz
function satoshiApp() {
  return {
    view: "generator",          // vista inicial
    fragmentHtml: "",
    async init() {
      await ensureWordlist();
      await this.navigate(this.view);
    },
    async navigate(view) {
      this.view = view;
      try {
        const r = await fetch(`/static/views/${view}.html`);
        if (!r.ok) throw new Error(`fragment ${view} no disponible`);
        this.fragmentHtml = await r.text();
      } catch (e) {
        this.fragmentHtml = `<p class="err-text">Error cargando vista: ${e.message}</p>`;
      }
    },
  };
}

// Exponer helpers globales para que cada vista los use sin imports
window.api = api;
window.openJobStream = openJobStream;
window.fmtBTC = fmtBTC;
window.fmtHMS = fmtHMS;
window.validateMnemonicWords = validateMnemonicWords;
window.satoshiApp = satoshiApp;
```

- [ ] **Step 2: Verificación: el shell se monta con sidebar y outlet vacío (las vistas aún no existen)**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -m uvicorn satoshi_tool.web.app:app --host 127.0.0.1 --port 8765 --log-level warning &
sleep 1
curl -s http://127.0.0.1:8765/static/app.js | head -3
curl -s http://127.0.0.1:8765/ | head -3
pkill -f "uvicorn satoshi_tool.web.app:app"
```
Expected: app.js servido sin error, index.html con la shell.

(La verificación visual con Chrome/Safari muestra el sidebar pintado pero el outlet con "Error cargando vista" — esperado hasta que existan las vistas.)

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/app.js
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): app.js con Alpine router, helpers API y consumidor SSE"
```

---

## Task 5: Vista Generador + wordlist BIP-39 para validación

**Files:**
- Create: `satoshi_tool/web/static/views/generator.html`
- Create: `satoshi_tool/web/static/bip39-en.json` (lista de 2048 palabras, generada con Python)

- [ ] **Step 1: Generar `bip39-en.json` con Python desde el wordlist de la lib `mnemonic`**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -c "
import json
from mnemonic import Mnemonic
with open('satoshi_tool/web/static/bip39-en.json', 'w', encoding='utf-8') as f:
    json.dump(Mnemonic('english').wordlist, f)
print('ok:', len(Mnemonic('english').wordlist), 'palabras')
"
```
Expected: `ok: 2048 palabras`.

- [ ] **Step 2: Crear `views/generator.html` con UI del Generador de Semillas**

```html
<div x-data="generatorView()">
  <h1>// GENERATOR_MODE</h1>
  <p class="subtitle">Crea una nueva mnemónica BIP-39 (nada se guarda en disco).</p>

  <div class="panel">
    <span class="label">Longitud</span>
    <div style="display:flex; gap:8px; align-items:center;">
      <select x-model="words" style="width:auto">
        <option value="12">12 palabras</option>
        <option value="24">24 palabras</option>
      </select>
      <button @click="generate()" :disabled="loading">
        <span x-show="!loading">Generar</span>
        <span x-show="loading">Generando...</span>
      </button>
    </div>
  </div>

  <template x-if="result">
    <div>
      <div class="panel">
        <h3 class="panel-title">Mnemónica</h3>
        <div class="word-grid">
          <template x-for="w in result.words" :key="w + Math.random()">
            <div class="word valid" x-text="w"></div>
          </template>
        </div>
        <button class="ghost" @click="copy(result.mnemonic)" style="margin-top:6px">
          Copiar mnemónica
        </button>
        <span x-show="copied" class="ok-text mono" style="margin-left:8px; font-size:11px">copiado</span>
      </div>
      <div class="panel">
        <h3 class="panel-title">⚠ Aviso</h3>
        <p class="subtitle" style="margin-bottom:0">
          Esta mnemónica NO se guarda en disco. Cópiala antes de cerrar esta vista o se perderá.
          Si la usas para fondos reales, guárdala en un lugar seguro.
        </p>
      </div>
    </div>
  </template>

  <template x-if="error">
    <div class="panel" style="border-color: var(--err)">
      <span class="err-text mono" x-text="error"></span>
    </div>
  </template>
</div>

<script>
function generatorView() {
  return {
    words: 12,
    result: null,
    loading: false,
    error: "",
    copied: false,
    async generate() {
      this.loading = true;
      this.error = "";
      this.result = null;
      try {
        this.result = await api.post("/api/generator", { words: parseInt(this.words) });
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
    copy(text) {
      navigator.clipboard.writeText(text).then(() => {
        this.copied = true;
        setTimeout(() => { this.copied = false; }, 1500);
      });
    },
  };
}
</script>
```

- [ ] **Step 3: Verificación manual con uvicorn**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -m uvicorn satoshi_tool.web.app:app --host 127.0.0.1 --port 8765 --log-level warning &
sleep 1
curl -s http://127.0.0.1:8765/static/views/generator.html | head -3
curl -s http://127.0.0.1:8765/static/bip39-en.json | python3 -c "import sys, json; print('words:', len(json.load(sys.stdin)))"
pkill -f "uvicorn satoshi_tool.web.app:app"
```
Expected: fragment generator.html servido, bip39-en.json con 2048 palabras.

(Abrir `http://127.0.0.1:8765/` en Chrome → seleccionar "Generador" en sidebar → click "Generar" → ver mnemónica formada por 12 palabras y botón copiar.)

- [ ] **Step 4: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/views/generator.html satoshi_tool/web/static/bip39-en.json
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): vista Generador + wordlist BIP-39 inglés para validación local"
```

---

## Task 6: Componente reutilizable "dashboard live" — KPIs + lista de eventos

**Files:**
- Modify: `satoshi_tool/web/static/app.js` (añadir helper de dashboard)

Este componente se usa en Auto, Manual full, Hunter y Passphrase. Lo definimos como función factory que devuelve un Alpine component con state y métodos comunes.

- [ ] **Step 1: Añadir al final de `app.js` la fábrica `jobDashboard()`**

```javascript
// Componente reutilizable de dashboard live para jobs largos
function jobDashboard() {
  return {
    running: false,
    jobId: null,
    kpi: {},
    events: [],     // últimos N eventos relevantes (used/error)
    hit: null,
    eventSource: null,
    error: "",

    startJob(jobId) {
      this.running = true;
      this.jobId = jobId;
      this.kpi = {};
      this.events = [];
      this.hit = null;
      this.error = "";

      this.eventSource = openJobStream(jobId, {
        kpi: (p) => { this.kpi = p; },
        addr: (p) => {
          this.events.unshift(p);
          if (this.events.length > 50) this.events.pop();
        },
        hit: (p) => {
          this.hit = p;
        },
        done: (p) => {
          this.running = false;
          if (p && p.totals) this.kpi = { ...this.kpi, ...p.totals };
        },
        cancelled: () => {
          this.running = false;
        },
        error: (p) => {
          this.running = false;
          this.error = p.message || "error desconocido";
        },
        connectionLost: () => {
          this.running = false;
          this.error = "conexión perdida con el job";
        },
      });
    },

    async stop() {
      if (!this.jobId) return;
      try {
        await api.post(`/api/jobs/${this.jobId}/cancel`, {});
      } catch (e) {
        this.error = e.message;
      }
    },

    reset() {
      if (this.eventSource) this.eventSource.close();
      this.running = false;
      this.jobId = null;
      this.kpi = {};
      this.events = [];
      this.hit = null;
      this.error = "";
    },
  };
}
window.jobDashboard = jobDashboard;
```

- [ ] **Step 2: Verificación de sintaxis (sin browser todavía)**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -m uvicorn satoshi_tool.web.app:app --host 127.0.0.1 --port 8765 --log-level warning &
sleep 1
curl -s http://127.0.0.1:8765/static/app.js | grep -c "jobDashboard"
pkill -f "uvicorn satoshi_tool.web.app:app"
```
Expected: al menos 2 (una en la función, otra en `window.jobDashboard`).

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/app.js
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): jobDashboard component reutilizable para vistas con SSE"
```

---

## Task 7: Vista Manual con validación en vivo de mnemónica

**Files:**
- Create: `satoshi_tool/web/static/views/manual.html`

- [ ] **Step 1: Crear `views/manual.html`**

```html
<div x-data="manualView()">
  <h1>// MANUAL_MODE</h1>
  <p class="subtitle">Introduce mnemónica (12/24), xprv o WIF y consulta sus direcciones.</p>

  <div class="panel">
    <span class="label">Seed</span>
    <textarea x-model="seed" @input="updateValidation()"
              placeholder="abandon abandon abandon ... about | xprv... | L...WIF"></textarea>

    <template x-if="words.length > 0">
      <div>
        <div class="word-grid">
          <template x-for="w in words" :key="w.idx">
            <div class="word" :class="w.state" x-text="w.word"></div>
          </template>
        </div>
        <span class="mono" style="font-size:10px"
              :class="checksumOk ? 'ok-text' : 'muted'"
              x-text="checksumLabel"></span>
      </div>
    </template>
  </div>

  <div class="panel" x-show="isMnemonic">
    <span class="label">Passphrase BIP-39 (opcional)</span>
    <input type="text" x-model="passphrase" placeholder="(vacío por defecto)">
  </div>

  <div class="panel">
    <span class="label">Tipo de escaneo</span>
    <div style="display:flex; gap:12px; align-items:center;">
      <label class="mono" style="font-size:11px; cursor:pointer">
        <input type="radio" x-model="mode" value="quick" style="width:auto; margin-right:4px">
        Rápido (m/.../0/0)
      </label>
      <label class="mono" style="font-size:11px; cursor:pointer">
        <input type="radio" x-model="mode" value="full" style="width:auto; margin-right:4px">
        Completo (gap limit 20)
      </label>
    </div>
  </div>

  <div style="display:flex; gap:8px; align-items:center; margin-bottom:12px;">
    <button @click="run()" :disabled="loading || dash.running">
      <span x-show="!loading && !dash.running">Derivar</span>
      <span x-show="loading">Consultando...</span>
      <span x-show="dash.running">Escaneando...</span>
    </button>
    <button class="danger" x-show="dash.running" @click="dash.stop()">Stop</button>
  </div>

  <template x-if="quickResults">
    <div>
      <h2>Resultados (quick scan)</h2>
      <template x-for="d in quickResults.derivations" :key="d.purpose">
        <div class="panel">
          <h3 class="panel-title">BIP<span x-text="d.purpose"></span></h3>
          <template x-if="d.ok">
            <div>
              <div class="row">
                <span class="ad mono" x-text="d.address"></span>
                <span class="mono" x-text="fmtBTC(d.total_sats)"></span>
              </div>
              <div class="row">
                <span class="muted mono">path: <span x-text="d.path"></span></span>
                <span><span class="tag" :class="d.ever_received ? 'ok' : 'warn'"
                       x-text="d.ever_received ? 'usada' : 'vacía'"></span></span>
              </div>
            </div>
          </template>
          <template x-if="!d.ok">
            <span class="err-text mono" x-text="d.error"></span>
          </template>
        </div>
      </template>
    </div>
  </template>

  <template x-if="dash.running || dash.events.length || dash.hit">
    <div>
      <h2>Escaneo completo</h2>
      <div class="kpi-grid">
        <div class="kpi"><div class="kpi-lbl">Tested</div><div class="kpi-val" x-text="dash.kpi.tested || 0"></div></div>
        <div class="kpi ok"><div class="kpi-lbl">Hits</div><div class="kpi-val" x-text="dash.kpi.hits || 0"></div></div>
        <div class="kpi err"><div class="kpi-lbl">Errors</div><div class="kpi-val" x-text="dash.kpi.errors || 0"></div></div>
      </div>

      <template x-if="dash.hit">
        <div class="hit-banner">
          <h3>★ HIT ENCONTRADO</h3>
          <div class="mono"><strong>address:</strong> <span x-text="dash.hit.address"></span></div>
          <div class="mono"><strong>path:</strong> <span x-text="dash.hit.path || '(?)'"></span></div>
          <div class="mono"><strong>saldo:</strong> <span x-text="fmtBTC((dash.hit.act && dash.hit.act.total) || 0)"></span></div>
        </div>
      </template>

      <div class="panel">
        <h3 class="panel-title">Direcciones con actividad o errores</h3>
        <template x-if="dash.events.length === 0">
          <p class="muted mono" style="font-size:11px">(esperando eventos…)</p>
        </template>
        <template x-for="(e, i) in dash.events" :key="i">
          <div class="row pulse">
            <span class="ad mono" x-text="`${e.purpose ? 'BIP'+e.purpose+' ' : ''}${e.change===1?'int':'ext'}/${e.index} ${e.address}`"></span>
            <span>
              <span x-show="e.status === 'used'" class="tag ok mono" x-text="fmtBTC(e.total_sats || 0)"></span>
              <span x-show="e.status === 'error'" class="tag err">error</span>
            </span>
          </div>
        </template>
      </div>
    </div>
  </template>

  <template x-if="error">
    <div class="panel" style="border-color: var(--err)">
      <span class="err-text mono" x-text="error"></span>
    </div>
  </template>
</div>

<script>
function manualView() {
  return {
    seed: "",
    passphrase: "",
    mode: "quick",
    words: [],
    checksumOk: false,
    checksumLabel: "",
    loading: false,
    quickResults: null,
    error: "",
    dash: jobDashboard(),

    get isMnemonic() {
      const s = this.seed.trim();
      if (s.startsWith("xprv")) return false;
      if ((s.length === 51 || s.length === 52) && "5KL".includes(s[0])) return false;
      return true;
    },

    updateValidation() {
      if (!this.isMnemonic) {
        this.words = [];
        this.checksumLabel = "";
        return;
      }
      const parsed = validateMnemonicWords(this.seed);
      this.words = parsed.map((p, i) => ({ ...p, idx: i }));
      const allValid = parsed.length > 0 && parsed.every(p => p.state === "valid");
      const len = parsed.length;
      if (allValid && (len === 12 || len === 24)) {
        this.checksumLabel = `${len} palabras válidas — checksum se valida al derivar`;
        this.checksumOk = true;
      } else if (len > 0) {
        this.checksumLabel = `${len} palabras (necesita 12 o 24, todas en el wordlist BIP-39)`;
        this.checksumOk = false;
      } else {
        this.checksumLabel = "";
        this.checksumOk = false;
      }
    },

    async run() {
      this.error = "";
      this.quickResults = null;
      this.dash.reset();
      if (!this.seed.trim()) {
        this.error = "Introduce una seed.";
        return;
      }
      if (this.mode === "quick") {
        this.loading = true;
        try {
          this.quickResults = await api.post("/api/manual/quick", {
            seed: this.seed.trim(),
            passphrase: this.isMnemonic ? this.passphrase : "",
          });
        } catch (e) {
          this.error = e.message;
        } finally {
          this.loading = false;
        }
      } else {
        try {
          const { job_id } = await api.post("/api/manual/full", {
            seed: this.seed.trim(),
            passphrase: this.isMnemonic ? this.passphrase : "",
            gap_limit: 20,
          });
          this.dash.startJob(job_id);
        } catch (e) {
          this.error = e.message;
        }
      }
    },
  };
}
</script>
```

- [ ] **Step 2: Verificación**

Arranca uvicorn, abre el navegador en `http://127.0.0.1:8765`, navega a "Manual", pega la mnemónica de test pública `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`. Verifica que las 12 palabras se ven con borde verde (state=valid), el label dice "12 palabras válidas". Pulsa "Derivar" en modo Rápido. Deben aparecer 4 paneles BIP44/49/84/86 con las direcciones públicas conocidas marcadas como "usada".

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/views/manual.html
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): vista Manual con validación en vivo + escaneo quick/full"
```

---

## Task 8: Vista Histórico (tabla con filtros)

**Files:**
- Create: `satoshi_tool/web/static/views/history.html`

- [ ] **Step 1: Crear `views/history.html`**

```html
<div x-data="historyView()" x-init="load()">
  <h1>// HISTORY</h1>
  <p class="subtitle">Hits guardados en Passphrases_Cazadas.txt y Semillas_Cazadas.txt.</p>

  <div class="panel">
    <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap">
      <label class="mono" style="font-size:11px">
        modo:
        <select x-model="mode" @change="load()" style="width:auto; margin-left:6px">
          <option value="">todos</option>
          <option value="seed">seed</option>
          <option value="passphrase">passphrase</option>
        </select>
      </label>
      <label class="mono" style="font-size:11px; cursor:pointer">
        <input type="checkbox" x-model="withBalance" @change="load()" style="width:auto; margin-right:4px">
        sólo con saldo &gt; 0
      </label>
      <button class="ghost" @click="load()">Refrescar</button>
      <span class="mono muted" style="font-size:11px"
            x-text="`${hits.length} hits`"></span>
    </div>
  </div>

  <template x-if="loading">
    <p class="muted mono">cargando…</p>
  </template>

  <template x-if="!loading && hits.length === 0">
    <div class="panel">
      <p class="muted mono" style="font-size:11px; margin:0">
        No hay hits guardados todavía. Cuando algún modo encuentre actividad on-chain,
        se guarda automáticamente y aparece aquí.
      </p>
    </div>
  </template>

  <template x-if="!loading && hits.length > 0">
    <div>
      <template x-for="(h, i) in hits" :key="i">
        <div class="panel">
          <div class="row">
            <span class="mono">
              <span class="tag" :class="h.mode === 'seed' ? 'ok' : 'warn'" x-text="h.mode"></span>
              <span class="muted" x-text="fmtDate(h.timestamp)"></span>
            </span>
            <span class="mono" x-text="fmtBTC(h.total_sats || 0)"></span>
          </div>
          <div class="row">
            <span class="ad mono" x-text="h.address"></span>
            <span class="mono muted" x-text="h.path"></span>
          </div>
          <div class="row">
            <button class="ghost" @click="h._reveal = !h._reveal"
                    x-text="h._reveal ? 'ocultar' : 'revelar datos sensibles'"
                    style="font-size:10px; padding:4px 8px"></button>
          </div>
          <template x-if="h._reveal">
            <div>
              <div class="row">
                <span class="muted mono">mnemonic:</span>
                <span class="mono" style="word-break:break-all" x-text="h.mnemonic || h.seed || '—'"></span>
              </div>
              <template x-if="h.passphrase">
                <div class="row">
                  <span class="muted mono">passphrase:</span>
                  <span class="mono" x-text="h.passphrase"></span>
                </div>
              </template>
            </div>
          </template>
        </div>
      </template>
    </div>
  </template>

  <template x-if="error">
    <div class="panel" style="border-color: var(--err)">
      <span class="err-text mono" x-text="error"></span>
    </div>
  </template>
</div>

<script>
function historyView() {
  return {
    hits: [],
    mode: "",
    withBalance: false,
    loading: false,
    error: "",
    async load() {
      this.loading = true;
      this.error = "";
      try {
        const params = new URLSearchParams();
        if (this.mode) params.set("mode", this.mode);
        if (this.withBalance) params.set("with_balance", "true");
        const r = await api.get(`/api/history?${params}`);
        this.hits = (r.hits || []).map(h => ({ ...h, _reveal: false }))
                                  .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
    fmtDate(ts) {
      if (!ts) return "(sin fecha)";
      const d = new Date(ts * 1000);
      return d.toISOString().replace("T", " ").substring(0, 19);
    },
  };
}
</script>
```

- [ ] **Step 2: Verificación**

Abre la web → click "Histórico". Si tienes hits en los .txt (el del test E2E del Plan #1 está, por ejemplo), aparecen en orden descendente por fecha, con botón "revelar datos sensibles" oculto por defecto. Cambia filtro a "passphrase" → se reduce la lista. Marca "sólo con saldo > 0" → si no hay ninguno, queda vacía.

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/views/history.html
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): vista Histórico con filtros y revelado de datos sensibles"
```

---

## Task 9: Vista Auto

**Files:**
- Create: `satoshi_tool/web/static/views/auto.html`

- [ ] **Step 1: Crear `views/auto.html`**

```html
<div x-data="autoView()">
  <h1>// AUTO_MODE</h1>
  <p class="subtitle">
    Genera mnemónicas aleatorias y comprueba si tienen actividad on-chain.
    Educativo — la probabilidad de hit es astronómicamente baja.
  </p>

  <div class="panel">
    <div style="display:flex; gap:8px; align-items:center;">
      <button @click="start()" :disabled="dash.running">
        <span x-show="!dash.running">Scan</span>
        <span x-show="dash.running">Escaneando…</span>
      </button>
      <button class="danger" x-show="dash.running" @click="dash.stop()">Stop</button>
    </div>
  </div>

  <template x-if="dash.running || dash.events.length || dash.hit || dash.kpi.seeds">
    <div>
      <div class="kpi-grid">
        <div class="kpi neutral"><div class="kpi-lbl">Seeds</div><div class="kpi-val" x-text="dash.kpi.seeds || 0"></div></div>
        <div class="kpi neutral"><div class="kpi-lbl">Addrs</div><div class="kpi-val" x-text="dash.kpi.addresses_checked || 0"></div></div>
        <div class="kpi ok"><div class="kpi-lbl">Hits</div><div class="kpi-val" x-text="dash.kpi.hits || 0"></div></div>
      </div>

      <template x-if="dash.hit">
        <div class="hit-banner">
          <h3>★ HIT ENCONTRADO</h3>
          <div class="mono"><strong>mnemonic:</strong> <span style="word-break:break-all" x-text="dash.hit.mnemonic"></span></div>
          <div class="mono"><strong>address:</strong> <span x-text="dash.hit.address"></span></div>
          <div class="mono"><strong>path:</strong> <span x-text="dash.hit.path"></span></div>
          <div class="mono"><strong>saldo:</strong> <span x-text="fmtBTC((dash.hit.act && dash.hit.act.total) || 0)"></span></div>
        </div>
      </template>
    </div>
  </template>

  <template x-if="dash.error">
    <div class="panel" style="border-color: var(--err)">
      <span class="err-text mono" x-text="dash.error"></span>
    </div>
  </template>
</div>

<script>
function autoView() {
  return {
    dash: jobDashboard(),
    async start() {
      this.dash.reset();
      try {
        const { job_id } = await api.post("/api/auto/start", {});
        this.dash.startJob(job_id);
      } catch (e) {
        this.dash.error = e.message;
      }
    },
  };
}
</script>
```

- [ ] **Step 2: Verificación**

Abre la web → click "Auto" → click "Scan". KPIs (Seeds, Addrs, Hits) actualizan en vivo. Click "Stop" → el job para limpiamente. No esperes ningún hit (probabilidad ~0).

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/views/auto.html
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): vista Auto con dashboard live"
```

---

## Task 10: Vista Hunter (con preview de combinaciones)

**Files:**
- Create: `satoshi_tool/web/static/views/hunter.html`

- [ ] **Step 1: Crear `views/hunter.html`**

```html
<div x-data="hunterView()">
  <h1>// SEED_HUNTER</h1>
  <p class="subtitle">Recupera mnemónicas con palabras desconocidas usando una máscara.</p>

  <div class="panel">
    <span class="label">Máscara (12 o 24 tokens)</span>
    <textarea x-model="mask" @input="estimate()"
              placeholder="palabra | ? (desconocida) | pre* (prefijo)"></textarea>
    <p class="mono muted" style="font-size:10px; margin:6px 0 0">
      Ejemplo: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?`
      <br>Combinaciones estimadas: <span class="ok-text" x-text="combos || '—'"></span>
    </p>
  </div>

  <div class="panel">
    <span class="label">Dirección objetivo (opcional)</span>
    <input type="text" x-model="target" placeholder="bc1... / 3... / 1... (vacío = busca actividad on-chain)">
  </div>

  <div class="panel">
    <span class="label">Passphrase BIP-39 (opcional)</span>
    <input type="text" x-model="passphrase">
  </div>

  <div class="panel">
    <span class="label">Purpose</span>
    <select x-model="purpose" style="width:auto">
      <option value="44">BIP44 — 1...</option>
      <option value="49">BIP49 — 3...</option>
      <option value="84">BIP84 — bc1q...</option>
      <option value="86">BIP86 — bc1p...</option>
    </select>
  </div>

  <div style="display:flex; gap:8px; align-items:center; margin-bottom:12px;">
    <button @click="start()" :disabled="dash.running || !mask.trim()">
      <span x-show="!dash.running">Cazar</span>
      <span x-show="dash.running">Cazando…</span>
    </button>
    <button class="danger" x-show="dash.running" @click="dash.stop()">Stop</button>
  </div>

  <template x-if="dash.running || dash.events.length || dash.hit">
    <div>
      <div class="kpi-grid">
        <div class="kpi neutral"><div class="kpi-lbl">Tested</div><div class="kpi-val" x-text="dash.kpi.tested || 0"></div></div>
        <div class="kpi neutral"><div class="kpi-lbl">Empty</div><div class="kpi-val" x-text="dash.kpi.empty || 0"></div></div>
        <div class="kpi ok"><div class="kpi-lbl">Hits</div><div class="kpi-val" x-text="dash.kpi.hits || 0"></div></div>
        <div class="kpi err"><div class="kpi-lbl">Errors</div><div class="kpi-val" x-text="dash.kpi.errors || 0"></div></div>
      </div>

      <template x-if="dash.hit">
        <div class="hit-banner">
          <h3>★ HIT ENCONTRADO</h3>
          <div class="mono"><strong>mnemonic:</strong> <span style="word-break:break-all" x-text="dash.hit.mnemonic"></span></div>
          <div class="mono"><strong>address:</strong> <span x-text="dash.hit.address"></span></div>
          <div class="mono"><strong>path:</strong> <span x-text="dash.hit.path"></span></div>
        </div>
      </template>

      <div class="panel">
        <h3 class="panel-title">Eventos relevantes</h3>
        <template x-if="dash.events.length === 0">
          <p class="muted mono" style="font-size:11px">(silencio = todo vacío hasta ahora)</p>
        </template>
        <template x-for="(e, i) in dash.events" :key="i">
          <div class="row">
            <span class="ad mono" x-text="e.address"></span>
            <span>
              <span x-show="e.status === 'used'" class="tag ok" x-text="fmtBTC(e.total_sats || 0)"></span>
              <span x-show="e.status === 'error'" class="tag err">error</span>
            </span>
          </div>
        </template>
      </div>
    </div>
  </template>
</div>

<script>
function hunterView() {
  return {
    mask: "",
    target: "",
    passphrase: "",
    purpose: "84",
    combos: null,
    dash: jobDashboard(),
    estimate() {
      const tokens = this.mask.trim().toLowerCase().split(/\s+/).filter(Boolean);
      if (![12, 24].includes(tokens.length)) { this.combos = null; return; }
      if (!WORDLIST) { this.combos = "?"; return; }
      let total = 1n;
      for (const tok of tokens) {
        if (tok === "?") total *= BigInt(WORDLIST.size);
        else if (tok.endsWith("*") && tok.length > 1) {
          const pref = tok.slice(0, -1);
          const matches = [...WORDLIST].filter(w => w.startsWith(pref)).length;
          total *= BigInt(matches || 0);
        }
        // palabras fijas: ×1
      }
      this.combos = total.toLocaleString();
    },
    async start() {
      this.dash.reset();
      try {
        const { job_id } = await api.post("/api/hunter/start", {
          mask: this.mask.trim(),
          target: this.target.trim(),
          passphrase: this.passphrase,
          purpose: parseInt(this.purpose),
        });
        this.dash.startJob(job_id);
      } catch (e) {
        this.dash.error = e.message;
      }
    },
  };
}
</script>
```

- [ ] **Step 2: Verificación**

Web → "Hunter". Máscara: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?`. Verifica que el contador de combinaciones marca `2,048`. Click "Cazar" sin target. Los KPIs deben actualizarse en vivo y aparecer hits (la mnemónica `... about` tiene actividad pública conocida).

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/views/hunter.html
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): vista Seed Hunter con preview de combinaciones y dashboard"
```

---

## Task 11: Vista Passphrase

**Files:**
- Create: `satoshi_tool/web/static/views/passphrase.html`

- [ ] **Step 1: Crear `views/passphrase.html`**

```html
<div x-data="passphraseView()">
  <h1>// PASSPHRASE_HUNTER</h1>
  <p class="subtitle">Prueba una lista de passphrases sobre una seed conocida.</p>

  <div class="panel">
    <span class="label">Seed (mnemónica / xprv / WIF)</span>
    <textarea x-model="seed"></textarea>
  </div>

  <div class="panel">
    <span class="label">Dirección objetivo (opcional)</span>
    <input type="text" x-model="target" placeholder="bc1... / 3... / 1... (vacío = busca actividad on-chain)">
  </div>

  <div class="panel">
    <span class="label">Purpose</span>
    <select x-model="purpose" style="width:auto">
      <option value="44">BIP44</option>
      <option value="49">BIP49</option>
      <option value="84">BIP84</option>
      <option value="86">BIP86</option>
    </select>
  </div>

  <div class="panel">
    <span class="label">Passphrases (una por línea)</span>
    <textarea x-model="passphrases" placeholder="passphrase-1&#10;passphrase-2&#10;..." style="min-height:120px"></textarea>
    <p class="mono muted" style="font-size:10px; margin:6px 0 0">
      <span x-text="`${passphraseList.length} passphrases a probar`"></span>
    </p>
  </div>

  <div style="display:flex; gap:8px; align-items:center; margin-bottom:12px;">
    <button @click="start()" :disabled="dash.running || passphraseList.length === 0 || !seed.trim()">
      <span x-show="!dash.running">Probar</span>
      <span x-show="dash.running">Probando…</span>
    </button>
    <button class="danger" x-show="dash.running" @click="dash.stop()">Stop</button>
  </div>

  <template x-if="dash.running || dash.hit || dash.kpi.tested">
    <div>
      <div class="kpi-grid">
        <div class="kpi neutral"><div class="kpi-lbl">Tested</div><div class="kpi-val" x-text="dash.kpi.tested || 0"></div></div>
        <div class="kpi ok"><div class="kpi-lbl">Hits</div><div class="kpi-val" x-text="dash.kpi.hits || 0"></div></div>
        <div class="kpi err"><div class="kpi-lbl">Errors</div><div class="kpi-val" x-text="dash.kpi.errors || 0"></div></div>
      </div>

      <template x-if="dash.hit">
        <div class="hit-banner">
          <h3>★ HIT ENCONTRADO</h3>
          <div class="mono"><strong>passphrase:</strong> <span x-text="dash.hit.passphrase"></span></div>
          <div class="mono"><strong>address:</strong> <span x-text="dash.hit.address"></span></div>
          <div class="mono"><strong>path:</strong> <span x-text="dash.hit.path"></span></div>
        </div>
      </template>
    </div>
  </template>
</div>

<script>
function passphraseView() {
  return {
    seed: "",
    target: "",
    purpose: "84",
    passphrases: "",
    dash: jobDashboard(),
    get passphraseList() {
      return this.passphrases.split("\n").map(s => s.trim()).filter(Boolean);
    },
    async start() {
      this.dash.reset();
      try {
        const { job_id } = await api.post("/api/passphrase/start", {
          seed: this.seed.trim(),
          target: this.target.trim(),
          purpose: parseInt(this.purpose),
          passphrases: this.passphraseList,
        });
        this.dash.startJob(job_id);
      } catch (e) {
        this.dash.error = e.message;
      }
    },
  };
}
</script>
```

- [ ] **Step 2: Verificación**

Web → "Passphrase". Pega `abandon × 11 about` como seed, mete 3 passphrases de prueba ("one", "two", "three") sin target. Click "Probar". KPIs actualizan, no debería haber hits (passphrases random aplicadas a la seed pública no producen direcciones con actividad).

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/views/passphrase.html
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): vista Passphrase Hunter con dashboard"
```

---

## Task 12: Iconos SVG (sustituir emojis del sidebar)

**Files:**
- Create: `satoshi_tool/web/static/icons/{auto,manual,passphrase,hunter,generator,history,logo}.svg`
- Modify: `satoshi_tool/web/static/index.html`

- [ ] **Step 1: Crear los 7 SVG (geométricos, monoline, en `currentColor` para heredar el color del item activo)**

`satoshi_tool/web/static/icons/auto.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <path d="M8 1 L3 9 L7 9 L6 15 L13 6 L9 6 Z"/>
</svg>
```

`satoshi_tool/web/static/icons/manual.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="7" cy="7" r="4.5"/>
  <line x1="10.5" y1="10.5" x2="14" y2="14"/>
</svg>
```

`satoshi_tool/web/static/icons/passphrase.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="6" cy="6" r="3"/>
  <line x1="8.5" y1="8.5" x2="14" y2="14"/>
  <line x1="11.5" y1="11.5" x2="13" y2="10"/>
  <line x1="13" y1="13" x2="14.5" y2="11.5"/>
</svg>
```

`satoshi_tool/web/static/icons/hunter.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="8" cy="8" r="6"/>
  <circle cx="8" cy="8" r="3"/>
  <circle cx="8" cy="8" r="1" fill="currentColor"/>
</svg>
```

`satoshi_tool/web/static/icons/generator.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <line x1="8" y1="2" x2="8" y2="14"/>
  <line x1="2" y1="8" x2="14" y2="8"/>
</svg>
```

`satoshi_tool/web/static/icons/history.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="8" cy="8" r="6"/>
  <polyline points="8,4 8,8 11,10"/>
</svg>
```

`satoshi_tool/web/static/icons/logo.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
  <polygon points="8,2 14,8 8,14 2,8"/>
  <polygon points="8,5 11,8 8,11 5,8" fill="currentColor"/>
</svg>
```

- [ ] **Step 2: Reemplazar emojis en `index.html` por `<img>` con los SVG**

Buscar y reemplazar en `satoshi_tool/web/static/index.html`:

`<span class="icon">⚡</span>` → `<img class="icon" src="/static/icons/auto.svg" alt="">`
`<span class="icon">🔍</span>` → `<img class="icon" src="/static/icons/manual.svg" alt="">`
`<span class="icon">🔑</span>` → `<img class="icon" src="/static/icons/passphrase.svg" alt="">`
`<span class="icon">🎯</span>` → `<img class="icon" src="/static/icons/hunter.svg" alt="">`
`<span class="icon">🆕</span>` → `<img class="icon" src="/static/icons/generator.svg" alt="">`
`<span class="icon">📜</span>` → `<img class="icon" src="/static/icons/history.svg" alt="">`

Y el logo (línea con `◈ SATOSHI`) se queda como texto puro — el carácter `◈` ya es estético y monoespaciado.

- [ ] **Step 3: Modificar regla CSS de `.icon` en `theme.css` para que los SVG hereden el color y se vean nítidos**

Añadir al final de `theme.css`:

```css
.sidebar .nav-item .icon { width: 14px; height: 14px; flex-shrink: 0; }
img.icon { filter: brightness(0) saturate(100%) invert(72%) sepia(20%) saturate(465%) hue-rotate(160deg); }
.sidebar .nav-item.active img.icon { filter: brightness(0) saturate(100%) invert(76%) sepia(46%) saturate(2186%) hue-rotate(345deg); }
```

(Los filtros CSS recolorean los SVG: el primero los pinta gris azulado del `--text-2`, el activo los pinta naranja `--accent`. Hack común para SVG monoline.)

- [ ] **Step 4: Verificación visual** — la sidebar muestra los SVG en gris azulado, y el item activo en naranja con glow.

- [ ] **Step 5: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/icons/ satoshi_tool/web/static/index.html satoshi_tool/web/static/theme.css
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): iconos SVG monoline sustituyen a emojis en el sidebar"
```

---

## Task 13: Animaciones finales — fade-in al cambiar vista, pulse en hits

**Files:**
- Modify: `satoshi_tool/web/static/app.js` (refrescar fade-in al navegar)

Las animaciones ya están definidas en `theme.css` (T2). Falta asegurar que se disparan al cambiar de vista. Alpine no re-aplica clases automáticamente cuando cambia `x-html`; añadimos `:key` y reinicializamos.

- [ ] **Step 1: Modificar `navigate` para forzar reaplicación de la animación**

En `app.js`, sustituir la función `navigate` dentro de `satoshiApp()` por:

```javascript
async navigate(view) {
  this.view = view;
  this.fragmentHtml = "";  // limpia primero para que el fade-in se re-dispare
  await new Promise(r => requestAnimationFrame(r));
  try {
    const r = await fetch(`/static/views/${view}.html`);
    if (!r.ok) throw new Error(`fragment ${view} no disponible`);
    this.fragmentHtml = await r.text();
  } catch (e) {
    this.fragmentHtml = `<p class="err-text">Error cargando vista: ${e.message}</p>`;
  }
},
```

- [ ] **Step 2: Verificación visual** — al cambiar entre items del sidebar, la vista nueva entra con fade-in suave. Cuando aparece un hit (Hunter con la máscara de test BIP-39), el banner se ilumina brevemente (la clase `pulse` ya está en `theme.css`).

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/web/static/app.js
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(ui): re-disparar fade-in al navegar entre vistas"
```

---

## Task 14: PyWebView wrapper — entrypoint nuevo en `Satoshi_Tool.py`

**Files:**
- Modify: `requirements.txt`
- Modify: `Satoshi_Tool.py` (sustitución completa: pasa de shim CLI a launcher web)

- [ ] **Step 1: Añadir pywebview a `requirements.txt`**

Sustituir el contenido por:

```
mnemonic==0.20
bip_utils>=2.8.0
requests>=2.25.0
fastapi>=0.110
uvicorn[standard]>=0.27
pywebview>=5.0
pyobjc-framework-WebKit>=10.0; sys_platform == "darwin"
```

- [ ] **Step 2: Instalar deps**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -m pip install -r requirements.txt
```
Expected: instalación sin errores. PyWebView y pyobjc-framework-WebKit instalados.

- [ ] **Step 3: Sustituir `Satoshi_Tool.py` por el launcher PyWebView**

```python
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
```

- [ ] **Step 4: Verificación rápida sin lanzar la ventana — el módulo importa sin errores**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -c "import Satoshi_Tool; print('imports ok')"
```
Expected: `imports ok` sin tracebacks.

- [ ] **Step 5: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add requirements.txt Satoshi_Tool.py
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(app): Satoshi_Tool.py lanza FastAPI + ventana PyWebView con cierre limpio"
```

---

## Task 15: Verificación manual de la ventana nativa

**Files:** ninguno (solo verificación)

- [ ] **Step 1: Arrancar la app y verificar que la ventana se abre**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 Satoshi_Tool.py
```
Expected: tras ~1 segundo se abre una ventana nativa de macOS titulada "Satoshi's Tool", con el sidebar de la SPA y la vista Generador cargada por defecto.

- [ ] **Step 2: Smoke test desde la ventana**

Dentro de la ventana abierta, navegar:
- **Generador** → click "Generar" → mnemónica de 12 palabras aparece + botón copiar.
- **Manual** → pegar `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` → validación en vivo pinta las 12 palabras en verde → "Derivar" en modo rápido → 4 paneles BIP44/49/84/86 con direcciones públicas.
- **Histórico** → la tabla carga (con o sin hits, según estado de los .txt).
- **Auto** / **Hunter** / **Passphrase** → al menos el panel se renderiza correctamente.

- [ ] **Step 3: Cerrar la ventana → uvicorn debe terminar y el proceso Python salir**

Cerrar la ventana con la X. Esperado: el proceso `python3 Satoshi_Tool.py` termina en <1s, no queda colgado.

Si se queda colgado: añadir un fallback en `Satoshi_Tool.py`:

```python
# Tras webview.start() — bloquea hasta que la ventana se cierra
# Forzar exit por si el thread daemon de uvicorn no responde al should_exit:
import os
os._exit(0)
```

(Solo si es necesario; PyWebView 5+ debería gestionar bien el cierre.)

- [ ] **Step 4: Commit (solo si se hizo el ajuste)**

Si tocaste algo en Satoshi_Tool.py:

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add Satoshi_Tool.py
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "fix(app): forzar exit tras webview.start si uvicorn queda colgado"
```

Si no, no hay commit en esta tarea.

---

## Task 16: Wrapper `Satoshi.command` para doble-click en macOS

**Files:**
- Create: `Satoshi.command`

- [ ] **Step 1: Crear `Satoshi.command` en la raíz del repo**

```bash
#!/bin/bash
# Wrapper para abrir Satoshi's Tool con doble-click en macOS.
# Cambia al directorio del script y ejecuta el launcher.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
exec /usr/bin/env python3 Satoshi_Tool.py
```

- [ ] **Step 2: Hacerlo ejecutable**

```bash
chmod +x "/Users/boris/Desktop/Programación/Bitcoin/Satoshi.command"
ls -l "/Users/boris/Desktop/Programación/Bitcoin/Satoshi.command"
```
Expected: permisos `-rwxr-xr-x`.

- [ ] **Step 3: Verificación: doble-click en Finder lo lanza**

(Manual, en macOS Finder.) Doble-click sobre `Satoshi.command` en el repo. Debe abrirse una ventana de Terminal momentáneamente y luego la ventana nativa de Satoshi's Tool. Cerrarla termina ambas.

Si la primera vez macOS bloquea "no se puede verificar el desarrollador": click derecho → Abrir → Abrir igualmente. Una vez confirmado, las siguientes ejecuciones van sin friction.

- [ ] **Step 4: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add Satoshi.command
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "feat(app): wrapper Satoshi.command para doble-click en macOS"
```

---

## Task 17: Verificación end-to-end con suite de tests

**Files:** ninguno

- [ ] **Step 1: Verificar que la suite completa sigue verde**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -m pytest -v 2>&1 | tail -10
```
Expected: 45 passed (mismo número que cerrando el Plan #1; no añadimos tests en el Plan #2 porque el frontend no se testea en MVP).

- [ ] **Step 2: Verificar que el CLI viejo headless sigue funcionando**

```bash
echo "Q" | python3 -m satoshi_tool.cli 2>&1 | tail -3
```
Expected: banner + menú + "Hasta luego 👋", sin tracebacks.

(El entrypoint `python3 Satoshi_Tool.py` ahora abre la ventana web; el CLI clásico queda en `python3 -m satoshi_tool.cli` para uso headless.)

- [ ] **Step 3: No hay commit en esta tarea** (solo verificación).

---

## Task 18: Limpieza final y bump de versión

**Files:**
- Modify: `satoshi_tool/__init__.py`
- Modify: `satoshi_tool/web/app.py` (la versión en `health` y FastAPI)

- [ ] **Step 1: Bump versión a `0.5.0` (Plan #2 cerrado — app web funcional)**

`satoshi_tool/__init__.py`:

```python
"""Satoshi's Tool — utilidades BIP-39 / HD para Bitcoin mainnet."""

__version__ = "0.5.0"
```

Y en `satoshi_tool/web/app.py`, sustituir las dos cadenas `"0.4.1"` por `"0.5.0"`:

```python
def create_app() -> FastAPI:
    app = FastAPI(
        title="Satoshi's Tool",
        version="0.5.0",
        description="API local para BIP-39 / HD Bitcoin (mainnet).",
    )

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.5.0"}
    ...
```

- [ ] **Step 2: Verificación**

```bash
cd "/Users/boris/Desktop/Programación/Bitcoin"
python3 -c "import satoshi_tool; print(satoshi_tool.__version__)"
python3 -m pytest tests/test_api.py::test_health_returns_ok -v
```
Expected: `0.5.0` y test pasando con la versión actualizada.

(El test `test_health_returns_ok` no asserta versión específica, sólo que existe — sigue verde.)

- [ ] **Step 3: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add satoshi_tool/__init__.py satoshi_tool/web/app.py
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "chore: bump version a 0.5.0 (Plan #2 — app web nativa funcional)"
```

---

## Task 19: README completo del proyecto

**Files:**
- Modify: `README.txt` → renombrar y reescribir como `README.md`
- Delete: `README.txt` (después de migrar contenido)

- [ ] **Step 1: Crear `README.md` con instrucciones del modelo B-bis (código en GitHub, app personal)**

```markdown
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
git clone https://github.com/<tu-usuario>/satoshis-tool.git
cd satoshis-tool
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
```

- [ ] **Step 2: Eliminar el viejo `README.txt`**

```bash
rm "/Users/boris/Desktop/Programación/Bitcoin/README.txt"
```

- [ ] **Step 3: Verificar que `README.md` está bien y `README.txt` no existe**

```bash
ls -la "/Users/boris/Desktop/Programación/Bitcoin/" | grep -E "README"
```
Expected: solo `README.md`.

- [ ] **Step 4: Commit**

```bash
git -C "/Users/boris/Desktop/Programación/Bitcoin" add README.md
git -C "/Users/boris/Desktop/Programación/Bitcoin" rm README.txt
git -C "/Users/boris/Desktop/Programación/Bitcoin" commit -m "docs: README.md completo con instalación, uso, arquitectura y disclaimer"
```

---

## Self-review

Revisión final del plan contra el spec:

**1. Spec coverage:**

- §6 UI/UX (sidebar 6 ítems): cubierto en T3, T12.
- §6 Comportamiento por modo (Auto, Manual, Passphrase, Hunter, Generador, Histórico): T5, T7, T8, T9, T10, T11.
- §6 Design tokens (paleta neón, tipografía mono para datos, esquinas, animaciones): T2.
- §6 Decisiones UX (validación en vivo, STOP, sin alertas modales, paste de mnemónicas): cubierto en T4 (validateMnemonicWords), T6 (jobDashboard.stop), T7-T11 (paneles inline en lugar de alerts), T7 (`@input="updateValidation()"` normaliza la textarea).
- §7 API/SSE: ya cubierto en Plan #1; el frontend la consume vía T4 (helpers), T6 (jobDashboard).
- §9 hito 4.4 (frontend SPA): T1-T13.
- §9 hito 4.5 (PyWebView wrapper): T14, T15, T16.
- §9 hito 4.6 (pulido + README): T13 (animaciones), T17 (verificación), T18 (versión), T19 (README).

Gap revisado: el spec §6 menciona "sonido suave del sistema" al hit de Auto/Manual. No lo implementé explícitamente porque el comportamiento por navegador varía mucho y rompería el ambiente sobrio de la estética. Lo dejo como mejora opcional fuera de scope de este plan.

**2. Placeholder scan:** revisé y no hay TBD/TODO/"implement later"/"add appropriate error handling" en ningún paso. Todos los pasos tienen código o comando concreto.

**3. Type consistency:**

- `jobDashboard()` (T6): expone `running`, `jobId`, `kpi`, `events`, `hit`, `error`, `startJob`, `stop`, `reset`. Coherente en T7, T9, T10, T11.
- `api.get`/`api.post` (T4): firma `(url) → Promise` y `(url, body) → Promise`. Coherente en T5, T7, T8, T9, T10, T11.
- `openJobStream(jobId, handlers)` (T4): handlers reciben payload directo. Coherente con cómo el backend del Plan #1 emite eventos (T13 de Plan #1: `JobEvent.as_dict()` devuelve `{type, payload, timestamp}`).
- `fmtBTC(sats)` y `fmtHMS(s)`: definidos en T4, usados en T7, T9.
- `WORDLIST` (Set en T5, usado en T4 `validateMnemonicWords` y T10 `estimate`).

Todo consistente.

**4. Dependencias entre tareas:**

- T1 (StaticFiles) → necesaria para T2-T13.
- T4 (app.js base con helpers) → necesaria para T5-T11 (todas las vistas dependen de `api.*`, `fmtBTC`, `validateMnemonicWords`).
- T6 (jobDashboard) → necesaria para T7 (manual full), T9 (auto), T10 (hunter), T11 (passphrase).
- T5 (bip39-en.json) → necesaria para que `validateMnemonicWords` y `hunter.estimate()` funcionen correctamente (con fallback silencioso si no está).
- T14 (PyWebView) → independiente del frontend; solo necesita que la SPA exista en T1+T4 mínimo.
- T19 (README) → último, no depende de nada técnico.

Si el agente ejecuta en orden, no hay conflictos.

**5. Pre-condiciones globales:**

- Repo en git desde Plan #1 (rama `main`, working tree clean). ✓ Verificado al inicio de esta sesión.
- Backend del Plan #1 funcionando (45 tests verdes). ✓ Verificado.
- Python 3.9 con bip_utils, mnemonic, fastapi, uvicorn instalados. ✓ Verificado.

Sin gaps relevantes. Plan listo para ejecución.
