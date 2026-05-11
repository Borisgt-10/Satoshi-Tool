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
  };
}

// Exponer helpers globales para que cada vista los use sin imports
window.api = api;
window.openJobStream = openJobStream;
window.fmtBTC = fmtBTC;
window.fmtHMS = fmtHMS;
window.validateMnemonicWords = validateMnemonicWords;
window.satoshiApp = satoshiApp;

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