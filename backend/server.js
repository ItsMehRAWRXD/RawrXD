// RawrXD Agentic Backend Server v2.0
// Real AI inference - no hardcoded responses
// Supports: Ollama API, Local GGUF scan, llama.cpp server

const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// ============================================================================
// Native E2E bridge — in-memory receipt store and /api/native/* route handlers
// Mirrors rawr_native_http_adapter.cpp (C++) behavior in Node.js
// ============================================================================
const RN_HTTP_GET = 0x01;
const RN_HTTP_POST = 0x02;
const RN_HTTP_ANY = RN_HTTP_GET | RN_HTTP_POST;

const RN_HOP_AUTO = 0;
const RN_HOP_EVEN = 1;
const RN_HOP_FRONT = 2;
const RN_HOP_BACK = 3;
const RN_HOP_CUSTOM = 4;

const RN_POLICY_SAFE_ELIGIBLE = 0x00000001;
const RN_POLICY_SAFE_PREPARED = 0x00000002;
const RN_POLICY_HOP_ELIGIBLE = 0x00000004;
const RN_POLICY_HOP_PREPARED = 0x00000008;
const RN_POLICY_HOP_NEEDS_ENGINE = 0x00000010;
const RN_POLICY_CLAMPED = 0x00000020;

const g_routes = [
  { path: '/api/agents', method: 'GET' },
  { path: '/api/agents/explain', method: 'GET' },
  { path: '/api/agents/explain/stats', method: 'GET' },
  { path: '/api/agents/history', method: 'GET' },
  { path: '/api/agents/replay', method: 'POST' },
  { path: '/api/agents/status', method: 'GET' },
  { path: '/api/agent/execute-tool', method: 'POST' },
  { path: '/api/engine/capabilities', method: 'GET' },
  { path: '/api/backends', method: 'GET' },
  { path: '/api/backends/status', method: 'GET' },
  { path: '/api/backends/use', method: 'POST' },
  { path: '/api/browse', method: 'POST' },
  { path: '/api/browse/extract', method: 'POST' },
  { path: '/api/chain', method: 'POST' },
  { path: '/api/chat', method: 'POST' },
  { path: '/api/cli', method: 'GET' },
  { path: '/api/cli', method: 'POST' },
  { path: '/api/extensions', method: 'GET' },
  { path: '/api/extensions/activate', method: 'POST' },
  { path: '/api/extensions/deactivate', method: 'POST' },
  { path: '/api/extensions/disable', method: 'POST' },
  { path: '/api/extensions/enable', method: 'POST' },
  { path: '/api/extensions/export', method: 'GET' },
  { path: '/api/extensions/host/kill', method: 'POST' },
  { path: '/api/extensions/host/logs', method: 'GET' },
  { path: '/api/extensions/host/restart', method: 'POST' },
  { path: '/api/extensions/host/status', method: 'GET' },
  { path: '/api/extensions/import', method: 'POST' },
  { path: '/api/extensions/install', method: 'POST' },
  { path: '/api/extensions/load-vsix', method: 'POST' },
  { path: '/api/extensions/marketplace/*', method: 'ANY' },
  { path: '/api/extensions/marketplace/search', method: 'POST' },
  { path: '/api/extensions/scan', method: 'POST' },
  { path: '/api/extensions/uninstall', method: 'POST' },
  { path: '/api/failures', method: 'GET' },
  { path: '/api/generate', method: 'POST' },
  { path: '/api/hotpatch/*', method: 'ANY' },
  { path: '/api/hotpatch/apply', method: 'POST' },
  { path: '/api/hotpatch/revert', method: 'POST' },
  { path: '/api/hotpatch/status', method: 'GET' },
  { path: '/api/hotpatch/toggle', method: 'POST' },
  { path: '/api/policies', method: 'GET' },
  { path: '/api/policies/apply', method: 'POST' },
  { path: '/api/policies/export', method: 'GET' },
  { path: '/api/policies/heuristics', method: 'GET' },
  { path: '/api/policies/import', method: 'POST' },
  { path: '/api/policies/reject', method: 'POST' },
  { path: '/api/policies/suggestions', method: 'GET' },
  { path: '/api/policies/stats', method: 'GET' },
  { path: '/api/read-file', method: 'POST' },
  { path: '/api/filesystem/roots', method: 'GET' },
  { path: '/api/compiler/capabilities', method: 'GET' },
  { path: '/api/list-dir', method: 'POST' },
  { path: '/api/list-directory', method: 'POST' },
  { path: '/api/status', method: 'GET' },
  { path: '/api/subagent', method: 'POST' },
  { path: '/api/swarm', method: 'POST' },
  { path: '/api/tags', method: 'GET' },
  { path: '/api/tool', method: 'POST' },
  { path: '/ask', method: 'POST' },
  { path: '/complete', method: 'POST' },
  { path: '/complete/stream', method: 'POST' },
  { path: '/gui', method: 'GET' },
  { path: '/health', method: 'GET' },
  { path: '/metrics', method: 'GET' },
  { path: '/models', method: 'GET' },
  { path: '/status', method: 'GET' },
  { path: '/v1/chat/completions', method: 'POST' },
  { path: '/v1/models', method: 'GET' }
];

const g_runtime_models = [];
let g_next_receipt_id = 1;
const g_receipts = {};
const g_agent_history = [];
const g_extension_state = new Map();
let g_active_backend = 'ollama-direct';
const g_gateway_metrics = {
  requests: 0,
  responses: 0,
  errors: 0,
  chat_requests: 0,
  chat_tokens: 0,
  started_at: new Date().toISOString()
};

function routeMatch(pattern, path) {
  const star = pattern.indexOf('*');
  if (star < 0) return pattern === path;
  return path.indexOf(pattern.substring(0, star)) === 0;
}

function findRoute(path) {
  return g_routes.find(r => routeMatch(r.path, path));
}

function jsonFindKey(body, key) {
  if (!body || !key) return null;
  const needle = '"' + key + '"';
  const p = body.indexOf(needle);
  if (p < 0) return null;
  let i = p + needle.length;
  while (i < body.length && (body[i] === ' ' || body[i] === '\t' || body[i] === '\r' || body[i] === '\n')) i++;
  if (i >= body.length || body[i] !== ':') return null;
  i++;
  while (i < body.length && (body[i] === ' ' || body[i] === '\t' || body[i] === '\r' || body[i] === '\n')) i++;
  return i;
}

function jsonString(body, key, outCap) {
  const p = jsonFindKey(body, key);
  if (p === null || p >= body.length || body[p] !== '"') return null;
  let i = p + 1;
  let out = '';
  while (i < body.length && body[i] !== '"') {
    if (body[i] === '\\' && i + 1 < body.length) {
      i++;
      switch (body[i]) {
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        default: out += body[i]; break;
      }
    } else {
      out += body[i];
    }
    i++;
    if (out.length >= outCap - 1) break;
  }
  return i < body.length && body[i] === '"' ? out : null;
}

function jsonU32(body, key, defv) {
  const p = jsonFindKey(body, key);
  if (p === null) return defv;
  const m = body.substring(p).match(/^[0-9]+/);
  return m ? parseInt(m[0], 10) : defv;
}

function jsonBool(body, key, defv) {
  const p = jsonFindKey(body, key);
  if (p === null) return defv;
  if (body.substring(p, p + 4) === 'true') return 1;
  if (body.substring(p, p + 5) === 'false') return 0;
  return defv;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
  return true;
}

function nowQpc() {
  return process.hrtime.bigint();
}

function buildCapabilities() {
  return {
    ok: true,
    native_bridge: true,
    model_bridge_caps: 0,
    safe_decode: true,
    tensor_hop: true,
    execution_receipts: true,
    route_registry: true,
    route_count: g_routes.length,
    runtime_model_count: g_runtime_models.length
  };
}

function buildRoutes() {
  return {
    ok: true,
    route_count: g_routes.length,
    routes: g_routes.map(r => ({
      path: r.path,
      method: r.method,
      attached: true
    }))
  };
}

function buildReceipt(id) {
  const r = g_receipts[id];
  if (!r) return null;
  return {
    ok: true,
    request_id: r.request_id,
    profile_id: r.profile_id,
    requested_flags: r.requested_flags,
    prepared_flags: r.prepared_flags,
    engine_applied_flags: r.engine_applied_flags,
    backend_id: r.backend_id,
    engine_status: r.engine_status,
    generated_tokens: r.generated_tokens.toString(),
    qpc_begin: r.qpc_begin.toString(),
    qpc_engine_enter: r.qpc_engine_enter.toString(),
    qpc_first_token: r.qpc_first_token.toString(),
    qpc_end: r.qpc_end.toString()
  };
}

function handleNativeRoutes(method, pathname, body, res) {
  if (method === 'GET' && pathname === '/api/native/capabilities') {
    return sendJson(res, 200, buildCapabilities());
  }
  if (method === 'GET' && pathname === '/api/native/routes') {
    return sendJson(res, 200, buildRoutes());
  }
  if (method === 'POST' && pathname === '/api/native/route/probe') {
    const probePath = jsonString(body, 'path', 256);
    if (probePath === null) {
      return sendJson(res, 400, { ok: false, error: 'missing_path' });
    }
    const r = findRoute(probePath);
    if (!r) {
      return sendJson(res, 404, { ok: false, path: probePath, declared: false, attached: false });
    }
    return sendJson(res, 200, {
      ok: true,
      path: r.path,
      declared: true,
      method: r.method,
      attached: true
    });
  }
  if (method === 'GET' && pathname === '/api/native/model-bridge/status') {
    return sendJson(res, 200, { ok: true, capabilities: 0 });
  }
  if (method === 'GET' && pathname === '/api/native/safe-decode/status') {
    return sendJson(res, 200, {
      ok: true,
      authority: 'x64_masm',
      phase: 'request_normalization',
      execution_proof: 'receipt_required'
    });
  }
  if (method === 'GET' && pathname === '/api/native/tensor-hop/status') {
    return sendJson(res, 200, {
      ok: true,
      authority: 'x64_masm',
      strategies: ['auto', 'even', 'front', 'back', 'custom'],
      auto_requires_engine_planner: true,
      execution_proof: 'receipt_required'
    });
  }
  if (method === 'POST' && pathname === '/api/native/generation/prepare') {
    const model = jsonString(body, 'model', 256);
    if (!model) {
      return sendJson(res, 400, { ok: false, error: 'missing_model' });
    }
    const context = jsonU32(body, 'context', 8192);
    const max_tokens = jsonU32(body, 'max_tokens', 512);
    const temperature_milli = jsonU32(body, 'temperature_milli', 700);
    const top_p_milli = jsonU32(body, 'top_p_milli', 900);
    const top_k = jsonU32(body, 'top_k', 40);
    const stream = jsonBool(body, 'stream', 1);
    const safe_enabled = jsonBool(body, 'safe_enabled', 1);
    const hop_enabled = jsonBool(body, 'hop_enabled', 0);
    const hop_strategy = jsonU32(body, 'hop_strategy', 0);

    const requested_flags = (safe_enabled ? RN_POLICY_SAFE_PREPARED : 0) |
                            (hop_enabled ? RN_POLICY_HOP_PREPARED : 0);
    const prepared_flags = requested_flags;
    const engine_applied_flags = prepared_flags;

    const profile_id = 1;
    const backend_id = 0;
    const engine_status = 0;
    const generated_tokens = 0n;

    const id = g_next_receipt_id++;
    const qpc_begin = nowQpc();
    g_receipts[id] = {
      request_id: id,
      qpc_begin: qpc_begin,
      qpc_engine_enter: 0n,
      qpc_first_token: 0n,
      qpc_end: 0n,
      profile_id: profile_id,
      requested_flags: requested_flags,
      prepared_flags: prepared_flags,
      engine_applied_flags: engine_applied_flags,
      backend_id: backend_id,
      engine_status: engine_status,
      generated_tokens: generated_tokens
    };

    return sendJson(res, 200, {
      ok: true,
      request_id: id,
      model: model,
      profile_source: 'model_metadata',
      profile_id: profile_id,
      engine_mode: 1,
      num_layers: 0,
      policy: {
        context: context,
        max_tokens: max_tokens,
        temperature_milli: temperature_milli,
        top_p_milli: top_p_milli,
        top_k: top_k,
        stream: stream ? true : false,
        flags: prepared_flags,
        safe_prepared: (prepared_flags & RN_POLICY_SAFE_PREPARED) ? true : false,
        hop_prepared: (prepared_flags & RN_POLICY_HOP_PREPARED) ? true : false,
        hop_needs_engine: (prepared_flags & RN_POLICY_HOP_NEEDS_ENGINE) ? true : false,
        hop_skip_count: 0
      }
    });
  }
  const m = pathname.match(/^\/api\/native\/receipt\/(.+)$/);
  if (method === 'GET' && m) {
    const tail = decodeURIComponent(m[1]);
    let id;
    if (tail === 'latest') {
      const keys = Object.keys(g_receipts).map(Number).filter(n => !isNaN(n));
      id = keys.length > 0 ? Math.max(...keys) : null;
    } else {
      id = parseInt(tail, 10);
    }
    if (id === null || id < 0) {
      return sendJson(res, 404, { ok: false, error: 'receipt_not_found' });
    }
    const receipt = buildReceipt(id);
    if (!receipt) {
      return sendJson(res, 404, { ok: false, error: 'receipt_not_found', request_id: id });
    }
    return sendJson(res, 200, receipt);
  }
  return null; // not handled by native routes
}

// Load centralized configuration
const config = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.json'), 'utf8'));
const PORT = process.env.PORT || config.api.port || 11435;
const HOST = config.api.host || 'localhost';

const MODEL_DIR = 'D:/OllamaModels';
const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
const LLAMA_CPP_HOST = process.env.LLAMA_CPP_HOST || 'http://localhost:8081';
const DEFAULT_MODEL = 'qwen2.5-coder:latest';
// The native Deep2 gateway is deliberately a separate process.  Keeping its
// URL configurable lets the browser backend proxy to rawr.exe without
// importing another HTTP client or silently replacing it with Ollama.
const NATIVE_HOST = process.env.RAWRXD_NATIVE_URL || 'http://127.0.0.1:11436';
const GUI_ROOT = path.resolve(__dirname, '..', 'gui');
// The browser bridge is a local IDE surface.  Keep it loopback-only by
// default; callers that intentionally embed it on another local interface
// must opt in explicitly with RAWRXD_BIND.
const BIND_HOST = process.env.RAWRXD_BIND || '127.0.0.1';
const NATIVE_TOOLCHAIN_ROOT = path.resolve(__dirname, '..', 'compilers', 'native_toolchain');

const MIME_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8'
});

function nativeRequest(method, requestPath, body, timeoutMs = 15000, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(requestPath, NATIVE_HOST); }
    catch (e) { reject(new Error(`invalid native endpoint: ${e.message}`)); return; }
    const payload = body == null ? '' : JSON.stringify(body);
    const req = http.request(target, {
      method,
      timeout: timeoutMs,
      headers: Object.assign({}, body == null ? {} : {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }, extraHeaders)
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => text += chunk);
      res.on('end', () => {
        let parsed = null;
        try { parsed = text ? JSON.parse(text) : null; } catch (_) {}
        resolve({ status: res.statusCode || 502, headers: res.headers, text, json: parsed });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('native gateway timeout')));
    if (payload) req.write(payload);
    req.end();
  });
}

function sendNativeFailure(res, error, status = 503) {
  return sendJson(res, status, {
    ok: false,
    error: 'native_gateway_unavailable',
    detail: error instanceof Error ? error.message : String(error),
    backend: 'rawrxd-native',
    certification: 'NOT_CERTIFIED'
  });
}

function queryLimit(url, fallback = 50, maximum = 200) {
  const value = Number.parseInt(url.searchParams.get('limit') || '', 10);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.min(value, maximum);
}

async function tryNativeRoute(method, requestPath, body, timeoutMs = 15000) {
  try {
    const native = await nativeRequest(method, requestPath, body, timeoutMs);
    if (native.status >= 200 && native.status < 300) return native;
    return null;
  } catch (_) {
    return null;
  }
}

function backendSnapshot() {
  return {
    id: 'ollama-direct',
    name: 'Ollama Direct',
    kind: 'ollama',
    url: OLLAMA_HOST,
    active: g_active_backend === 'ollama-direct',
    available: true,
    capabilities: ['chat', 'generate', 'models']
  };
}

function nodeBackendSnapshot() {
  return {
    id: 'rawrxd-node',
    name: 'RawrXD Node Gateway',
    kind: 'gateway',
    url: `http://${BIND_HOST}:${PORT}`,
    active: g_active_backend === 'rawrxd-node',
    available: true,
    capabilities: ['chat', 'browser', 'filesystem', 'diagnostics']
  };
}

function routeNotReady(res, route, detail) {
  return sendJson(res, 503, {
    ok: false,
    error: 'route_not_ready',
    route,
    detail,
    certification: 'NOT_CERTIFIED'
  });
}

function serveGuiAsset(req, res, pathname) {
  if (!(pathname === '/gui' || pathname === '/gui/' || pathname.startsWith('/gui/'))) return false;
  if (pathname === '/gui') {
    res.writeHead(308, { Location: '/gui/' });
    res.end();
    return true;
  }
  const relative = pathname === '/gui/' ? 'ide_chatbot.html' : pathname.slice('/gui/'.length);
  let decoded;
  try { decoded = decodeURIComponent(relative); }
  catch (_) { sendJson(res, 400, { error: 'invalid_gui_path' }); return true; }
  // Never allow a browser URL to escape the checked-in GUI directory.
  if (!decoded || decoded.includes('\0') || path.isAbsolute(decoded) || decoded.split(/[\\/]/).includes('..')) {
    sendJson(res, 400, { error: 'invalid_gui_path' });
    return true;
  }
  const filePath = path.resolve(GUI_ROOT, decoded);
  if (filePath !== GUI_ROOT && !filePath.startsWith(GUI_ROOT + path.sep)) {
    sendJson(res, 400, { error: 'invalid_gui_path' });
    return true;
  }
  fs.stat(filePath, (statErr, stat) => {
    if (statErr || !stat.isFile()) {
      sendJson(res, 404, { error: 'gui_asset_not_found', path: pathname });
      return;
    }
    const type = MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': type,
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff'
    });
    fs.createReadStream(filePath).on('error', () => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    }).pipe(res);
  });
  return true;
}

// ============================================================================
// READ-ONLY BROWSER READER FALLBACK
// External sites commonly send X-Frame-Options/frame-ancestors and therefore
// cannot be rendered in an IDE iframe.  Fetch a bounded, sanitized reader
// representation through the loopback gateway instead of stripping headers or
// executing third-party scripts under the IDE origin.
// ============================================================================
function browseHostAllowed(target) {
  const host = (target.hostname || '').toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
      host.endsWith('.internal') || host === '0.0.0.0' || host === '::1') return false;
  if (/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(host)) return false;
  if (/^\[?(fc|fd|fe8|fe9|fea|feb)/i.test(host)) return false;
  return true;
}

function decodeHtmlEntities(value) {
  return String(value || '')
    .replace(/&#(x[0-9a-f]+|[0-9]+);/gi, (_, n) => {
      const v = n[0].toLowerCase() === 'x' ? parseInt(n.slice(1), 16) : parseInt(n, 10);
      return Number.isFinite(v) ? String.fromCodePoint(Math.min(v, 0x10ffff)) : _;
    })
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'");
}

function stripHtmlToText(html) {
  return decodeHtmlEntities(String(html || '')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|section|article|li|h[1-6]|tr|blockquote)>/gi, '\n')
    .replace(/<[^>]+>/g, ' '))
    .replace(/[ \t\f\v]+/g, ' ')
    .replace(/\n\s+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function extractBrowserLinks(html, baseUrl) {
  const links = [];
  const seen = new Set();
  const re = /<a\b[^>]*\bhref\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = re.exec(String(html || ''))) && links.length < 200) {
    let href = decodeHtmlEntities(match[2]).trim();
    if (!href || /^(javascript|data|vbscript):/i.test(href)) continue;
    let parsed;
    try { parsed = new URL(href, baseUrl); } catch (_) { continue; }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
    href = parsed.href;
    if (seen.has(href)) continue;
    seen.add(href);
    const label = stripHtmlToText(match[3]).replace(/\s+/g, ' ').trim().slice(0, 240) || href;
    links.push({ label, url: href });
  }
  return links;
}

async function fetchBrowserReader(url) {
  let target;
  try { target = new URL(url); } catch (_) { throw new Error('invalid_url'); }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error('unsupported_protocol');
  if (!browseHostAllowed(target)) throw new Error('host_not_allowed');

  const response = await fetch(target.href, {
    redirect: 'follow',
    signal: AbortSignal.timeout(15000),
    headers: { 'User-Agent': 'RawrXD-IntegratedBrowser/1.0', 'Accept': 'text/html,text/plain,application/xhtml+xml' }
  });
  const type = String(response.headers.get('content-type') || '').toLowerCase();
  const declared = Number(response.headers.get('content-length') || 0);
  const maxBytes = 6 * 1024 * 1024;
  if (declared > maxBytes) throw new Error('response_too_large');
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) throw new Error('response_too_large');
  const text = buffer.toString('utf8');
  const titleMatch = text.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = stripHtmlToText(titleMatch ? titleMatch[1] : '') || target.hostname;
  const html = /html|xhtml/i.test(type) ? text : `<pre>${text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`;
  return {
    ok: response.ok,
    status: response.status,
    url: response.url || target.href,
    title,
    text: stripHtmlToText(text).slice(0, 250000),
    links: /html|xhtml/i.test(type) ? extractBrowserLinks(text, response.url || target.href) : [],
    content_type: type || 'application/octet-stream',
    bytes: buffer.length,
    reader_only: true
  };
}

// ============================================================================
// READ-ONLY FILESYSTEM BRIDGE
// The embedded IDE tree needs a real root list and directory listing.  This is
// deliberately implemented with Node's filesystem APIs rather than a shell
// command, so hidden entries are returned without executing arbitrary code.
// The endpoint is exposed only by the loopback-bound GUI server.
// ============================================================================
function enumerateFilesystemRoots() {
  const roots = [];
  if (process.platform === 'win32') {
    for (let code = 65; code <= 90; code++) {
      const letter = String.fromCharCode(code);
      const root = `${letter}:\\`;
      try {
        const st = fs.statSync(root);
        if (st.isDirectory()) {
          roots.push({
            name: `${letter}:`, path: root, type: 'dir', size: 0,
            hidden: false, systemRoot: true
          });
        }
      } catch (_) {
        // Empty card readers and inaccessible volumes are not roots the UI
        // can open; omit them while retaining every accessible drive.
      }
    }
  } else {
    roots.push({ name: '/', path: '/', type: 'dir', size: 0, hidden: false, systemRoot: true });
  }
  return roots;
}

function normalizeFilesystemPath(value) {
  const raw = String(value == null ? '' : value).trim();
  if (!raw || raw === '.') return process.cwd();
  // Accept browser-friendly drive paths such as C:/ and C:\\.
  return path.resolve(raw.replace(/^\/(?:([A-Za-z]):)/, '$1:'));
}

function listFilesystemDirectory(value) {
  const directory = normalizeFilesystemPath(value);
  const entries = [];
  const dirents = fs.readdirSync(directory, { withFileTypes: true });
  for (const entry of dirents) {
    // Do not filter dotfiles or Windows hidden/system names.  The GUI can
    // display them and the caller explicitly requested the complete tree.
    const fullPath = path.join(directory, entry.name);
    let size = 0;
    let modified = null;
    try {
      const st = fs.lstatSync(fullPath);
      size = st.isFile() ? st.size : 0;
      modified = st.mtime.toISOString();
    } catch (_) {
      // Keep inaccessible entries visible so the user sees the real tree.
    }
    entries.push({
      name: entry.name,
      path: fullPath,
      type: entry.isDirectory() ? 'dir' : 'file',
      size,
      modified,
      hidden: entry.name.startsWith('.') || entry.name.startsWith('$'),
      symlink: entry.isSymbolicLink()
    });
  }
  entries.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
  return { path: directory, entries, hidden_included: true };
}

function nativeCompilerCapabilities() {
  const tools = [
    ['assembler', 'rawrxd_native_assembler.exe'],
    ['linker', 'rawrxd_native_linker.exe'],
    ['librarian', 'rawrxd_native_librarian.exe'],
    ['resource_compiler', 'rawrxd_native_rc.exe'],
    ['debugger', 'rawrxd_native_debug.exe'],
    ['manifest', 'rawrxd_native_manifest.exe'],
    ['c_compiler', 'c_compiler_working.exe']
  ];
  return tools.map(([kind, name]) => {
    const fullPath = path.join(NATIVE_TOOLCHAIN_ROOT, name);
    let size = 0;
    try { size = fs.statSync(fullPath).size; } catch (_) {}
    return { kind, name, path: fullPath, present: size > 0, size };
  });
}

// ============================================================================
// REAL MODEL FETCHING - Query Ollama API for actual installed models
// ============================================================================
async function fetchOllamaModels() {
  return new Promise((resolve) => {
    const url = new URL('/api/tags', OLLAMA_HOST);

    const req = http.request(url, { method: 'GET', timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const models = (json.models || []).map(m => ({
            name: m.name,
            path: m.name,
            type: 'ollama',
            size: formatBytes(m.size),
            modified: m.modified_at,
            family: m.details?.family || 'unknown',
            parameters: m.details?.parameter_size || 'unknown',
            quantization: m.details?.quantization_level || 'unknown'
          }));
          resolve(models);
        } catch (e) {
          console.error('[Ollama] Parse error:', e.message);
          resolve([]);
        }
      });
    });

    req.on('error', (e) => {
      console.error('[Ollama] Connection error:', e.message);
      resolve([]);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve([]);
    });

    req.end();
  });
}

// Scan local GGUF files
function scanGGUFModels() {
  const models = [];
  try {
    if (fs.existsSync(MODEL_DIR)) {
      const files = fs.readdirSync(MODEL_DIR);
      files.filter(f => f.endsWith('.gguf')).forEach(file => {
        const filepath = path.join(MODEL_DIR, file);
        const stats = fs.statSync(filepath);
        models.push({
          name: file.replace('.gguf', ''),
          path: filepath,
          type: 'gguf',
          size: formatBytes(stats.size),
          modified: stats.mtime.toISOString()
        });
      });
    }
  } catch (e) {
    console.error('[GGUF] Scan error:', e.message);
  }
  return models;
}

// Get all available models (REAL - from Ollama + GGUF scan)
async function getAllModels() {
  const [ollamaModels, ggufModels] = await Promise.all([
    fetchOllamaModels(),
    Promise.resolve(scanGGUFModels())
  ]);

  const allModels = [...ollamaModels, ...ggufModels];
  console.log(`[Models] Found ${ollamaModels.length} Ollama + ${ggufModels.length} GGUF = ${allModels.length} total`);
  return allModels;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ============================================================================
// REAL AI INFERENCE - Send to Ollama for actual model responses
// ============================================================================
async function queryOllama(model, prompt, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL('/api/generate', OLLAMA_HOST);

    const payload = JSON.stringify({
      model: model,
      prompt: prompt,
      stream: false,
      options: {
        temperature: options.temperature || 0.7,
        top_p: options.top_p || 0.9,
        num_predict: options.max_tokens || 2048
      }
    });

    console.log(`[Ollama] Querying ${model}...`);

    const req = http.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 120000 // 2 minute timeout for inference
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error));
            return;
          }
          const tps = json.eval_count && json.eval_duration
            ? (json.eval_count / (json.eval_duration / 1e9)).toFixed(1)
            : 'N/A';
          console.log(`[Ollama] Response: ${json.response?.length || 0} chars, ${tps} tok/s`);
          resolve({
            answer: json.response,
            model: model,
            eval_count: json.eval_count,
            eval_duration: json.eval_duration,
            tokens_per_second: tps
          });
        } catch (e) {
          reject(new Error('Failed to parse Ollama response: ' + e.message));
        }
      });
    });

    req.on('error', (e) => reject(new Error('Ollama connection failed: ' + e.message)));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Ollama request timeout (model may be loading)'));
    });

    req.write(payload);
    req.end();
  });
}

// Smart model routing
async function queryModel(model, prompt, options = {}) {
  console.log(`[Query] Model: ${model}, Prompt: ${prompt.substring(0, 80)}...`);

  // All models go through Ollama (it handles GGUF too via modelfile)
  return queryOllama(model, prompt, options);
}

// ============================================================================
// HTTP SERVER
// ============================================================================
const server = http.createServer(async (req, res) => {
  g_gateway_metrics.requests += 1;
  res.once('finish', () => {
    g_gateway_metrics.responses += 1;
    if (res.statusCode >= 400) g_gateway_metrics.errors += 1;
  });
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const method = req.method;
  if (pathname === '/api/chat' || pathname === '/v1/chat/completions' || pathname === '/api/generate' || pathname === '/complete' || pathname === '/complete/stream') {
    g_gateway_metrics.chat_requests += 1;
  }

  console.log(`[${new Date().toISOString()}] ${req.method} ${pathname}`);

  // Handle OPTIONS (CORS preflight)
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // GET /models - REAL model list from Ollama API + GGUF scan
  if (req.method === 'GET' && pathname === '/models') {
    try {
      const models = await getAllModels();
      res.writeHead(200);
      res.end(JSON.stringify({ models }));
    } catch (e) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // GET /health
  if (req.method === 'GET' && pathname === '/health') {
    const models = await getAllModels();
    res.writeHead(200);
    res.end(JSON.stringify({
      status: 'online',
      models: models.length,
      uptime: process.uptime(),
      ollama: OLLAMA_HOST
    }));
    return;
  }

  // Opening the backend origin from the IDE's built-in browser lands on the
  // product UI directly; API clients still use their explicit routes.
  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(308, { Location: '/gui/' });
    res.end();
    return;
  }

  // The browser bundle is served by this same process.  Keeping the static
  // route here avoids the old split-brain setup where HTML came from one
  // server while the navigation asset was requested from a different root.
  if (serveGuiAsset(req, res, pathname)) return;

  // Browser reader fallback for sites that refuse iframe embedding.  It is
  // intentionally read-only and bounded; it never executes remote scripts or
  // rewrites a third party site's security headers.
  if (req.method === 'POST' && (pathname === '/api/browse' || pathname === '/api/browse/extract')) {
    try {
      const body = JSON.parse(await parseBody(req) || '{}');
      if (!body || typeof body.url !== 'string' || !body.url.trim()) {
        sendJson(res, 400, { ok: false, error: 'url_required' });
        return;
      }
      const page = await fetchBrowserReader(body.url.trim());
      if (!page.ok) {
        sendJson(res, 502, Object.assign(page, { ok: false, error: 'remote_http_error' }));
        return;
      }
      sendJson(res, 200, page);
    } catch (e) {
      sendJson(res, 502, { ok: false, error: 'browse_fetch_failed', detail: e.message, certification: 'NOT_CERTIFIED' });
    }
    return;
  }

  // Native capability probing must never report the Ollama/Node shim as a
  // Deep2 engine.  Proxy the probe to rawr.exe and fail explicitly when the
  // native process is not running.
  if (req.method === 'GET' && pathname === '/api/engine/capabilities') {
    try {
      const native = await nativeRequest('GET', '/api/engine/capabilities', null, 5000);
      if (native.status >= 200 && native.status < 300 && native.json) {
        res.writeHead(native.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(native.json));
      } else {
        // Deep2's OpenAI server predates the richer capabilities endpoint.
        // Treat a healthy /health + /v1/models pair as a reachable native
        // execution lane, while keeping GPU and certification claims explicit.
        const health = await nativeRequest('GET', '/health', null, 5000);
        const models = await nativeRequest('GET', '/v1/models', null, 5000);
        if (health.status >= 200 && health.status < 300 && models.status >= 200 && models.status < 300) {
          sendJson(res, 200, {
            ok: true,
            backend: 'deep2-openai',
            engine: 'Deep2',
            native_execution: true,
            server_health: health.json || health.text,
            models: models.json || models.text,
            gpu_execution: 'UNVERIFIED',
            full_model_certification: 'NOT_CERTIFIED',
            capabilities_endpoint: 'compatibility_fallback'
          });
        } else {
          sendNativeFailure(res, `native capabilities returned HTTP ${native.status}`);
        }
      }
    } catch (e) { sendNativeFailure(res, e); }
    return;
  }

  // The CLI bridge is read-only until the native MOTD/session authority is
  // presented.  Forwarding is allowed only to the native gateway; arbitrary
  // shell execution is never performed by this Node process.
  if (req.method === 'GET' && pathname === '/api/cli') {
    try {
      const native = await nativeRequest('GET', '/api/cli', null, 5000);
      if (native.status >= 200 && native.status < 300 && native.json) {
        res.writeHead(native.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(native.json));
      } else sendNativeFailure(res, `native CLI probe returned HTTP ${native.status}`);
    } catch (e) { sendNativeFailure(res, e); }
    return;
  }

  if (req.method === 'POST' && pathname === '/api/cli') {
    try {
      const body = await parseBody(req);
      const command = JSON.parse(body || '{}');
      if (!command || typeof command.command !== 'string' || !command.command.trim()) {
        sendJson(res, 400, { ok: false, error: 'command_required' });
        return;
      }
      const native = await nativeRequest('POST', '/api/cli', command, 30000);
      const payload = native.json || { ok: false, error: native.text || 'native CLI error' };
      res.writeHead(native.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) { sendNativeFailure(res, e); }
    return;
  }

  // Complete local filesystem roots for the left-hand IDE tree.  This is a
  // read-only operation and intentionally does not cross the native MOTD
  // mutation gate; file writes and process execution still go through the
  // native tool authority below.
  if (req.method === 'GET' && pathname === '/api/filesystem/roots') {
    try {
      sendJson(res, 200, {
        roots: enumerateFilesystemRoots(),
        hidden_included: true,
        backend: 'rawrxd-node-loopback'
      });
    } catch (e) {
      sendJson(res, 500, { ok: false, error: 'filesystem_roots_failed', detail: e.message });
    }
    return;
  }

  if (req.method === 'GET' && pathname === '/api/compiler/capabilities') {
    const tools = nativeCompilerCapabilities();
    sendJson(res, 200, {
      native_only: true,
      dependency_free: true,
      root: NATIVE_TOOLCHAIN_ROOT,
      tools,
      available: tools.some(t => t.present)
    });
    return;
  }

  if (req.method === 'POST' && (pathname === '/api/list-dir' || pathname === '/api/list-directory')) {
    try {
      const body = JSON.parse(await parseBody(req) || '{}');
      const requested = body && typeof body.path === 'string' ? body.path : '.';
      const result = listFilesystemDirectory(requested);
      sendJson(res, 200, result);
    } catch (e) {
      const code = e && (e.code === 'ENOENT' || e.code === 'ENOTDIR') ? 404 :
        (e && (e.code === 'EACCES' || e.code === 'EPERM') ? 403 : 400);
      sendJson(res, code, {
        ok: false,
        error: 'filesystem_list_failed',
        detail: e.message,
        hidden_included: true
      });
    }
    return;
  }

  if (req.method === 'POST' && pathname === '/api/read-file') {
    try {
      const body = await parseBody(req);
      const request = JSON.parse(body || '{}');
      if (!request || typeof request.path !== 'string' || !request.path.trim()) {
        sendJson(res, 400, { ok: false, error: 'path_required' });
        return;
      }
      const motd = typeof req.headers['x-motd-ack'] === 'string' ? req.headers['x-motd-ack'] : '';
      const native = await nativeRequest('POST', '/api/read-file', request, 15000,
        motd ? { 'X-MOTD-ACK': motd } : {});
      const payload = native.json || { ok: false, error: native.text || 'native file bridge error' };
      res.writeHead(native.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) { sendNativeFailure(res, e); }
    return;
  }

  // Agentic tools always cross the native authority boundary.  This bridge
  // intentionally does not execute shell commands in Node and does not
  // convert a denied native request into a success response.
  if (req.method === 'POST' && (pathname === '/api/tool' || pathname === '/api/agent/execute-tool')) {
    try {
      const body = JSON.parse(await parseBody(req) || '{}');
      const command = pathname === '/api/agent/execute-tool'
        ? { tool: body.name || body.tool || '', args: body.arguments || body.args || {} }
        : body;
      if (!command.tool || typeof command.tool !== 'string') {
        sendJson(res, 400, { ok: false, error: 'tool_required' });
        return;
      }
      const motd = typeof req.headers['x-motd-ack'] === 'string' ? req.headers['x-motd-ack'] : '';
      const native = await nativeRequest('POST', '/api/tool', command, 30000,
        motd ? { 'X-MOTD-ACK': motd } : {});
      const payload = native.json || { ok: false, error: native.text || 'native tool error' };
      res.writeHead(native.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) { sendNativeFailure(res, e); }
    return;
  }

  // -----------------------------------------------------------------------
  // Compatibility/control-plane routes.  These are real routes used by the
  // IDE panels; they must never disappear as a 404 just because the optional
  // native control process is not running.  Read-only probes return truthful
  // state locally, while mutations and execution still fail closed at the
  // native authority boundary.
  // -----------------------------------------------------------------------
  if (req.method === 'GET' && pathname === '/api/backends') {
    const native = await tryNativeRoute('GET', '/api/backends', null, 3000);
    if (native && native.json) { sendJson(res, native.status, native.json); return; }
    sendJson(res, 200, { ok: true, active: g_active_backend, backends: [nodeBackendSnapshot(), backendSnapshot()], native: { available: false, url: NATIVE_HOST } });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/backends/status') {
    const native = await tryNativeRoute('GET', '/api/backends/status', null, 3000);
    if (native && native.json) { sendJson(res, native.status, native.json); return; }
    sendJson(res, 200, { ok: true, active_backend: g_active_backend, backends: [nodeBackendSnapshot(), backendSnapshot()], native_available: false });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/backends/use') {
    try {
      const body = JSON.parse(await parseBody(req) || '{}');
      const requested = String(body.backend || body.id || body.name || '').trim().toLowerCase();
      const aliases = { ollama: 'ollama-direct', 'ollama-direct': 'ollama-direct', node: 'rawrxd-node', 'rawrxd-node': 'rawrxd-node', native: 'rawrxd-native', 'rawrxd-native': 'rawrxd-native' };
      const target = aliases[requested];
      if (!target) { sendJson(res, 400, { ok: false, error: 'unknown_backend', requested, available: ['ollama-direct', 'rawrxd-node', 'rawrxd-native'] }); return; }
      if (target === 'rawrxd-native') {
        const native = await tryNativeRoute('POST', '/api/backends/use', { backend: target }, 5000);
        if (!native) { routeNotReady(res, pathname, `native backend unavailable at ${NATIVE_HOST}`); return; }
        sendJson(res, native.status, native.json || { ok: native.status >= 200 && native.status < 300, backend: target });
        return;
      }
      g_active_backend = target;
      sendJson(res, 200, { ok: true, active_backend: g_active_backend, backend: target, changed: true });
    } catch (e) { sendJson(res, 400, { ok: false, error: 'invalid_backend_request', detail: e.message }); }
    return;
  }

  if (req.method === 'GET' && (pathname === '/api/agents' || pathname === '/api/agents/status')) {
    const nativePath = pathname;
    const native = await tryNativeRoute('GET', nativePath, null, 3000);
    if (native && native.json) { sendJson(res, native.status, native.json); return; }
    sendJson(res, 200, {
      ok: true,
      available: false,
      backend: 'rawrxd-native',
      agent_count: 0,
      agents: [],
      running: false,
      history_count: g_agent_history.length,
      detail: `native agent service unavailable at ${NATIVE_HOST}`
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/agents/history') {
    const native = await tryNativeRoute('GET', pathname + (url.search || ''), null, 3000);
    if (native && native.json) { sendJson(res, native.status, native.json); return; }
    sendJson(res, 200, { ok: true, entries: g_agent_history.slice(-queryLimit(url)), count: g_agent_history.length, available: false });
    return;
  }

  if (req.method === 'GET' && (pathname === '/api/agents/explain' || pathname === '/api/agents/explain/stats')) {
    const native = await tryNativeRoute('GET', pathname + (url.search || ''), null, 3000);
    if (native && native.json) { sendJson(res, native.status, native.json); return; }
    sendJson(res, 200, { ok: true, available: false, route: pathname, explanations: [], stats: { requests: g_agent_history.length, failures: 0 } });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/agents/replay') {
    const body = JSON.parse(await parseBody(req) || '{}');
    const native = await tryNativeRoute('POST', pathname, body, 30000);
    if (native) { sendJson(res, native.status, native.json || { ok: native.status >= 200 && native.status < 300 }); return; }
    routeNotReady(res, pathname, `native replay service unavailable at ${NATIVE_HOST}`);
    return;
  }

  if (req.method === 'GET' && pathname === '/api/failures') {
    const failures = Object.values(g_receipts).filter(r => r && (r.ok === false || r.status === 'failed' || r.error));
    sendJson(res, 200, { ok: true, failures: failures.slice(-queryLimit(url)), count: failures.length });
    return;
  }

  if (req.method === 'GET' && pathname === '/metrics') {
    sendJson(res, 200, {
      ok: true,
      backend: 'rawrxd-node',
      uptime_seconds: process.uptime(),
      active_backend: g_active_backend,
      metrics: Object.assign({}, g_gateway_metrics)
    });
    return;
  }

  if (req.method === 'POST' && (pathname === '/api/chain' || pathname === '/api/subagent' || pathname === '/api/swarm')) {
    const body = JSON.parse(await parseBody(req) || '{}');
    const native = await tryNativeRoute('POST', pathname, body, 30000);
    if (native) { sendJson(res, native.status, native.json || { ok: native.status >= 200 && native.status < 300 }); return; }
    routeNotReady(res, pathname, `native orchestration service unavailable at ${NATIVE_HOST}`);
    return;
  }

  if (req.method === 'POST' && (pathname === '/complete' || pathname === '/complete/stream')) {
    try {
      const body = JSON.parse(await parseBody(req) || '{}');
      const model = String(body.model || DEFAULT_MODEL).trim();
      const prompt = String(body.prompt || body.question || '').trim();
      if (!prompt) { sendJson(res, 400, { ok: false, error: 'prompt_required' }); return; }
      const result = await queryOllama(model, prompt, { temperature: body.temperature, max_tokens: body.max_tokens, top_p: body.top_p });
      if (pathname === '/complete/stream') {
        const token = { model, response: result.answer || '', done: true, eval_count: result.eval_count, eval_duration: result.eval_duration };
        const payload = JSON.stringify(token) + '\n';
        res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-cache', 'Content-Length': Buffer.byteLength(payload) });
        res.end(payload);
      } else {
        sendJson(res, 200, Object.assign({ ok: true }, result));
      }
    } catch (e) { sendJson(res, 502, { ok: false, error: 'completion_failed', detail: e.message, certification: 'NOT_CERTIFIED' }); }
    return;
  }

  if (req.method === 'GET' && pathname === '/api/extensions') {
    sendJson(res, 200, { ok: true, extensions: Array.from(g_extension_state.values()), count: g_extension_state.size, host: { running: false, available: false } });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/extensions/host/status') {
    sendJson(res, 200, { ok: true, running: false, available: false, detail: 'extension host is optional and not running' });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/extensions/host/logs') {
    sendJson(res, 200, { ok: true, logs: [], available: false });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/extensions/export') {
    sendJson(res, 200, { ok: true, format: 'rawrxd-extension-manifest-v1', extensions: Array.from(g_extension_state.values()) });
    return;
  }

  if (req.method === 'POST' && /^\/api\/extensions\/(activate|deactivate|enable|disable)$/.test(pathname)) {
    try {
      const body = JSON.parse(await parseBody(req) || '{}');
      const id = String(body.id || body.extension || body.name || '').trim();
      if (!id) { sendJson(res, 400, { ok: false, error: 'extension_id_required' }); return; }
      const action = pathname.substring(pathname.lastIndexOf('/') + 1);
      const current = g_extension_state.get(id) || { id, name: id, version: 'unknown', builtin: false };
      current.enabled = action === 'activate' || action === 'enable';
      current.active = action === 'activate';
      current.updated_at = new Date().toISOString();
      g_extension_state.set(id, current);
      sendJson(res, 200, { ok: true, action, extension: current, persisted: false, authority: 'node-session' });
    } catch (e) { sendJson(res, 400, { ok: false, error: 'invalid_extension_request', detail: e.message }); }
    return;
  }

  if (req.method === 'POST' && /^\/api\/extensions\/(install|import|load-vsix|uninstall|scan)$/.test(pathname)) {
    const body = JSON.parse(await parseBody(req) || '{}');
    const native = await tryNativeRoute('POST', pathname, body, 30000);
    if (native) { sendJson(res, native.status, native.json || { ok: native.status >= 200 && native.status < 300 }); return; }
    if (pathname.endsWith('/scan')) {
      sendJson(res, 200, { ok: true, extensions: Array.from(g_extension_state.values()), scanned: true, available: false });
      return;
    }
    routeNotReady(res, pathname, `extension authority unavailable at ${NATIVE_HOST}`);
    return;
  }

  if (req.method === 'POST' && pathname === '/api/extensions/marketplace/search') {
    const body = JSON.parse(await parseBody(req) || '{}');
    sendJson(res, 200, { ok: true, query: String(body.query || body.search || ''), results: [], source: 'offline', available: false });
    return;
  }

  if (req.method === 'POST' && /^\/api\/extensions\/host\/(kill|restart)$/.test(pathname)) {
    routeNotReady(res, pathname, 'extension host is optional and is not running');
    return;
  }

  if (req.method === 'GET' && pathname === '/api/hotpatch/status') {
    sendJson(res, 200, { ok: true, enabled: false, available: false, fail_closed: true, reason: 'native hotpatch authority unavailable' });
    return;
  }

  if (req.method === 'POST' && /^\/api\/hotpatch\/(apply|revert|toggle)$/.test(pathname)) {
    const body = JSON.parse(await parseBody(req) || '{}');
    const native = await tryNativeRoute('POST', pathname, body, 30000);
    if (native) { sendJson(res, native.status, native.json || { ok: native.status >= 200 && native.status < 300 }); return; }
    routeNotReady(res, pathname, `native hotpatch authority unavailable at ${NATIVE_HOST}`);
    return;
  }

  if (req.method === 'GET' && pathname === '/api/policies') {
    sendJson(res, 200, { ok: true, fail_closed: true, tool_authority: 'native-only', policies: [], certification: 'NOT_CERTIFIED' });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/policies/stats') {
    sendJson(res, 200, { ok: true, applied: 0, rejected: 0, suggestions: 0, fail_closed: true });
    return;
  }

  if (req.method === 'GET' && (pathname === '/api/policies/heuristics' || pathname === '/api/policies/suggestions')) {
    sendJson(res, 200, { ok: true, heuristics: [], suggestions: [], available: false, fail_closed: true });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/policies/export') {
    sendJson(res, 200, { ok: true, format: 'rawrxd-policy-v1', fail_closed: true, policies: [] });
    return;
  }

  if (req.method === 'POST' && /^\/api\/policies\/(apply|reject|import)$/.test(pathname)) {
    const body = JSON.parse(await parseBody(req) || '{}');
    const native = await tryNativeRoute('POST', pathname, body, 30000);
    if (native) { sendJson(res, native.status, native.json || { ok: native.status >= 200 && native.status < 300 }); return; }
    routeNotReady(res, pathname, `native policy authority unavailable at ${NATIVE_HOST}`);
    return;
  }

  // POST /ask - REAL AI inference via Ollama
  if (req.method === 'POST' && pathname === '/ask') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const model = data.model || DEFAULT_MODEL;
        const prompt = data.question || data.prompt || '';

        if (!prompt) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'No question/prompt provided' }));
          return;
        }

        const result = await queryModel(model, prompt, {
          temperature: data.temperature,
          max_tokens: data.max_tokens,
          top_p: data.top_p
        });

        res.writeHead(200);
        res.end(JSON.stringify(result));

      } catch (e) {
        console.error('[Ask] Error:', e.message);
        res.writeHead(500);
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // GET /status - HeadlessIDE / new binary compatibility
  if (req.method === 'GET' && pathname === '/status') {
    const models = await getAllModels();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      server: 'RawrXD-Node-Backend',
      version: '2.0.0',
      backend: 'rawrxd-node',
      port: PORT,
      models_loaded: models.length,
      capabilities: {
        kernel_engines: true,
        model_swarm: false,
        dual_engine_800b: false,
        hotpatching: false,
        file_read: true,
        cli: true,
        native_bridge: true
      }
    }));
    return;
  }

  // GET /api/status - old tool_server compatibility
  if (req.method === 'GET' && pathname === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      running: true,
      server: 'RawrXD-Node-Backend',
      port: PORT,
      uptime_seconds: Math.round(process.uptime()),
      native_bridge: true
    }));
    return;
  }

  // GET /v1/models - OpenAI-compatible model listing
  if (req.method === 'GET' && pathname === '/v1/models') {
    try {
      const models = await getAllModels();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        object: 'list',
        data: models.map(m => ({
          id: m.name,
          object: 'model',
          created: Math.floor(Date.now() / 1000),
          owned_by: 'rawrxd'
        }))
      }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ object: 'list', data: [] }));
    }
    return;
  }

  // GET /api/tags - Ollama-compatible model listing
  if (req.method === 'GET' && pathname === '/api/tags') {
    try {
      const models = await getAllModels();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        models: models.map(m => ({
          name: m.name,
          model: m.name,
          size: 0,
          modified_at: new Date().toISOString(),
          details: { format: m.type || 'unknown' }
        }))
      }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ models: [] }));
    }
    return;
  }

  // POST /v1/chat/completions - OpenAI-compatible chat endpoint
  if (req.method === 'POST' && pathname === '/v1/chat/completions') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        const messages = parsed.messages || [];
        const model = parsed.model || 'rawrxd';
        const stream = parsed.stream === true;

        // Prefer the native Deep2 gateway.  The Node service is only a
        // browser-facing bridge; it must not silently turn a native request
        // into an unrelated Ollama model.
        try {
          const nativeReq = Object.assign({}, parsed, { stream: false });
          const native = await nativeRequest('POST', '/v1/chat/completions', nativeReq, 120000);
          const nativeContent = native.json && native.json.choices && native.json.choices[0] &&
            native.json.choices[0].message && native.json.choices[0].message.content;
          if (native.status >= 200 && native.status < 300 && native.json &&
              typeof nativeContent === 'string' && nativeContent.length > 0) {
            const nativeResponse = native.json;
            if (stream) {
              const chunk = {
                id: nativeResponse.id || ('chatcmpl-' + Date.now()),
                object: 'chat.completion.chunk',
                created: nativeResponse.created || Math.floor(Date.now() / 1000),
                model: nativeResponse.model || model,
                choices: [{ index: 0, delta: { role: 'assistant', content: nativeContent }, finish_reason: null }]
              };
              const done = {
                id: chunk.id, object: 'chat.completion.chunk', created: chunk.created,
                model: chunk.model, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }]
              };
              const payload = `data: ${JSON.stringify(chunk)}\n\ndata: ${JSON.stringify(done)}\n\ndata: [DONE]\n\n`;
              res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Content-Length': Buffer.byteLength(payload) });
              res.end(payload);
            } else {
              res.writeHead(native.status, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(nativeResponse));
            }
            return;
          }
        } catch (_) {
          // Ollama remains a compatibility fallback when the native gateway
          // is not running; the failure is still reported if both fail.
        }

        // Forward to Ollama if available
        const ollamaOpts = {
          hostname: 'localhost', port: 11434, path: '/api/chat', method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          timeout: 120000
        };
        const ollamaBody = JSON.stringify({
          model: model,
          messages: messages,
          stream: false,
          options: {
            temperature: parsed.temperature || 0.7,
            top_p: parsed.top_p || 0.9,
            top_k: parsed.top_k || 40,
            num_ctx: (parsed.options && parsed.options.num_ctx) || parsed.context || 8192,
            num_predict: parsed.max_tokens || 512
          }
        });

        try {
          const ollamaRes = await new Promise((resolve, reject) => {
            const req = http.request(ollamaOpts, (res) => {
              let buf = '';
              res.on('data', c => buf += c);
              res.on('end', () => resolve({ status: res.statusCode, body: buf }));
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
            req.write(ollamaBody);
            req.end();
          });
          const ollamaData = JSON.parse(ollamaRes.body);
          if (ollamaRes.status < 200 || ollamaRes.status >= 300 || ollamaData.error) {
            throw new Error(ollamaData.error || `Ollama HTTP ${ollamaRes.status}`);
          }
          // A zero-token response is not a successful completion.  Returning
          // HTTP 200 with finish_reason=stop made the GUI display an empty
          // answer as if the model had completed normally.
          const ollamaText = ollamaData.message && typeof ollamaData.message.content === 'string'
            ? ollamaData.message.content
            : ollamaData.response;
          if (typeof ollamaText !== 'string' || ollamaText.length === 0) {
            throw new Error('model returned zero visible tokens');
          }
          const openaiResponse = {
            id: 'chatcmpl-' + Date.now(),
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: ollamaData.model || model,
            choices: [{
              index: 0,
              message: { role: 'assistant', content: ollamaText },
              finish_reason: ollamaData.done_reason || 'stop'
            }],
            usage: {
              prompt_tokens: ollamaData.prompt_eval_count || 0,
              completion_tokens: ollamaData.eval_count || 0,
              total_tokens: (ollamaData.prompt_eval_count || 0) + (ollamaData.eval_count || 0)
            }
          };
          if (stream) {
            // Preserve the OpenAI streaming contract even when the request is
            // served by the Ollama compatibility fallback.  Returning a
            // buffered JSON document here makes browser clients that consume
            // SSE report a false successful completion with zero tokens.
            const id = openaiResponse.id;
            const created = openaiResponse.created;
            const responseText = openaiResponse.choices[0].message.content;
            const chunk = {
              id,
              object: 'chat.completion.chunk',
              created,
              model: openaiResponse.model,
              choices: [{ index: 0, delta: { role: 'assistant', content: responseText }, finish_reason: null }]
            };
            const done = {
              id,
              object: 'chat.completion.chunk',
              created,
              model: openaiResponse.model,
              choices: [{ index: 0, delta: {}, finish_reason: openaiResponse.choices[0].finish_reason || 'stop' }]
            };
            const payload = `data: ${JSON.stringify(chunk)}\n\ndata: ${JSON.stringify(done)}\n\ndata: [DONE]\n\n`;
            res.writeHead(200, {
              'Content-Type': 'text/event-stream',
              'Cache-Control': 'no-cache, no-transform',
              'X-Accel-Buffering': 'no',
              'Content-Length': Buffer.byteLength(payload)
            });
            res.end(payload);
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(openaiResponse));
          }
        } catch (ollamaErr) {
          // Do not fabricate assistant text or a successful stop reason when
          // both native and Ollama inference are unavailable.
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: {
              type: 'backend_unavailable',
              message: ollamaErr.message,
              backend: 'ollama',
              native_endpoint: NATIVE_HOST,
              certification: 'NOT_CERTIFIED'
            }
          }));
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'Invalid JSON: ' + e.message } }));
      }
    });
    return;
  }

  // Ollama-compatible chat route.  Keep this as a first-class gateway route
  // instead of making browser clients flatten multi-turn history into a
  // single prompt.  The native backend gets first refusal; Ollama is a
  // compatibility fallback when the native service is unavailable.
  if (req.method === 'POST' && pathname === '/api/chat') {
    try {
      const parsed = JSON.parse(await parseBody(req) || '{}');
      const model = parsed.model || DEFAULT_MODEL;
      const messages = Array.isArray(parsed.messages) ? parsed.messages :
        (typeof parsed.prompt === 'string' ? [{ role: 'user', content: parsed.prompt }] : []);
      if (!messages.length) {
        sendJson(res, 400, { error: 'No messages provided' });
        return;
      }
      const stream = parsed.stream === true;
      const requestBody = Object.assign({}, parsed, {
        model,
        messages,
        stream: false,
        options: Object.assign({}, parsed.options || {}, {
          num_ctx: (parsed.options && parsed.options.num_ctx) || parsed.context || 8192,
          num_predict: (parsed.options && parsed.options.num_predict) || parsed.max_tokens || 512
        })
      });

      // Native /api/chat support is optional.  If it is present, preserve the
      // exact Ollama-shaped response while adapting stream framing below.
      try {
        const native = await nativeRequest('POST', '/api/chat', requestBody, 120000);
        const nativeText = native.json && native.json.message && native.json.message.content;
        if (native.status >= 200 && native.status < 300 && native.json &&
            typeof nativeText === 'string' && nativeText.length > 0) {
          if (stream) {
            const payload = JSON.stringify(Object.assign({}, native.json, {
              model: native.json.model || model,
              message: { role: 'assistant', content: nativeText },
              done: false
            })) + '\n' + JSON.stringify(Object.assign({}, native.json, {
              model: native.json.model || model,
              message: { role: 'assistant', content: '' },
              done: true,
              done_reason: native.json.done_reason || 'stop'
            })) + '\n';
            res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-cache', 'Content-Length': Buffer.byteLength(payload) });
            res.end(payload);
          } else {
            res.writeHead(native.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
            res.end(JSON.stringify(native.json));
          }
          return;
        }
      } catch (_) {
        // Continue to Ollama compatibility fallback.
      }

      const ollamaOpts = {
        hostname: 'localhost', port: 11434, path: '/api/chat', method: 'POST',
        headers: { 'Content-Type': 'application/json' }, timeout: 120000
      };
      const ollamaBody = JSON.stringify(Object.assign({}, requestBody, { stream: false }));
      const ollamaRes = await new Promise((resolve, reject) => {
        const upstream = http.request(ollamaOpts, (upstreamRes) => {
          let buf = '';
          upstreamRes.setEncoding('utf8');
          upstreamRes.on('data', c => buf += c);
          upstreamRes.on('end', () => resolve({ status: upstreamRes.statusCode || 502, body: buf }));
        });
        upstream.on('error', reject);
        upstream.on('timeout', () => { upstream.destroy(new Error('Ollama chat timeout')); });
        upstream.write(ollamaBody);
        upstream.end();
      });
      const ollamaData = JSON.parse(ollamaRes.body || '{}');
      const chatText = ollamaData.message && ollamaData.message.content;
      if (ollamaRes.status < 200 || ollamaRes.status >= 300 || ollamaData.error ||
          typeof chatText !== 'string' || chatText.length === 0) {
        throw new Error(ollamaData.error || 'model returned zero visible tokens');
      }
      if (stream) {
        const payload = JSON.stringify(Object.assign({}, ollamaData, {
          model: ollamaData.model || model,
          message: { role: 'assistant', content: chatText },
          done: false
        })) + '\n' + JSON.stringify({
          model: ollamaData.model || model,
          message: { role: 'assistant', content: '' },
          done: true,
          done_reason: ollamaData.done_reason || 'stop'
        }) + '\n';
        res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-cache', 'Content-Length': Buffer.byteLength(payload) });
        res.end(payload);
      } else {
        res.writeHead(ollamaRes.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
        res.end(JSON.stringify(ollamaData));
      }
    } catch (e) {
      sendJson(res, 502, { error: { type: 'chat_backend_unavailable', message: e.message, certification: 'NOT_CERTIFIED' } });
    }
    return;
  }

  // Ollama-compatible single-prompt route.  This route follows the same
  // native-first policy as /v1/chat/completions and never reports an empty
  // response as a successful completion.
  if (req.method === 'POST' && pathname === '/api/generate') {
    try {
      const parsed = JSON.parse(await parseBody(req) || '{}');
      const stream = parsed.stream === true;
      try {
        const native = await nativeRequest('POST', '/api/generate', Object.assign({}, parsed, { stream: false }), 120000);
        const nativeText = native.json && (native.json.response || native.json.output || '');
        if (native.status >= 200 && native.status < 300 && typeof nativeText === 'string' && nativeText.length > 0) {
          if (stream) {
            const payload = `data: ${JSON.stringify({ model: native.json.model || parsed.model || DEFAULT_MODEL, response: nativeText, done: false })}\n\n` +
              `data: ${JSON.stringify({ model: native.json.model || parsed.model || DEFAULT_MODEL, response: '', done: true, done_reason: native.json.done_reason || 'stop' })}\n\n`;
            res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Content-Length': Buffer.byteLength(payload) });
            res.end(payload);
          } else {
            res.writeHead(native.status, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(native.json));
          }
          return;
        }
      } catch (_) {}
      const model = parsed.model || DEFAULT_MODEL;
      const prompt = typeof parsed.prompt === 'string' ? parsed.prompt : '';
      if (!prompt) { sendJson(res, 400, { error: 'No prompt provided' }); return; }
      const result = await queryOllama(model, prompt, {
        temperature: parsed.options && parsed.options.temperature,
        top_p: parsed.options && parsed.options.top_p,
        max_tokens: parsed.options && parsed.options.num_predict
      });
      if (!result || typeof result.answer !== 'string' || result.answer.length === 0) {
        sendJson(res, 502, { error: { type: 'empty_output', message: 'model returned zero visible tokens' } });
        return;
      }
      if (stream) {
        const payload = `data: ${JSON.stringify({ model, response: result.answer, done: false })}\n\n` +
          `data: ${JSON.stringify({ model, response: '', done: true, done_reason: 'stop' })}\n\n`;
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Content-Length': Buffer.byteLength(payload) });
        res.end(payload);
      } else {
        sendJson(res, 200, { model, response: result.answer, done: true, done_reason: 'stop', eval_count: result.eval_count || 0 });
      }
    } catch (e) {
      sendJson(res, 503, { error: { type: 'backend_unavailable', message: e.message, certification: 'NOT_CERTIFIED' } });
    }
    return;
  }

  // POST /exec - Execute terminal commands (real execution)
  if (req.method === 'POST' && pathname === '/exec') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const command = data.command;

        if (!command) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'No command provided' }));
          return;
        }

        console.log(`[Exec] Running: ${command}`);

        exec(command, { cwd: 'D:\\rawrxd', timeout: 30000, shell: 'powershell.exe' }, (error, stdout, stderr) => {
          res.writeHead(200);
          res.end(JSON.stringify({
            output: stdout || 'Command completed',
            stderr: stderr || null,
            error: error ? error.message : null,
            exitCode: error ? error.code : 0
          }));
        });

      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // ── Native E2E bridge: /api/native/* ──
  if (pathname.startsWith('/api/native/')) {
    const body = await parseBody(req);
    const handled = handleNativeRoutes(method, pathname, body, res);
    if (handled) return;
    // Fall through to 404 if not handled
  }

  // 404 for everything else
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

// ============================================================================
// STARTUP
// ============================================================================
server.listen(PORT, BIND_HOST, async () => {
  console.log(`
================================================
  RawrXD Agentic Backend Server v2.0
  REAL AI Inference - No Hardcoded Responses
================================================
  
  [+] Server listening on http://${BIND_HOST}:${PORT}
[+] Ollama endpoint: ${OLLAMA_HOST}
[+] GGUF directory: ${MODEL_DIR}
`);

  // Test Ollama connection and show available models
  const models = await fetchOllamaModels();
  if (models.length > 0) {
    console.log(`[+] Ollama connected: ${models.length} models available`);
    models.slice(0, 5).forEach(m => console.log(`    - ${m.name} (${m.size})`));
    if (models.length > 5) console.log(`    ... and ${models.length - 5} more`);
  } else {
    console.log(`[!] Ollama not available - will use GGUF models only`);
  }

  const gguf = scanGGUFModels();
  if (gguf.length > 0) {
    console.log(`[+] GGUF models found: ${gguf.length}`);
  }

  console.log(`\n[+] Ready for frontend connections\n`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[!] Shutting down...');
  server.close(() => process.exit(0));
});
