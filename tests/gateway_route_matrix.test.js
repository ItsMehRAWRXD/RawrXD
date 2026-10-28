'use strict';

// Dependency-free live gateway contract test.  Start backend/server.js before
// running this file.  It deliberately treats native-service absence as a
// structured 503, while a 404 for a registered route is always a failure.
const fs = require('fs');

const base = process.env.RAWRXD_GATEWAY_URL || 'http://127.0.0.1:19035';
const source = fs.readFileSync(require('path').join(__dirname, '..', 'backend', 'server.js'), 'utf8');
const routeBlock = source.match(/const g_routes = \[(.*?)\n\];/s);
if (!routeBlock) throw new Error('g_routes registry not found');
const routes = [...routeBlock[1].matchAll(/\{ path: '([^']+)', method: '([^']+)' \}/g)]
  .map(m => ({ path: m[1], method: m[2] }))
  .filter(r => !r.path.includes('*'));

async function request(path, method, body) {
  const init = { method, headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined) init.body = JSON.stringify(body);
  const response = await fetch(base + path, init);
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) {}
  return { status: response.status, headers: response.headers, text, json };
}

function bodyFor(path) {
  if (path === '/api/chat') return { model: 'llama3.2:3b', messages: [{ role: 'user', content: 'Reply with exactly OK' }], stream: false, options: { num_predict: 4 } };
  if (path === '/v1/chat/completions') return { model: 'llama3.2:3b', messages: [{ role: 'user', content: 'Reply with exactly OK' }], stream: false, max_tokens: 4 };
  if (path === '/api/generate' || path === '/complete' || path === '/complete/stream') return { model: 'llama3.2:3b', prompt: 'Reply with exactly OK', stream: false, options: { num_predict: 4 } };
  if (path === '/api/extensions/activate') return { id: 'test.gateway.extension' };
  if (path === '/api/backends/use') return { backend: 'ollama-direct' };
  return {};
}

(async () => {
  const failures = [];
  const results = [];
  for (const route of routes) {
    const result = await request(route.path, route.method, route.method === 'POST' ? bodyFor(route.path) : undefined);
    const valid = result.status !== 404;
    results.push({ path: route.path, method: route.method, status: result.status, valid });
    if (!valid) failures.push(`${route.method} ${route.path}: 404`);
  }

  const preflight = await request('/api/chat', 'OPTIONS');
  if (preflight.status !== 200 || preflight.headers.get('access-control-allow-origin') !== '*') {
    failures.push(`OPTIONS /api/chat: status=${preflight.status} cors=${preflight.headers.get('access-control-allow-origin')}`);
  }

  const chat = await request('/api/chat', 'POST', bodyFor('/api/chat'));
  if (chat.status < 200 || chat.status >= 300 || !chat.json || !String(chat.json.message?.content || chat.json.response || '').trim()) {
    failures.push(`POST /api/chat: status=${chat.status} nonempty assistant response required`);
  }

  const activate = await request('/api/extensions/activate', 'POST', { id: 'test.gateway.extension' });
  if (activate.status !== 200 || !activate.json?.extension?.enabled) failures.push('extension activation did not persist in session');

  const metrics = await request('/metrics', 'GET');
  if (metrics.status !== 200 || !metrics.json?.metrics || metrics.json.metrics.requests < 1) failures.push('metrics route did not expose request counters');

  const summary = { ok: failures.length === 0, route_count: routes.length, valid_routes: results.filter(r => r.valid).length, failures, status_counts: results.reduce((a, r) => (a[r.status] = (a[r.status] || 0) + 1, a), {}) };
  console.log(JSON.stringify(summary, null, 2));
  process.exitCode = failures.length === 0 ? 0 : 1;
})().catch(err => { console.error(err.stack || err); process.exitCode = 1; });

