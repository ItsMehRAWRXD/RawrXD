/**
 * RawrZ Server Helper — ensures embedded API (http://127.0.0.1:3000) is reachable
 * and provides getApiBase(), ensureServerReady(), and apiCall() for all panels.
 * When the app is run via Electron (npm start), the server is started automatically.
 * If server is not running, ensureServerReady() shows a message to start the app.
 */
(function () {
  'use strict';

  const DEFAULT_PORT = 3000;
  const HEALTH_ENDPOINT = '/api/health';
  const SERVER_MSG = 'RawrZ server is not running. Please start the app with "npm start" (or run Electron) to use this feature.';

  function getApiBase() {
    if (typeof location === 'undefined') return 'http://127.0.0.1:' + DEFAULT_PORT;
    if (location.protocol === 'file:' || !location.hostname) return 'http://127.0.0.1:' + DEFAULT_PORT;
    return location.origin;
  }

  async function ensureServerReady() {
    const base = getApiBase();
    try {
      const res = await fetch(base + HEALTH_ENDPOINT, { method: 'GET' });
      if (res.ok) return base;
    } catch (_) {}
    if (typeof alert !== 'undefined') alert(SERVER_MSG);
    else console.warn(SERVER_MSG);
    return null;
  }

  async function apiCall(endpoint, method, body) {
    const base = await ensureServerReady();
    if (!base) return null;
    const url = base + (endpoint.startsWith('/') ? endpoint : '/' + endpoint);
    const opts = {
      method: method || 'GET',
      headers: { 'Content-Type': 'application/json' }
    };
    if (body != null && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      opts.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    try {
      const res = await fetch(url, opts);
      const text = await res.text();
      let data = text;
      try {
        data = JSON.parse(text);
      } catch (_) {}
      return { status: res.status, ok: res.ok, data };
    } catch (err) {
      if (typeof alert !== 'undefined') alert('Request failed: ' + (err.message || err));
      return { status: 0, ok: false, data: { error: err.message } };
    }
  }

  window.RawrZServerHelper = {
    getApiBase: getApiBase,
    ensureServerReady: ensureServerReady,
    apiCall: apiCall
  };
})();
