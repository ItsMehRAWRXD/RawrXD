(function () {
  'use strict';

  var API = '/api/v1/screenpilot';
  var NativeFetch = window.fetch.bind(window);

  function byId(id) { return document.getElementById(id); }
  function escapeText(v) {
    var d = document.createElement('div');
    d.textContent = String(v == null ? '' : v);
    return d.innerHTML;
  }

  var SP = {
    authorityLocked: true,
    available: false,
    mode: 'ask',
    sessionToken: '',
    activeRequestId: '',
    activeAbort: null,
    workspace: '',
    health: null,
    initPromise: null,
    legacyFallback: false,
    approval: null
  };

  if (window.State) {
    State.screenpilot = SP;

    // Final shipping build is same-origin on the existing LocalServer.
    if (location.protocol === 'http:' &&
        (location.hostname === '127.0.0.1' ||
         location.hostname === 'localhost' ||
         location.hostname === '::1' ||
         location.hostname === '[::1]')) {
      State.backend.url = location.origin;
      if (typeof _ideServerUrl !== 'undefined') _ideServerUrl = location.origin;
      State.backend.directMode = false;
    }
  }

  function status(text, ok) {
    var s = byId('screenpilotAuthorityStatus');
    if (s) {
      s.textContent = text;
      s.style.color = ok === false ? 'var(--accent-red)' :
        (ok === true ? 'var(--accent-green)' : 'var(--text-muted)');
    }
  }

  function syncLegacyAgentUi() {
    if (!window.State) return;
    State.agenticMode = SP.mode === 'build' || SP.mode === 'agent';

    var btn = byId('agenticModeBtn');
    var label = byId('agenticModeLabel');
    if (!btn || !label) return;

    if (SP.mode === 'agent') {
      label.textContent = 'Agent: ON';
      btn.style.opacity = '1.0';
      btn.style.color = 'var(--accent-green)';
      btn.title = 'AGENT mode — canonical Tool Authority, workspace-scoped';
    } else if (SP.mode === 'build') {
      label.textContent = 'Build';
      btn.style.opacity = '1.0';
      btn.style.color = 'var(--accent-cyan)';
      btn.title = 'BUILD mode — workspace edits + build/test authority';
    } else if (SP.mode === 'plan') {
      label.textContent = 'Plan';
      btn.style.opacity = '0.8';
      btn.style.color = 'var(--accent-secondary)';
      btn.title = 'PLAN mode — read/search only';
    } else {
      label.textContent = 'Agent: OFF';
      btn.style.opacity = '0.5';
      btn.style.color = '';
      btn.title = 'ASK mode — read/search only';
    }
  }

  function setMode(mode) {
    mode = String(mode || '').toLowerCase();
    if (mode === 'chat') mode = 'ask';
    if (mode === 'agentic') mode = 'agent';
    if (['ask', 'plan', 'build', 'agent'].indexOf(mode) === -1) return false;

    SP.mode = mode;
    try { localStorage.setItem('rawrxd_screenpilot_mode', mode); } catch (_) {}

    document.querySelectorAll('[data-screenpilot-mode]').forEach(function (b) {
      var on = b.getAttribute('data-screenpilot-mode') === mode;
      b.classList.toggle('active', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });

    syncLegacyAgentUi();
    if (typeof logDebug === 'function') logDebug('[ScreenPilot] mode=' + mode, 'info');
    status((SP.available ? 'CANONICAL' : 'OFFLINE') + ' · ' + mode.toUpperCase(), SP.available);
    return true;
  }

  function mountModeUi() {
    if (byId('screenpilotModeBar')) return;

    var chatHeader = document.querySelector('.chat-header');
    if (chatHeader) {
      var wrap = document.createElement('div');
      wrap.id = 'screenpilotModeBar';
      wrap.className = 'mode-switcher';
      wrap.setAttribute('role', 'group');
      wrap.setAttribute('aria-label', 'ScreenPilot agent mode');

      ['ask', 'plan', 'build', 'agent'].forEach(function (mode) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'mode-btn';
        b.setAttribute('data-screenpilot-mode', mode);
        b.textContent = mode.toUpperCase();
        b.addEventListener('click', function () { setMode(mode); });
        wrap.appendChild(b);
      });

      var right = chatHeader.lastElementChild;
      chatHeader.insertBefore(wrap, right || null);
    }

    var toolbar = document.querySelector('.input-toolbar');
    if (toolbar && !byId('screenpilotWorkspace')) {
      var item = document.createElement('div');
      item.className = 'toolbar-item';
      item.style.cursor = 'default';
      item.innerHTML =
        '<span title="Canonical workspace root">&#x1F4C1;</span>' +
        '<input id="screenpilotWorkspace" type="text" spellcheck="false" ' +
        'aria-label="ScreenPilot workspace" ' +
        'style="width:160px;background:transparent;border:0;border-bottom:1px solid var(--border-subtle);' +
        'color:var(--text-secondary);font:11px var(--font-mono);outline:none;" />' +
        '<span id="screenpilotAuthorityStatus" style="font:10px var(--font-mono);">CHECKING</span>';
      toolbar.appendChild(item);

      var wi = byId('screenpilotWorkspace');
      wi.value = SP.workspace || '';
      wi.addEventListener('change', function () {
        SP.workspace = wi.value.trim();
        try { localStorage.setItem('rawrxd_workspace', SP.workspace); } catch (_) {}
      });
    }
  }

  function requestId() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    var a = new Uint32Array(4);
    if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(a);
    else {
      for (var i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 0xffffffff);
    }
    return 'sp-' + Date.now().toString(36) + '-' +
      Array.prototype.map.call(a, function (x) { return x.toString(16); }).join('');
  }

  async function fetchJson(path, init) {
    var res = await NativeFetch(API + path, Object.assign({
      credentials: 'same-origin',
      cache: 'no-store'
    }, init || {}));
    var text = await res.text();
    var obj = {};
    if (text) {
      try { obj = JSON.parse(text); }
      catch (_) { obj = { raw: text }; }
    }
    if (!res.ok) {
      var e = new Error((obj && obj.error) || ('HTTP ' + res.status));
      e.status = res.status;
      throw e;
    }
    return obj;
  }

  async function acquireSession(force) {
    if (SP.sessionToken && !force) return SP.sessionToken;
    var s = await fetchJson('/session', { method: 'POST' });
    if (!s.token) throw new Error('ScreenPilot session token missing');
    SP.sessionToken = s.token;
    return SP.sessionToken;
  }

  function authHeaders(extra) {
    var h = new Headers(extra || {});
    if (SP.sessionToken) h.set('X-RawrXD-Session', SP.sessionToken);
    return h;
  }

  async function initialize() {
    if (SP.initPromise) return SP.initPromise;

    SP.initPromise = (async function () {
      mountModeUi();

      if (location.protocol !== 'http:' ||
          !['127.0.0.1', 'localhost', '::1', '[::1]'].includes(location.hostname)) {
        SP.available = false;
        status('SERVE VIA :11435', false);
        throw new Error('Shipping ScreenPilot must be served from the localhost LocalServer, not file://');
      }

      var h = await fetchJson('/health');
      if (!h.ok || h.transport !== 'in-process' || h.authority !== 'canonical') {
        throw new Error('Canonical ScreenPilot authority route not active');
      }

      SP.health = h;
      SP.workspace = '';
      try { SP.workspace = localStorage.getItem('rawrxd_workspace') || ''; } catch (_) {}
      if (!SP.workspace) SP.workspace = h.workspaceRoot || '';
      var wi = byId('screenpilotWorkspace');
      if (wi) wi.value = SP.workspace;

      await acquireSession(true);
      SP.available = true;
      status('CANONICAL · ' + SP.mode.toUpperCase(), true);

      if (window.State) {
        State.backend.url = location.origin;
        State.backend.directMode = false;
        State.backend.online = true;
        State.backend.serverType = 'rawrxd-screenpilot-canonical';
      }

      if (typeof logDebug === 'function') {
        logDebug('[ScreenPilot] canonical in-process authority online', 'info');
      }
      return true;
    })().catch(function (e) {
      SP.available = false;
      status('AUTHORITY OFFLINE', false);
      if (typeof logDebug === 'function') logDebug('[ScreenPilot] ' + e.message, 'error');
      throw e;
    });

    return SP.initPromise;
  }

  function appendAgentChunk(textEl, aggregate, chunk) {
    aggregate.value += chunk;
    var snapshot = aggregate.value;
    requestAnimationFrame(function () {
      if (typeof formatMessage === 'function') textEl.innerHTML = formatMessage(snapshot);
      else textEl.textContent = snapshot;
      var c = byId('chatMessages');
      if (c) c.scrollTop = c.scrollHeight;
    });
  }

  function removeApprovalUi() {
    var old = byId('screenpilotApprovalOverlay');
    if (old) old.remove();
    SP.approval = null;
  }

  async function respondApproval(requestIdValue, approvalId, decision) {
    await NativeFetch(API + '/agent/approve', {
      method: 'POST',
      credentials: 'same-origin',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        requestId: requestIdValue,
        approvalId: approvalId,
        decision: decision
      })
    });
    removeApprovalUi();
  }

  function showApproval(requestIdValue, data) {
    removeApprovalUi();

    var overlay = document.createElement('div');
    overlay.id = 'screenpilotApprovalOverlay';
    overlay.style.cssText =
      'position:fixed;inset:0;z-index:200000;background:rgba(0,0,0,.72);display:flex;' +
      'align-items:center;justify-content:center;padding:24px;';

    var panel = document.createElement('div');
    panel.style.cssText =
      'width:min(680px,95vw);background:var(--bg-secondary);border:1px solid var(--accent-secondary);' +
      'border-radius:12px;padding:18px;box-shadow:0 20px 70px rgba(0,0,0,.6);';

    var title = document.createElement('div');
    title.textContent = 'ScreenPilot approval required';
    title.style.cssText = 'font-weight:700;color:var(--accent-secondary);margin-bottom:10px;';

    var body = document.createElement('pre');
    body.textContent =
      'Tool: ' + (data.tool || 'unknown') + '\n' +
      'Risk: ' + (data.risk || 'elevated') + '\n\n' +
      (data.summary || 'No summary provided.');
    body.style.cssText =
      'white-space:pre-wrap;color:var(--text-primary);background:var(--bg-primary);padding:12px;' +
      'border-radius:8px;max-height:45vh;overflow:auto;';

    var actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:10px;justify-content:flex-end;margin-top:14px;';

    var deny = document.createElement('button');
    deny.textContent = 'Deny';
    deny.className = 'code-btn';
    deny.addEventListener('click', function () {
      respondApproval(requestIdValue, data.approvalId, 'deny').catch(function (e) {
        if (typeof addMessage === 'function') addMessage('system', 'Approval response failed: ' + e.message);
      });
    });

    var approve = document.createElement('button');
    approve.textContent = 'Approve once';
    approve.className = 'code-btn';
    approve.style.borderColor = 'var(--accent-green)';
    approve.style.color = 'var(--accent-green)';
    approve.addEventListener('click', function () {
      respondApproval(requestIdValue, data.approvalId, 'approve').catch(function (e) {
        if (typeof addMessage === 'function') addMessage('system', 'Approval response failed: ' + e.message);
      });
    });

    actions.appendChild(deny);
    actions.appendChild(approve);
    panel.appendChild(title);
    panel.appendChild(body);
    panel.appendChild(actions);
    overlay.appendChild(panel);
    document.body.appendChild(overlay);

    SP.approval = { requestId: requestIdValue, approvalId: data.approvalId };
  }

  async function run(query) {
    await initialize();
    await acquireSession(false);

    var model = (window.State && State.model && State.model.current) || 'rawrxd';
    var workspace = (byId('screenpilotWorkspace') && byId('screenpilotWorkspace').value.trim()) ||
      SP.workspace || (SP.health && SP.health.workspaceRoot) || '';

    if (!workspace) throw new Error('Workspace is required');

    SP.workspace = workspace;
    try { localStorage.setItem('rawrxd_workspace', workspace); } catch (_) {}

    var id = requestId();
    SP.activeRequestId = id;
    SP.activeAbort = new AbortController();

    if (window.Conversation && Conversation.addMessage) {
      Conversation.addMessage('user', query);
    }

    var msgDiv = typeof addMessage === 'function'
      ? addMessage('assistant', '', { streaming: true, skipMemory: true })
      : null;
    var textEl = msgDiv ? msgDiv.querySelector('.message-text') : null;
    var aggregate = { value: '' };
    if (textEl) textEl.classList.add('streaming-cursor');

    var res;
    try {
      res = await NativeFetch(API + '/agent/run', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        signal: SP.activeAbort.signal,
        body: JSON.stringify({
          requestId: id,
          mode: SP.mode,
          model: model,
          workspace: workspace,
          prompt: query
        })
      });

      if (res.status === 401) {
        await acquireSession(true);
        throw new Error('Session rotated; resend the request');
      }
      if (!res.ok || !res.body) {
        throw new Error('ScreenPilot agent HTTP ' + res.status + ': ' + await res.text());
      }

      var reader = res.body.getReader();
      var decoder = new TextDecoder('utf-8');
      var pending = '';
      var exitCode = null;

      while (true) {
        var part = await reader.read();
        if (part.done) break;
        pending += decoder.decode(part.value, { stream: true });

        var nl;
        while ((nl = pending.indexOf('\n')) >= 0) {
          var line = pending.slice(0, nl).trim();
          pending = pending.slice(nl + 1);
          if (!line) continue;

          var evt;
          try { evt = JSON.parse(line); }
          catch (_) {
            if (textEl) appendAgentChunk(textEl, aggregate, line + '\n');
            continue;
          }

          if (evt.requestId && evt.requestId !== id) continue;

          if (evt.type === 'approval_required') {
            var approvalData = {};
            try { approvalData = JSON.parse(evt.data || '{}'); }
            catch (_) { approvalData = { summary: evt.data || '' }; }
            showApproval(id, approvalData);
            continue;
          }

          if (evt.type === 'started' || evt.type === 'status') {
            status('RUNNING · ' + SP.mode.toUpperCase(), true);
            continue;
          }

          if (evt.type === 'exit') {
            exitCode = Number(evt.data);
            continue;
          }

          var chunk = evt.data == null ? '' : String(evt.data);
          if (!chunk) continue;

          if (evt.type === 'tool') chunk = '\n[tool] ' + chunk + '\n';
          else if (evt.type === 'receipt') chunk = '\n[receipt] ' + chunk + '\n';
          else if (evt.type === 'error') chunk = '\n[error] ' + chunk + '\n';

          if (textEl) appendAgentChunk(textEl, aggregate, chunk);
        }
      }

      if (textEl) {
        textEl.classList.remove('streaming-cursor');
        if (typeof formatMessage === 'function') textEl.innerHTML = formatMessage(aggregate.value);
        else textEl.textContent = aggregate.value;
      }

      if (aggregate.value && window.Conversation && Conversation.addMessage) {
        Conversation.addMessage('assistant', aggregate.value);
      }

      if (exitCode !== null && exitCode !== 0 && typeof addMessage === 'function') {
        addMessage('system', 'ScreenPilot agent exited with code ' + exitCode, { skipMemory: true });
      }

      status('CANONICAL · ' + SP.mode.toUpperCase(), true);
      return aggregate.value;
    } catch (e) {
      if (e && e.name === 'AbortError') {
        status('CANCELLED · ' + SP.mode.toUpperCase(), null);
        return aggregate.value;
      }
      status('AUTHORITY ERROR', false);
      if (typeof addMessage === 'function') {
        addMessage('system', 'ScreenPilot authority error: ' + e.message, { skipMemory: true });
      }
      throw e;
    } finally {
      removeApprovalUi();
      SP.activeRequestId = '';
      SP.activeAbort = null;
      if (textEl) textEl.classList.remove('streaming-cursor');
    }
  }

  async function cancel() {
    var id = SP.activeRequestId;
    if (!id) return false;

    try {
      await NativeFetch(API + '/agent/cancel', {
        method: 'POST',
        credentials: 'same-origin',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ requestId: id })
      });
    } finally {
      if (SP.activeAbort) SP.activeAbort.abort();
      removeApprovalUi();
    }
    return true;
  }

  // Attach the session header to same-origin legacy privileged calls too.
  // Server middleware can use RawrXD_ScreenPilot_ValidateBrowserSession().
  window.fetch = function (input, init) {
    init = init || {};
    var raw = typeof input === 'string' ? input : input.url;
    var u;
    try { u = new URL(raw, location.href); } catch (_) { return NativeFetch(input, init); }

    if (SP.sessionToken && u.origin === location.origin &&
        (u.pathname.startsWith('/api/') || u.pathname.startsWith('/v1/'))) {
      init.headers = authHeaders(init.headers);
    }
    return NativeFetch(input, init);
  };

  // Main chat path: fail closed if canonical authority is absent.
  var legacySendToBackend = window.sendToBackend;
  window.sendToBackend = async function (query) {
    try {
      if (!SP.available) await initialize();
      if (SP.available) return await run(query);
    } catch (e) {
      if (SP.legacyFallback && typeof legacySendToBackend === 'function') {
        if (typeof logDebug === 'function') logDebug('[ScreenPilot] explicit legacy fallback: ' + e.message, 'warn');
        return legacySendToBackend(query);
      }
      throw e;
    }
  };

  var legacyStopGeneration = window.stopGeneration;
  window.stopGeneration = function () {
    if (SP.activeRequestId) {
      cancel().catch(function (e) {
        if (typeof logDebug === 'function') logDebug('[ScreenPilot] cancel failed: ' + e.message, 'error');
      });
      if (typeof showSendHideStop === 'function') showSendHideStop();
      return;
    }
    if (typeof legacyStopGeneration === 'function') return legacyStopGeneration();
  };

  var legacySetMode = window.setMode;
  window.setMode = function (mode) {
    var m = String(mode || '').toLowerCase();
    if (['ask', 'plan', 'build', 'agent', 'chat', 'agentic'].includes(m)) return setMode(m);
    if (typeof legacySetMode === 'function') return legacySetMode(mode);
    return false;
  };

  window.toggleAgenticMode = function () {
    setMode(SP.mode === 'agent' ? 'ask' : 'agent');
  };

  // Message code actions are delegated, so sanitized assistant HTML never needs onclick.
  document.addEventListener('click', function (event) {
    var b = event.target.closest ? event.target.closest('[data-code-action]') : null;
    if (!b) return;
    var a = b.getAttribute('data-code-action');
    if (a === 'copy' && typeof copyCode === 'function') copyCode(b);
    else if (a === 'keep' && typeof keepCode === 'function') keepCode(b);
    else if (a === 'undo' && typeof undoCode === 'function') undoCode(b);
  });

  // Replace the MWM fake compiler completion with a real canonical BUILD request.
  if (window.MWM && typeof MWM.compileAction === 'function') {
    MWM.compileAction = function (id, type) {
      var log = byId(id + '-log');
      if (log) log.textContent += '[Build] canonical BUILD requested: ' + type + '\n';
      var prompt =
        'Use canonical Tool Authority in BUILD mode. Run the project ' + type +
        ' build for workspace ' + (SP.workspace || '') +
        '. Report the exact command, exit code, compiler errors, and verification receipt.';

      var priorMode = SP.mode;
      setMode('build');
      run(prompt).then(function (out) {
        if (log) log.textContent += out + '\n';
      }).catch(function (e) {
        if (log) log.textContent += '[Build] ERROR: ' + e.message + '\n';
      }).finally(function () {
        setMode(priorMode);
      });
    };
  }


  // Replace the MWM reverse-analysis placeholder with a real canonical ASK task.
  if (window.MWM && typeof MWM.reAction === 'function') {
    MWM.reAction = function (id, type) {
      var hex = byId(id + '-hex');
      if (hex) hex.textContent = '[RE] canonical analysis requested: ' + type + '\n\n';

      var priorMode = SP.mode;
      setMode('ask');
      var prompt =
        'Use canonical Tool Authority in ASK mode. Perform ' + type +
        ' reverse-engineering analysis within workspace ' + (SP.workspace || '') +
        '. Do not modify files. Return evidence and exact limitations.';

      run(prompt).then(function (out) {
        if (hex) hex.textContent = out;
      }).catch(function (e) {
        if (hex) hex.textContent = '[RE] ERROR: ' + e.message;
      }).finally(function () {
        setMode(priorMode);
      });
    };
  }

  // The original HTML advertised a MASM native bridge while using no-op JS
  // methods. Keep an actually functional browser scheduler fallback, but label
  // it honestly. Native MASM integration remains a separate optional backend.
  if (window.MWM && MWM.kernel) {
    (function upgradeMwmKernelFallback(kernel) {
      var tasks = new Map();
      var registered = new Map();
      var processed = 0;
      var startedAt = Date.now();
      var nextFallbackId = 1000000;

      kernel.backend = 'browser-fallback';
      kernel.native = false;

      kernel.init = function () {
        kernel.backend = 'browser-fallback';
        kernel.native = false;
        return true;
      };

      kernel.submitTask = function (type, priority, windowId, callback) {
        var id = ++nextFallbackId;
        var record = {
          id: id,
          type: type,
          priority: priority,
          windowId: windowId,
          cancelled: false
        };
        tasks.set(id, record);

        queueMicrotask(function () {
          var current = tasks.get(id);
          if (!current || current.cancelled) return;
          try {
            if (typeof callback === 'function') callback();
          } finally {
            tasks.delete(id);
            processed++;
          }
        });
        return id;
      };

      kernel.cancelTask = function (taskId) {
        var t = tasks.get(taskId);
        if (!t) return false;
        t.cancelled = true;
        tasks.delete(taskId);
        return true;
      };

      kernel.registerWindow = function (type, x, y, w, h) {
        var id = ++nextFallbackId;
        registered.set(id, { type: type, x: x, y: y, w: w, h: h });
        return id;
      };

      kernel.unregisterWindow = function (windowId) {
        return registered.delete(windowId);
      };

      kernel.sendIPC = function (msg, src, dst, payload) {
        var ev = new CustomEvent('rawrxd:mwm:ipc', {
          detail: { message: msg, source: src, destination: dst, payload: payload }
        });
        window.dispatchEvent(ev);
        return true;
      };

      kernel.getStats = function () {
        return {
          backend: 'browser-fallback',
          native: false,
          activeWindows: registered.size,
          activeTasks: tasks.size,
          totalProcessed: processed,
          workerCount: 1,
          uptimeMs: Date.now() - startedAt
        };
      };

      kernel.swarmBroadcast = function (type, payload, modelCount) {
        window.dispatchEvent(new CustomEvent('rawrxd:mwm:swarm', {
          detail: { type: type, payload: payload, modelCount: modelCount }
        }));
        return Number(modelCount) || 0;
      };

      kernel.chainOfThought = function (windowId, steps, callbacks) {
        var list = Array.isArray(callbacks) ? callbacks.slice() : [];
        return kernel.submitTask('chain-of-thought', 0, windowId, function () {
          for (var i = 0; i < list.length; i++) {
            if (typeof list[i] === 'function') list[i](i, steps);
          }
        });
      };
    })(MWM.kernel);
  }

  try {
    var saved = localStorage.getItem('rawrxd_screenpilot_mode');
    if (saved && ['ask', 'plan', 'build', 'agent'].includes(saved)) SP.mode = saved;
  } catch (_) {}

  mountModeUi();
  setMode(SP.mode);

  window.ScreenPilotAuthority = {
    state: SP,
    init: initialize,
    run: run,
    cancel: cancel,
    setMode: setMode,
    acquireSession: acquireSession
  };

  // Start authority probing before DOMContentLoaded handlers invoke backend discovery.
  initialize().catch(function () {});
})();
