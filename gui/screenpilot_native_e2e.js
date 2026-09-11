/* screenpilot_native_e2e.js */
(function () {
  'use strict';

  var NativeE2E = {
    online: false,
    caps: null,
    routes: {},
    lastPrepare: null,
    lastReceipt: null,

    base: function () {
      return (typeof getActiveUrl === 'function')
        ? getActiveUrl()
        : 'http://127.0.0.1:11435';
    },

    get: async function (path, timeout) {
      var r = await fetch(this.base() + path, {
        method: 'GET',
        signal: AbortSignal.timeout(timeout || 8000)
      });
      var text = await r.text(), data;
      try { data = JSON.parse(text); } catch (_) { data = { raw: text }; }
      if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + path);
      return data;
    },

    post: async function (path, body, timeout) {
      var r = await fetch(this.base() + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
        signal: AbortSignal.timeout(timeout || 15000)
      });
      var text = await r.text(), data;
      try { data = JSON.parse(text); } catch (_) { data = { raw: text }; }
      if (!r.ok) {
        throw new Error('HTTP ' + r.status + ' ' + path + ': ' +
                        text.substring(0, 160));
      }
      return data;
    },

    refresh: async function () {
      try {
        this.caps = await this.get('/api/native/capabilities');
        var rr = await this.get('/api/native/routes');
        this.routes = {};
        (rr.routes || []).forEach(function (r) {
          NativeE2E.routes[r.path] = r;
        });
        this.online = true;
      } catch (e) {
        this.caps = { ok: false, error: e.message };
        this.routes = {};
        this.online = false;
      }
      this.updateBadge();
      return this.online;
    },

    updateBadge: function () {
      var el = document.getElementById('nativeE2EBadge');
      if (!el) {
        el = document.createElement('span');
        el.id = 'nativeE2EBadge';
        el.style.cssText =
          'font-size:10px;padding:2px 6px;border-radius:10px;margin-left:8px;';
        var title = document.querySelector('#enginePanel .agent-title');
        if (title) title.appendChild(el);
      }
      if (!el) return;
      el.textContent = this.online ? 'NATIVE E2E' : 'NATIVE OFFLINE';
      el.style.background = this.online
        ? 'rgba(46,204,113,.15)' : 'rgba(231,76,60,.15)';
      el.style.color = this.online
        ? 'var(--accent-green)' : 'var(--accent-red)';
    },

    hopStrategyId: function (name) {
      var map = { auto: 0, even: 1, front: 2, back: 3, custom: 4 };
      return map[name] == null ? 0 : map[name];
    },

    prepareGeneration: async function (query) {
      if (State.backend && State.backend.directMode) {
        this.lastPrepare = null;
        return null;
      }

      var safe = State.gen.safeDecodeProfile || {};
      var hop = State.gen.tensorHop || {};
      var custom = Array.isArray(hop.customSkip) ? hop.customSkip : [];

      this.lastPrepare = await this.post('/api/native/generation/prepare', {
        model: State.model.current || '',
        context: State.gen.context >>> 0,
        max_tokens: State.gen.maxTokens >>> 0,
        temperature_milli:
          Math.max(0, Math.round((State.gen.temperature || 0) * 1000)),
        top_p_milli:
          Math.max(0, Math.round((State.gen.top_p || 0) * 1000)),
        top_k: State.gen.top_k >>> 0,
        stream: !!State.gen.stream,

        safe_enabled: !!safe.enabled,
        safe_context: safe.safeContext >>> 0,
        safe_max_tokens: safe.safeMaxTokens >>> 0,
        safe_temperature_milli:
          Math.max(0, Math.round((safe.safeTemperature || 0) * 1000)),
        safe_top_p_milli:
          Math.max(0, Math.round((safe.safeTopP || 0) * 1000)),
        safe_top_k: safe.safeTopK >>> 0,

        hop_enabled: !!hop.enabled,
        hop_strategy: this.hopStrategyId(hop.strategy),
        hop_skip_permille:
          Math.max(0, Math.min(500, Math.round((hop.skipRatio || 0) * 1000))),
        hop_keep_first: hop.keepFirst >>> 0,
        hop_keep_last: hop.keepLast >>> 0,
        hop_custom_csv: custom.join(','),

        prompt_bytes: new TextEncoder().encode(query || '').length
      }, 10000);

      return this.lastPrepare;
    },

    fetchReceipt: async function (id) {
      if (!id) return null;
      try {
        this.lastReceipt = await this.get(
          '/api/native/receipt/' + encodeURIComponent(id), 5000);
        return this.lastReceipt;
      } catch (_) {
        return null;
      }
    },

    proofLabel: function (r) {
      if (!r) return 'NO RECEIPT';
      if (!r.qpc_engine_enter) return 'PREPARED / NOT EXECUTED';
      if (!r.qpc_first_token) return 'ENGINE ENTERED / NO TOKEN';
      if (!r.qpc_end) return 'STREAMING';
      return r.engine_status === 0 ? 'EXECUTED' : 'ENGINE FAIL';
    },

    routeFor: function (path) {
      if (this.routes[path]) return this.routes[path];
      var keys = Object.keys(this.routes);
      for (var i = 0; i < keys.length; ++i) {
        var p = keys[i];
        if (p.indexOf('*') >= 0 &&
            path.indexOf(p.substring(0, p.indexOf('*'))) === 0) {
          return this.routes[p];
        }
      }
      return null;
    },

    probeRoute: function (path) {
      return this.post('/api/native/route/probe', { path: path }, 5000);
    },

    executeEndpoint: async function (path) {
      var rr = this.routeFor(path);
      if (!rr) {
        addMessage('system',
          'Engine Explorer: `' + path +
          '` is not declared by the native route registry.',
          { skipMemory: true });
        return;
      }
      if (!rr.attached) {
        addMessage('system',
          'Engine Explorer: `' + path +
          '` is declared but **not attached** to a live handler.',
          { skipMemory: true });
        return;
      }
      if (path.indexOf('*') >= 0) {
        addMessage('system',
          'Engine Explorer: expand wildcard route `' + path +
          '` to a concrete path before execution.',
          { skipMemory: true });
        return;
      }

      try {
        var data;
        if (rr.method === 'GET') {
          data = await EngineAPI._get(path, 15000);
        } else {
          var raw = window.prompt(
            'POST body for ' + path + ' (JSON)', '{}');
          if (raw === null) return;
          var body;
          try { body = JSON.parse(raw || '{}'); }
          catch (e) { throw new Error('Invalid JSON: ' + e.message); }
          if (!window.confirm(
              'Execute POST ' + path + ' against localhost RawrXD?')) return;
          data = await EngineAPI._post(path, body, 60000);
        }
        addMessage('system',
          '**Engine Explorer E2E** `' + path + '`\\n```json\\n' +
          JSON.stringify(data, null, 2).substring(0, 12000) +
          '\\n```', { skipMemory: true });
      } catch (e) {
        addMessage('system',
          '**Engine Explorer FAIL** `' + path + '` — ' + e.message,
          { skipMemory: true });
      }
    },

    esc: function (v) {
      return String(v == null ? '' : v)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },

    renderExplorer: function (filter) {
      var el = document.getElementById('engineMapContent');
      if (!el || typeof EngineAPI === 'undefined' ||
          !EngineAPI.SUBSYSTEMS) return;

      var q = String(filter || '').toLowerCase();
      var keys = Object.keys(EngineAPI.SUBSYSTEMS);
      var totalFiles = 0, totalEndpoints = 0;

      var h =
        '<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;">' +
        '<button class="code-btn" data-native-refresh="1">Probe Native</button>' +
        '<span style="font-size:10px;color:var(--text-muted);">' +
        (this.online
          ? 'model bridge + native route registry reachable'
          : 'native proof bridge unavailable') +
        '</span></div>';

      for (var i = 0; i < keys.length; ++i) {
        var name = keys[i], sub = EngineAPI.SUBSYSTEMS[name];
        var match = !q ||
          name.toLowerCase().indexOf(q) >= 0 ||
          sub.files.some(function (f) {
            return f.toLowerCase().indexOf(q) >= 0;
          }) ||
          sub.endpoints.some(function (e) {
            return e.toLowerCase().indexOf(q) >= 0;
          });
        if (!match) continue;

        totalFiles += sub.files.length;
        totalEndpoints += sub.endpoints.length;

        h += '<div style="margin-bottom:12px;border:1px solid var(--border);' +
             'border-radius:6px;padding:8px;">';
        h += '<div style="font-weight:bold;color:var(--accent-cyan);' +
             'margin-bottom:4px;">' + this.esc(name) + '</div>';
        h += '<div style="font-size:10px;color:var(--text-secondary);' +
             'margin-bottom:6px;">' + this.esc(sub.desc) + '</div>';
        h += '<div style="font-size:10px;color:var(--accent-green);' +
             'margin-bottom:5px;">Files: ';

        sub.files.forEach(function (f) {
          h += '<code style="margin-right:4px;">' +
               NativeE2E.esc(f) + '</code>';
        });
        h += '</div>';

        if (sub.endpoints.length) {
          h += '<div style="font-size:10px;color:var(--accent-orange);">' +
               'Endpoints:';
          sub.endpoints.forEach(function (ep) {
            var rr = NativeE2E.routeFor(ep);
            var state = !rr
              ? 'UNDECLARED' : (rr.attached ? 'ATTACHED' : 'DECLARED');
            var color = !rr
              ? 'var(--accent-red)'
              : (rr.attached
                 ? 'var(--accent-green)' : 'var(--accent-orange)');
            var method = rr ? rr.method : '?';

            h += '<div style="display:flex;align-items:center;gap:6px;' +
                 'margin:3px 0;">' +
                 '<span style="min-width:48px;color:var(--text-muted);">' +
                 NativeE2E.esc(method) + '</span>' +
                 '<code style="flex:1;">' + NativeE2E.esc(ep) + '</code>' +
                 '<span style="font-size:9px;color:' + color + ';">' +
                 state + '</span>' +
                 '<button class="code-btn" data-native-probe="' +
                 NativeE2E.esc(ep) + '">Probe</button>' +
                 '<button class="code-btn" data-native-run="' +
                 NativeE2E.esc(ep) + '"' +
                 (rr && rr.attached ? '' : ' disabled') +
                 '>Run</button></div>';
          });
          h += '</div>';
        }
        h += '</div>';
      }

      el.innerHTML =
        '<div style="margin-bottom:8px;color:var(--accent-secondary);' +
        'font-size:11px;">' +
        keys.length + ' subsystems, ' + totalFiles + ' files, ' +
        totalEndpoints + ' endpoints — ' +
        Object.keys(this.routes).length +
        ' native route patterns</div>' + h;

      var refresh = el.querySelector('[data-native-refresh]');
      if (refresh) {
        refresh.addEventListener('click', function () {
          NativeE2E.refresh().then(function () {
            NativeE2E.renderExplorer(
              (document.getElementById('engineSearchInput') || {}).value || '');
          });
        });
      }

      el.querySelectorAll('[data-native-probe]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var path = btn.getAttribute('data-native-probe');
          NativeE2E.probeRoute(path).then(function (x) {
            addMessage('system',
              '```json\\n' + JSON.stringify(x, null, 2) + '\\n```',
              { skipMemory: true });
          }).catch(function (e) {
            addMessage('system',
              '**Native route probe failed:** ' + e.message,
              { skipMemory: true });
          });
        });
      });

      el.querySelectorAll('[data-native-run]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          NativeE2E.executeEndpoint(
            btn.getAttribute('data-native-run'));
        });
      });
    }
  };

  window.RawrNativeE2E = NativeE2E;

  var oldBuildExtras = window.buildOpenAIPayloadExtras;
  if (typeof oldBuildExtras === 'function') {
    window.buildOpenAIPayloadExtras = function () {
      var x = oldBuildExtras();
      var p = NativeE2E.lastPrepare;
      if (p && p.ok && p.policy) {
        x.max_tokens = p.policy.max_tokens;
        x.temperature = p.policy.temperature_milli / 1000;
        x.top_p = p.policy.top_p_milli / 1000;
        x.top_k = p.policy.top_k;
        x.rawr_native_request_id = p.request_id;
        x.rawr_native_policy_flags = p.policy.flags;
        x.rawr_native_policy = {
          safe_prepared: !!p.policy.safe_prepared,
          tensor_hop_prepared: !!p.policy.hop_prepared,
          tensor_hop_needs_engine: !!p.policy.hop_needs_engine,
          hop_skip_count: p.policy.hop_skip_count
        };
        if (x.options) x.options.num_ctx = p.policy.context;
      }
      return x;
    };
  }

  var oldSendToBackend = window.sendToBackend;
  if (typeof oldSendToBackend === 'function') {
    window.sendToBackend = async function (query) {
      if (!State.backend.directMode) {
        try {
          if (!NativeE2E.online) await NativeE2E.refresh();
          if (!NativeE2E.online)
            throw new Error('native bridge is not reachable');

          var prep = await NativeE2E.prepareGeneration(query);
          if (!prep || !prep.ok)
            throw new Error('generation prepare rejected');

          logDebug('[NativeE2E] request_id=' + prep.request_id +
                   ' prepared_flags=' + prep.policy.flags, 'info');
        } catch (e) {
          addMessage('system',
            'Native E2E gate rejected the RawrXD request: **' +
            e.message + '**.',
            { skipMemory: true });
          return;
        }
      }

      await oldSendToBackend(query);

      if (NativeE2E.lastPrepare &&
          NativeE2E.lastPrepare.request_id) {
        var receipt = await NativeE2E.fetchReceipt(
          NativeE2E.lastPrepare.request_id);
        if (receipt) {
          logDebug('[NativeE2E] receipt ' + receipt.request_id +
                   ' = ' + NativeE2E.proofLabel(receipt), 'info');
        }
      }
    };
  }

  if (window.EngineAPI && EngineAPI.SUBSYSTEMS) {
    EngineAPI.renderSubsystemMap = function (filter) {
      NativeE2E.renderExplorer(filter);
    };
  }

  window.renderEngineMap = async function () {
    await NativeE2E.refresh();
    NativeE2E.renderExplorer(
      (document.getElementById('engineSearchInput') || {}).value || '');
  };

  window.filterEngineMap = function (v) {
    NativeE2E.renderExplorer(v);
  };

  setTimeout(function () { NativeE2E.refresh(); }, 250);
})();
