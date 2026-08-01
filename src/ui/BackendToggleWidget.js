// src/ui/BackendToggleWidget.js
// UI toggle for switching between PowerShell and BareMetal backends.
// Communicates with the native BackendManager via RawrRuntime bridge.

(function() {
    'use strict';

    // -----------------------------------------------------------------------
    // Backend metadata
    // -----------------------------------------------------------------------
    const BACKENDS = {
        PowerShell: {
            id: 'PowerShell',
            label: 'PowerShell Automation',
            icon: '⚡',
            description: 'Script-driven builds via Win32 API bridge. Best for rapid iteration.',
            capabilities: ['Compile', 'Link', 'Audit', 'Smoke']
        },
        BareMetal: {
            id: 'BareMetal',
            label: 'Bare-Metal Native',
            icon: '🔧',
            description: 'Direct ml64.exe / cl.exe invocation. Zero-dependency, air-gapped ready.',
            capabilities: ['Compile', 'Link', 'Smoke', 'GPU', 'Telemetry']
        },
        Remote: {
            id: 'Remote',
            label: 'Remote Build Farm',
            icon: '🌐',
            description: 'Distributed compilation across remote agents. (Coming soon)',
            capabilities: ['Compile', 'Remote']
        },
        Sandbox: {
            id: 'Sandbox',
            label: 'Sandbox Isolated',
            icon: '🛡️',
            description: 'Isolated sandbox builds with rollback. (Coming soon)',
            capabilities: ['Compile', 'Sandbox']
        }
    };

    // -----------------------------------------------------------------------
    // Widget state
    // -----------------------------------------------------------------------
    let currentBackend = 'PowerShell';
    let isHealthy = false;
    let telemetryInterval = null;

    // -----------------------------------------------------------------------
    // DOM helpers
    // -----------------------------------------------------------------------
    function createElement(tag, className, text) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        if (text) el.textContent = text;
        return el;
    }

    // -----------------------------------------------------------------------
    // Build the widget UI
    // -----------------------------------------------------------------------
    function renderWidget(container) {
        container.innerHTML = '';
        container.className = 'backend-toggle-widget';

        const header = createElement('div', 'widget-header');
        header.appendChild(createElement('h3', null, 'Backend Engine'));
        const statusBadge = createElement('span', 'status-badge', '●');
        statusBadge.id = 'backend-status-badge';
        header.appendChild(statusBadge);
        container.appendChild(header);

        const currentInfo = createElement('div', 'current-backend');
        currentInfo.id = 'current-backend-info';
        container.appendChild(currentInfo);

        const grid = createElement('div', 'backend-grid');
        Object.values(BACKENDS).forEach(backend => {
            const card = createElement('div', 'backend-card');
            card.dataset.backend = backend.id;
            if (backend.id === currentBackend) card.classList.add('active');

            const icon = createElement('span', 'backend-icon', backend.icon);
            const label = createElement('span', 'backend-label', backend.label);
            const desc = createElement('span', 'backend-desc', backend.description);

            const caps = createElement('div', 'backend-caps');
            backend.capabilities.forEach(cap => {
                const tag = createElement('span', 'cap-tag', cap);
                caps.appendChild(tag);
            });

            card.appendChild(icon);
            card.appendChild(label);
            card.appendChild(desc);
            card.appendChild(caps);

            card.addEventListener('click', () => selectBackend(backend.id));
            grid.appendChild(card);
        });
        container.appendChild(grid);

        const actions = createElement('div', 'widget-actions');
        const buildBtn = createElement('button', 'action-btn primary', '▶ Run Build');
        buildBtn.addEventListener('click', () => runBuild());
        const smokeBtn = createElement('button', 'action-btn', '🧪 Smoke Test');
        smokeBtn.addEventListener('click', () => runSmokeTest());
        const auditBtn = createElement('button', 'action-btn', '🔍 Audit');
        auditBtn.addEventListener('click', () => runAudit());
        actions.appendChild(buildBtn);
        actions.appendChild(smokeBtn);
        actions.appendChild(auditBtn);
        container.appendChild(actions);

        const telemetry = createElement('div', 'telemetry-panel');
        telemetry.id = 'backend-telemetry';
        telemetry.innerHTML = '<pre>Waiting for telemetry...</pre>';
        container.appendChild(telemetry);

        updateCurrentInfo();
        startTelemetryPolling();
    }

    // -----------------------------------------------------------------------
    // Update current backend display
    // -----------------------------------------------------------------------
    function updateCurrentInfo() {
        const info = document.getElementById('current-backend-info');
        if (!info) return;
        const backend = BACKENDS[currentBackend];
        info.innerHTML = `
            <div class="backend-active-row">
                <span class="backend-icon-large">${backend.icon}</span>
                <div>
                    <strong>${backend.label}</strong>
                    <span class="backend-id">${backend.id}</span>
                </div>
            </div>
        `;

        const badge = document.getElementById('backend-status-badge');
        if (badge) {
            badge.className = 'status-badge ' + (isHealthy ? 'healthy' : 'unhealthy');
            badge.title = isHealthy ? 'Backend healthy' : 'Backend not responding';
        }
    }

    // -----------------------------------------------------------------------
    // Backend selection
    // -----------------------------------------------------------------------
    async function selectBackend(id) {
        currentBackend = id;

        // Update UI
        document.querySelectorAll('.backend-card').forEach(card => {
            card.classList.toggle('active', card.dataset.backend === id);
        });
        updateCurrentInfo();

        // Notify native layer
        if (window.RawrRuntime && RawrRuntime.selectBackend) {
            try {
                const result = await RawrRuntime.selectBackend(id);
                isHealthy = result.success;
                updateCurrentInfo();
            } catch (e) {
                console.error('Backend selection failed:', e);
                isHealthy = false;
                updateCurrentInfo();
            }
        }
    }

    // -----------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------
    async function runBuild() {
        const telemetry = document.getElementById('backend-telemetry');
        if (telemetry) telemetry.innerHTML = '<pre>Building...</pre>';

        if (window.RawrRuntime && RawrRuntime.executeBuild) {
            try {
                const result = await RawrRuntime.executeBuild('compile');
                showResult(result);
            } catch (e) {
                showResult({ success: false, stderrLog: e.message });
            }
        } else {
            showResult({ success: false, stderrLog: 'RawrRuntime not available' });
        }
    }

    async function runSmokeTest() {
        const telemetry = document.getElementById('backend-telemetry');
        if (telemetry) telemetry.innerHTML = '<pre>Running smoke test...</pre>';

        if (window.RawrRuntime && RawrRuntime.executeSmokeTest) {
            try {
                const result = await RawrRuntime.executeSmokeTest();
                showResult(result);
            } catch (e) {
                showResult({ success: false, stderrLog: e.message });
            }
        } else {
            showResult({ success: false, stderrLog: 'RawrRuntime not available' });
        }
    }

    async function runAudit() {
        const telemetry = document.getElementById('backend-telemetry');
        if (telemetry) telemetry.innerHTML = '<pre>Running audit...</pre>';

        if (window.RawrRuntime && RawrRuntime.runAudit) {
            try {
                const result = await RawrRuntime.runAudit();
                showAuditResult(result);
            } catch (e) {
                showResult({ success: false, stderrLog: e.message });
            }
        } else {
            showResult({ success: false, stderrLog: 'RawrRuntime not available' });
        }
    }

    // -----------------------------------------------------------------------
    // Result display
    // -----------------------------------------------------------------------
    function showResult(result) {
        const telemetry = document.getElementById('backend-telemetry');
        if (!telemetry) return;
        const status = result.success ? '✅ SUCCESS' : '❌ FAILED';
        telemetry.innerHTML = `<pre>${status}\nExit: ${result.exitCode || 0}\nDuration: ${result.durationMs || 0}ms\n\n${result.stdoutLog || ''}\n${result.stderrLog || ''}</pre>`;
    }

    function showAuditResult(metrics) {
        const telemetry = document.getElementById('backend-telemetry');
        if (!telemetry) return;
        telemetry.innerHTML = `<pre>
🔍 Audit Results
────────────────
Info:     ${metrics.infoCount || 0}
Low:      ${metrics.lowCount || 0}
Medium:   ${metrics.mediumCount || 0}
High:     ${metrics.highCount || 0}
Critical: ${metrics.criticalCount || 0}
Total:    ${(metrics.infoCount || 0) + (metrics.lowCount || 0) + (metrics.mediumCount || 0) + (metrics.highCount || 0) + (metrics.criticalCount || 0)}
        </pre>`;
    }

    // -----------------------------------------------------------------------
    // Telemetry polling
    // -----------------------------------------------------------------------
    function startTelemetryPolling() {
        if (telemetryInterval) clearInterval(telemetryInterval);
        telemetryInterval = setInterval(async () => {
            if (window.RawrRuntime && RawrRuntime.pollTelemetry) {
                try {
                    const snapshot = await RawrRuntime.pollTelemetry();
                    const panel = document.getElementById('backend-telemetry');
                    if (panel && panel.innerHTML.includes('Waiting')) {
                        panel.innerHTML = `<pre>📊 Telemetry\n${JSON.stringify(snapshot, null, 2)}</pre>`;
                    }
                } catch (e) {
                    // Silent fail — telemetry is best-effort
                }
            }
        }, 5000);
    }

    // -----------------------------------------------------------------------
    // CSS injection
    // -----------------------------------------------------------------------
    function injectStyles() {
        if (document.getElementById('backend-toggle-styles')) return;
        const style = document.createElement('style');
        style.id = 'backend-toggle-styles';
        style.textContent = `
            .backend-toggle-widget {
                background: #1e1e2e;
                border: 1px solid #313244;
                border-radius: 8px;
                padding: 16px;
                color: #cdd6f4;
                font-family: 'Segoe UI', system-ui, sans-serif;
                max-width: 480px;
            }
            .widget-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
            }
            .widget-header h3 {
                margin: 0;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: #89b4fa;
            }
            .status-badge {
                font-size: 18px;
                transition: color 0.3s;
            }
            .status-badge.healthy { color: #a6e3a1; }
            .status-badge.unhealthy { color: #f38ba8; }
            .current-backend {
                background: #181825;
                border-radius: 6px;
                padding: 10px 12px;
                margin-bottom: 12px;
            }
            .backend-active-row {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .backend-icon-large { font-size: 24px; }
            .backend-id {
                display: block;
                font-size: 11px;
                color: #6c7086;
                margin-top: 2px;
            }
            .backend-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 8px;
                margin-bottom: 12px;
            }
            .backend-card {
                background: #181825;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 10px;
                cursor: pointer;
                transition: all 0.2s;
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            .backend-card:hover {
                border-color: #89b4fa;
                background: #1e1e2e;
            }
            .backend-card.active {
                border-color: #a6e3a1;
                background: #1e2a1e;
            }
            .backend-icon { font-size: 18px; }
            .backend-label {
                font-weight: 600;
                font-size: 12px;
            }
            .backend-desc {
                font-size: 10px;
                color: #6c7086;
                line-height: 1.3;
            }
            .backend-caps {
                display: flex;
                flex-wrap: wrap;
                gap: 4px;
                margin-top: 4px;
            }
            .cap-tag {
                background: #313244;
                color: #cdd6f4;
                font-size: 9px;
                padding: 2px 6px;
                border-radius: 3px;
            }
            .widget-actions {
                display: flex;
                gap: 8px;
                margin-bottom: 12px;
            }
            .action-btn {
                flex: 1;
                background: #313244;
                border: 1px solid #45475a;
                color: #cdd6f4;
                padding: 8px 12px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                transition: all 0.2s;
            }
            .action-btn:hover {
                background: #45475a;
            }
            .action-btn.primary {
                background: #89b4fa;
                color: #1e1e2e;
                border-color: #89b4fa;
            }
            .action-btn.primary:hover {
                background: #b4befe;
            }
            .telemetry-panel {
                background: #11111b;
                border-radius: 4px;
                padding: 10px;
                font-size: 11px;
                max-height: 200px;
                overflow-y: auto;
            }
            .telemetry-panel pre {
                margin: 0;
                white-space: pre-wrap;
                word-break: break-word;
            }
        `;
        document.head.appendChild(style);
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------
    window.BackendToggleWidget = {
        mount: function(selector) {
            const container = typeof selector === 'string'
                ? document.querySelector(selector)
                : selector;
            if (!container) {
                console.error('BackendToggleWidget: container not found');
                return;
            }
            injectStyles();
            renderWidget(container);
        },
        getCurrentBackend: () => currentBackend,
        isHealthy: () => isHealthy
    };

})();
