// src/ui/AgenticIssuePanel.js
// Toggleable Agentic Issue Dashboard — real-time anomaly metrics by severity

class AgenticIssuePanel {
    constructor() {
        this.runtime = window.RawrRuntime || { requireElement: (id) => document.getElementById(id), publish: () => {} };
        this.isVisible = true;
        this.metrics = {
            info: 0,
            low: 32,
            medium: 0,
            high: 1300,
            critical: 0
        };
        
        this.containerId = 'agentic-issue-panel-container';
        this.initViewportSurface();
    }

    initViewportSurface() {
        // Safe DOM Allocation through our core runtime boundary contract
        const mountNode = this.runtime.requireElement('active-panel-mount') || document.body;
        
        const shell = document.createElement('div');
        shell.id = this.containerId;
        shell.className = 'agentic-panel-shell';
        shell.innerHTML = this.generateMarkupTemplate();
        
        mountNode.appendChild(shell);
        this.bindUserActionHooks();
    }

    generateMarkupTemplate() {
        const totalIssues = Object.values(this.metrics).reduce((a, b) => a + b, 0);
        
        return `
            <div class="agentic-panel-header">
                <h3>
                    🤖 AGENTIC AUDITOR METRICS
                    <span class="agentic-badge">${totalIssues} Detected</span>
                </h3>
                <button id="toggle-agentic-view-btn" class="agentic-toggle-btn">
                    ${this.isVisible ? '▼ Collapse Panel' : '▲ Expand Panel'}
                </button>
            </div>

            <div id="agentic-panel-body" class="agentic-panel-body" style="display: ${this.isVisible ? 'grid' : 'none'};">
                <div class="agentic-metric-card agentic-severity-info">
                    <div class="agentic-metric-label">Informational</div>
                    <div class="agentic-metric-value">${this.metrics.info}</div>
                </div>

                <div class="agentic-metric-card agentic-severity-low">
                    <div class="agentic-metric-label">Low Severity</div>
                    <div class="agentic-metric-value">${this.metrics.low}</div>
                </div>

                <div class="agentic-metric-card agentic-severity-medium">
                    <div class="agentic-metric-label">Medium Severity</div>
                    <div class="agentic-metric-value">${this.metrics.medium}</div>
                </div>

                <div class="agentic-metric-card agentic-severity-high">
                    <div class="agentic-metric-label">High Threat</div>
                    <div class="agentic-metric-value">${this.metrics.high}</div>
                </div>

                <div class="agentic-metric-card agentic-severity-critical">
                    <div class="agentic-metric-label">Critical Exception</div>
                    <div class="agentic-metric-value">${this.metrics.critical}</div>
                </div>
            </div>
        `;
    }

    bindUserActionHooks() {
        const toggleButton = document.getElementById('toggle-agentic-view-btn');
        const panelBody = document.getElementById('agentic-panel-body');

        if (!toggleButton || !panelBody) return;

        toggleButton.addEventListener('click', () => {
            this.isVisible = !this.isVisible;
            panelBody.style.display = this.isVisible ? 'grid' : 'none';
            toggleButton.innerText = this.isVisible ? '▼ Collapse Panel' : '▲ Expand Panel';
            
            // Broadcast state update across universal decoupled event broker
            this.runtime.publish('ui:panel:toggled', { visible: this.isVisible });
        });
    }

    updateAnomaliesRegister(newMetrics = {}) {
        this.metrics = { ...this.metrics, ...newMetrics };
        const shell = this.runtime.requireElement(this.containerId);
        if (shell) {
            shell.innerHTML = this.generateMarkupTemplate();
            this.bindUserActionHooks();
        }
    }
}

if (typeof window !== 'undefined') {
    window.AgenticIssuePanel = AgenticIssuePanel;
}

module.exports = { AgenticIssuePanel };
