class AgenticIssuePanel {
    constructor() {
        this.runtime = (typeof window !== 'undefined' && window.RawrRuntime) ? window.RawrRuntime : null;
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
        const mountNode = this.runtime && this.runtime.requireElement 
            ? this.runtime.requireElement('active-panel-mount')
            : document.body;
        
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
                <span class="agentic-panel-title">🤖 AGENTIC AUDITOR METRICS</span>
                <span class="agentic-panel-count">${totalIssues} Detected</span>
                <button id="toggle-agentic-view-btn">${this.isVisible ? '▼ Collapse Panel' : '▲ Expand Panel'}</button>
            </div>
            <div id="agentic-panel-body" class="agentic-panel-body" style="display: ${this.isVisible ? 'grid' : 'none'};">
                <div class="metric-card metric-info">
                    <span class="metric-label">Informational</span>
                    <span class="metric-value">${this.metrics.info}</span>
                </div>
                <div class="metric-card metric-low">
                    <span class="metric-label">Low Severity</span>
                    <span class="metric-value">${this.metrics.low}</span>
                </div>
                <div class="metric-card metric-medium">
                    <span class="metric-label">Medium Severity</span>
                    <span class="metric-value">${this.metrics.medium}</span>
                </div>
                <div class="metric-card metric-high">
                    <span class="metric-label">High Threat</span>
                    <span class="metric-value">${this.metrics.high}</span>
                </div>
                <div class="metric-card metric-critical">
                    <span class="metric-label">Critical Exception</span>
                    <span class="metric-value">${this.metrics.critical}</span>
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
            
            if (this.runtime && this.runtime.publish) {
                this.runtime.publish('ui:panel:toggled', { visible: this.isVisible });
            }
        });
    }

    updateAnomaliesRegister(newMetrics = {}) {
        this.metrics = { ...this.metrics, ...newMetrics };
        const shell = document.getElementById(this.containerId);
        if (shell) {
            shell.innerHTML = this.generateMarkupTemplate();
            this.bindUserActionHooks();
        }
    }
}

if (typeof window !== 'undefined') {
    window.AgenticIssuePanel = AgenticIssuePanel;
}
