// ============================================================================
// panel-bootloader.js - Dynamic Panel Engine
// Manifest-driven panel loading with dependency resolution
// ============================================================================

class PanelBootloader {
    constructor() {
        this.manifestSource = '/src/config/panels.json';
        this.panels = [];
        this.currentPanelId = null;
        this.runtime = window.RawrRuntime;
    }

    async init() {
        console.log('[PanelBootloader] Initializing...');

        try {
            const response = await fetch(this.manifestSource);
            this.panels = await response.json();
            console.log(`[PanelBootloader] Loaded ${this.panels.length} panel definitions.`);
            this.renderNavigation();
            this.routeToDefault();
        } catch (e) {
            console.error('[PanelBootloader] Failed to load manifest:', e);
        }
    }

    renderNavigation() {
        const menu = this.runtime.requireElement('dynamic-menu-container');
        menu.innerHTML = '';

        // Group panels
        const groups = {};
        this.panels.forEach(panel => {
            const group = panel.menu?.group || 'general';
            if (!groups[group]) groups[group] = [];
            groups[group].push(panel);
        });

        // Render groups
        Object.entries(groups).sort().forEach(([group, panels]) => {
            const header = document.createElement('div');
            header.className = 'menu-group-header';
            header.textContent = group.charAt(0).toUpperCase() + group.slice(1);
            menu.appendChild(header);

            panels.sort((a, b) => (a.menu?.order || 99) - (b.menu?.order || 99));
            panels.forEach(panel => {
                const btn = document.createElement('button');
                btn.className = 'menu-item-link';
                btn.dataset.panelId = panel.id;
                btn.innerHTML = `<span class="icon-${panel.icon}"></span> ${panel.title}`;
                btn.addEventListener('click', () => this.mountPanel(panel.id));
                menu.appendChild(btn);
            });
        });
    }

    async mountPanel(panelId) {
        const panel = this.panels.find(p => p.id === panelId);
        if (!panel) {
            console.error(`[PanelBootloader] Unknown panel: ${panelId}`);
            return;
        }

        // Update active state in nav
        document.querySelectorAll('.menu-item-link').forEach(el => {
            el.classList.toggle('active', el.dataset.panelId === panelId);
        });

        const stage = this.runtime.requireElement('active-panel-mount');
        stage.innerHTML = `<div class="panel-loading" data-id="${panel.id}">Loading ${panel.title}...</div>`;

        // Update breadcrumbs
        const breadcrumbs = this.runtime.requireElement('breadcrumbs');
        breadcrumbs.innerHTML = `
            <span class="breadcrumb-item" data-panel="system-diagnostics">Home</span>
            <span class="breadcrumb-separator">/</span>
            <span class="breadcrumb-item">${panel.title}</span>
        `;

        // Load CSS dependencies
        if (panel.css) {
            for (const css of panel.css) {
                if (!document.querySelector(`link[href="${css}"]`)) {
                    const link = document.createElement('link');
                    link.rel = 'stylesheet';
                    link.href = css;
                    document.head.appendChild(link);
                }
            }
        }

        // Load scripts sequentially
        if (panel.scripts) {
            for (const src of panel.scripts) {
                await this.injectScript(src);
            }
        }

        stage.innerHTML = `<div id="panel-viewport-${panel.id}" class="panel-active-view"></div>`;
        this.currentPanelId = panel.id;

        // Update status
        const statusText = this.runtime.requireElement('status-text');
        if (statusText) statusText.textContent = `Panel: ${panel.title}`;

        this.runtime.publish('panel:mounted', { id: panelId, meta: panel });
    }

    injectScript(src) {
        return new Promise((resolve, reject) => {
            if (document.querySelector(`script[src="${src}"]`)) return resolve();
            const script = document.createElement('script');
            script.src = src;
            script.onload = resolve;
            script.onerror = () => reject(new Error(`Failed: ${src}`));
            document.head.appendChild(script);
        });
    }

    routeToDefault() {
        // Check URL hash for panel routing
        const hash = window.location.hash.replace('#', '');
        if (hash) {
            const panel = this.panels.find(p => p.routes && p.routes.includes(hash));
            if (panel) {
                this.mountPanel(panel.id);
                return;
            }
        }

        // Default to first panel
        if (this.panels.length > 0) {
            this.mountPanel(this.panels[0].id);
        }
    }

    getCurrentPanel() {
        return this.panels.find(p => p.id === this.currentPanelId) || null;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const loader = new PanelBootloader();
    loader.init();
});
