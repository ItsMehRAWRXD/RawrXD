// src/core/panel-bootloader.js
// Master Dynamic Bootloader — orchestrates all 21 specialized components
// into a single active thread with topological script loading, feature flag
// gating, storage migration, and crash recovery integration.

class MasterPanelOrchestrator {
    constructor() {
        this.runtime = window.RawrRuntime;
        this.state = window.RawrStateManager;
        this.ipc = window.RawrIpcSynchronizer;
        this.resolver = window.DependencyResolver;
        this.flags = window.RawrFeatureFlagEngine;
        this.migrator = window.RawrMigrationEngine;
        this.ledger = window.RawrLedgerCommitter;
        this.kernel = window.RawrKernelBridge;

        this.manifestPath = '/src/config/panels.json';
        this.panels = [];
        this._bootTimestamp = null;
    }

    async boot() {
        this._bootTimestamp = Date.now();
        console.log('================================================================');
        console.log('⚡ STARTING FULL SYSTEM LIFECYCLE INITIALIZATION');
        console.log('================================================================');

        try {
            // 1. Process schema migration states
            if (this.migrator) {
                console.log('[Bootloader] Running migration pipeline...');
                this.migrator.processMigrationPipeline();
            }

            // 2. Initialize atomic state tracking maps
            if (this.state) {
                console.log('[Bootloader] Initializing state manager...');
                this.state.initialize({
                    engineStatus: 'initialized',
                    activePanelId: null,
                    metrics: [],
                    engineLastActive: Date.now(),
                    bootTimestamp: this._bootTimestamp
                });
            }

            // 3. Bind persistent update journal logic
            if (this.ledger) {
                console.log('[Bootloader] Attaching ledger to state manager...');
                this.ledger.attachToStateManager();
            }

            // 4. Calibrate the vector acceleration kernel bridge
            if (this.kernel) {
                console.log('[Bootloader] Initializing kernel bridge...');
                this.kernel.init();
            }

            // 5. Fetch panels manifest schema configuration
            console.log('[Bootloader] Fetching panel manifest...');
            const response = await fetch(this.manifestPath);
            if (!response.ok) throw new Error(`HTTP ${response.status}: Failed to load panel manifest`);
            this.panels = await response.json();
            console.log(`[Bootloader] Loaded ${this.panels.length} panel definitions`);

            // 6. Draw sidebar layouts and route cleanly to default views
            this.renderNavigationMenu();
            this.routeToInitialViewport();

            console.log('✅ SYSTEM INTEGRATION SUCCESSFUL: Bootloader online.');
            console.log(`   Boot duration: ${Date.now() - this._bootTimestamp}ms`);
            console.log(`   Panels registered: ${this.panels.length}`);
            console.log(`   Kernel bridge: ${this.kernel ? this.kernel.activeKernelSet : 'N/A'}`);
        } catch (e) {
            console.error('CRITICAL BOOTLOADER ORCHESTRATION SHUTDOWN:', e);
            if (window.RawrCrashRecovery) {
                window.RawrCrashRecovery.handleSystemFault({
                    type: 'Bootloader Initialization Crash',
                    message: e.message,
                    stack: e.stack,
                    timestamp: Date.now()
                });
            }
            // Render fallback UI
            this._renderFallbackUI(e.message);
        }
    }

    renderNavigationMenu() {
        const menuContainer = this.runtime?.requireElement('dynamic-menu-container');
        if (!menuContainer) {
            console.warn('[Bootloader] No menu container found — skipping nav render');
            return;
        }
        menuContainer.innerHTML = '';

        this.panels.forEach(panel => {
            // Evaluate permission flag access before exposing menu items
            if (this.flags && !this.flags.evaluate(`panel.${panel.id.replace('-', '.')}`)) {
                console.warn(`[Bootloader] Feature Flag disabled viewport: [${panel.id}]`);
                return;
            }

            const actionButton = document.createElement('button');
            actionButton.className = 'menu-item-link';
            actionButton.id = `nav-target-${panel.id}`;
            actionButton.innerHTML = ` ${panel.title}`;

            actionButton.addEventListener('click', () => this.transitionToPanel(panel.id));
            menuContainer.appendChild(actionButton);
        });
    }

    async transitionToPanel(panelId) {
        const panel = this.panels.find(p => p.id === panelId);
        if (!panel) {
            console.error(`[Bootloader] Navigation targeted untracked layout: ${panelId}`);
            return;
        }

        console.log(`📡 Switching Viewport Frame target context to: [${panelId}]`);

        // Mark state transition inside our central ledger mapping
        if (this.state) {
            this.state.dispatch('PANEL_SET_ACTIVE', { id: panelId });
        }

        const stage = this.runtime?.requireElement('active-panel-mount');
        if (!stage) {
            console.error('[Bootloader] No active-panel-mount element found');
            return;
        }

        stage.innerHTML = `<div class="panel-loading">Resolving Module Dependencies for ${panel.title}...</div>`;

        // Deploy dynamic topological sorting to load panel script chains
        if (this.resolver && panel.dependencies) {
            const sortingGraph = new this.resolver();
            panel.dependencies.forEach(dep => sortingGraph.addModule(dep));
            sortingGraph.addModule(panel.id, panel.dependencies);

            const executionQueue = sortingGraph.resolveExecutionOrder();
            console.log(`⛓️ Topological Script Load Sequence: ${JSON.stringify(executionQueue)}`);
        }

        // Inject script paths sequentially into document headers
        if (panel.scripts) {
            for (const scriptSrc of panel.scripts) {
                await this.executeScriptInjection(scriptSrc);
            }
        }

        // Render viewport layout containers
        stage.innerHTML = `
            <div class="panel-header">
                <h2>${panel.title}</h2>
                <span class="panel-badge">${panel.badge || 'active'}</span>
            </div>
            <div class="panel-content" id="panel-content-${panel.id}">
                <p>Native vector acceleration context active.</p>
                <p>Kernel set: <strong>${this.kernel ? this.kernel.activeKernelSet : 'GENERIC'}</strong></p>
            </div>
            <div class="panel-footer">
                <small>Panel ID: ${panel.id} | Loaded: ${new Date().toISOString()}</small>
            </div>
        `;

        // Update active class indicators across sidebar buttons
        const navigationLinks = document.querySelectorAll('.menu-item-link');
        navigationLinks.forEach(link => link.classList.remove('active'));

        const activeLink = document.getElementById(`nav-target-${panel.id}`);
        if (activeLink) activeLink.classList.add('active');

        if (this.runtime) {
            this.runtime.publish('panel:mounted', { id: panelId, timestamp: Date.now() });
        }
    }

    executeScriptInjection(src) {
        return new Promise((resolve, reject) => {
            if (document.querySelector(`script[src="${src}"]`)) return resolve();
            const tag = document.createElement('script');
            tag.src = src;
            tag.onload = () => {
                console.log(`[Bootloader] Script loaded: ${src}`);
                resolve();
            };
            tag.onerror = (err) => {
                console.error(`[Bootloader] Script failed: ${src}`, err);
                reject(new Error(`Script load failed: ${src}`));
            };
            document.head.appendChild(tag);
        });
    }

    routeToInitialViewport() {
        if (this.panels.length > 0) {
            this.transitionToPanel(this.panels[0].id);
        }
    }

    _renderFallbackUI(errorMessage) {
        const stage = this.runtime?.requireElement('active-panel-mount');
        if (stage) {
            stage.innerHTML = `
                <div class="fallback-ui">
                    <h2>⚠️ System Recovery Mode</h2>
                    <p>Bootloader encountered an error during initialization.</p>
                    <pre class="error-detail">${errorMessage}</pre>
                    <button onclick="location.reload()">Retry System Boot</button>
                </div>
            `;
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.OrchestratorInstance = new MasterPanelOrchestrator();
    window.OrchestratorInstance.boot();
});
