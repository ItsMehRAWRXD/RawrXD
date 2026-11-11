// ============================================================================
// hmr-controller.js - Hot Module Reload & Dependency Resolver
// Live script injection with dependency graph validation
// ============================================================================

class RawrHmrController {
    constructor() {
        this.runtime = window.RawrRuntime;
        this.registry = window.RawrModuleRegistry;
        this.activeModules = new Map();
    }

    async registerAndInjectModule(moduleId, scriptUrl, dependencies = []) {
        console.log(`[HMR] Registering module: ${moduleId}`);

        // Validate dependency graph
        if (window.DependencyResolver) {
            const graph = new window.DependencyResolver();
            graph.addModule(moduleId, dependencies);
            try {
                graph.resolveExecutionOrder();
            } catch (error) {
                console.error(`[HMR] Dependency cycle in ${moduleId}:`, error.message);
                return false;
            }
        }

        // Hot swap if already loaded
        if (this.activeModules.has(moduleId)) {
            await this.executeHotSwap(moduleId, scriptUrl);
            return true;
        }

        // Fresh load
        await this.injectScriptTag(moduleId, scriptUrl);
        this.activeModules.set(moduleId, { url: scriptUrl, loadedAt: Date.now() });
        if (this.runtime) this.runtime.publish('module:loaded', { id: moduleId });
        return true;
    }

    async executeHotSwap(moduleId, scriptUrl) {
        console.warn(`[HMR] Hot-swapping: ${moduleId}`);

        if (this.runtime) this.runtime.publish('module:hotswap:before', { moduleId });

        // Remove old script
        const old = document.querySelector(`script[data-hmr-id="${moduleId}"]`);
        if (old) old.remove();

        // Clean up old module from registry
        if (this.registry && typeof this.registry.stopModule === 'function') {
            this.registry.stopModule(moduleId);
        }

        // Inject new version
        await this.injectScriptTag(moduleId, scriptUrl);
        this.activeModules.set(moduleId, { url: scriptUrl, loadedAt: Date.now() });

        if (this.runtime) this.runtime.publish('module:hotswap:after', { moduleId });
        console.log(`[HMR] Swap complete: ${moduleId}`);
    }

    injectScriptTag(moduleId, scriptUrl) {
        return new Promise((resolve, reject) => {
            const existing = document.querySelector(`script[data-hmr-id="${moduleId}"]`);
            if (existing) return resolve();

            const script = document.createElement('script');
            script.src = `${scriptUrl}?t=${Date.now()}`;
            script.dataset.hmrId = moduleId;
            script.onload = resolve;
            script.onerror = () => reject(new Error(`Failed to load: ${scriptUrl}`));
            document.head.appendChild(script);
        });
    }

    unloadModule(moduleId) {
        if (!this.activeModules.has(moduleId)) return;
        const old = document.querySelector(`script[data-hmr-id="${moduleId}"]`);
        if (old) old.remove();
        this.activeModules.delete(moduleId);
        if (this.registry && typeof this.registry.stopModule === 'function') {
            this.registry.stopModule(moduleId);
        }
        if (this.runtime) this.runtime.publish('module:unloaded', { id: moduleId });
    }

    listActiveModules() {
        return Array.from(this.activeModules.entries()).map(([id, info]) => ({
            id,
            url: info.url,
            loadedAt: new Date(info.loadedAt).toISOString()
        }));
    }
}

if (typeof window !== 'undefined') {
    window.RawrHmrController = new RawrHmrController();
}
