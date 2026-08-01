// ============================================================================
// module-registry.js - Dynamic Module Registry & Sandboxing
// Proxy-trapped execution context for third-party modules
// ============================================================================

class RawrModuleRegistry {
    constructor() {
        this.modules = new Map();
        this.runtime = window.RawrRuntime;
    }

    registerModule(moduleId, moduleInstance, manifest = {}) {
        if (this.modules.has(moduleId)) {
            throw new Error(`Module conflict: '${moduleId}' already registered.`);
        }

        if (manifest.dependencies) {
            manifest.dependencies.forEach(dep => {
                if (!window[dep] && !(this.runtime && this.runtime.has(dep))) {
                    throw new Error(`Module '${moduleId}' missing dependency: '${dep}'`);
                }
            });
        }

        const sandbox = this.createSandbox(moduleId, manifest.permissions || []);
        const entry = {
            id: moduleId,
            instance: moduleInstance,
            manifest,
            context: sandbox,
            active: false,
            registeredAt: Date.now()
        };

        this.modules.set(moduleId, entry);
        console.log(`[ModuleRegistry] Registered: ${moduleId}`);
        if (this.runtime) this.runtime.publish('module:registered', { id: moduleId, manifest });
    }

    createSandbox(moduleId, permissions) {
        const allowed = new Set(['RawrRuntime', 'document', 'console', 'setTimeout',
            'setInterval', 'clearTimeout', 'clearInterval', 'fetch', 'Promise',
            'Math', 'Date', 'JSON', 'Array', 'Object', 'String', 'Number',
            'Map', 'Set', 'Error', 'performance', 'requestAnimationFrame',
            'cancelAnimationFrame', 'Blob', 'FileReader', 'atob', 'btoa',
            'Int8Array', 'Uint8Array', 'Int16Array', 'Uint16Array',
            'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array']);

        return new Proxy(window, {
            get: (target, prop) => {
                if (prop === 'electronAPI' && !permissions.includes('ipc:native')) {
                    console.error(`[Sandbox] Module '${moduleId}' denied electronAPI access.`);
                    return undefined;
                }
                if (prop === 'RawrModuleRegistry' && moduleId !== 'core') {
                    console.error(`[Sandbox] Module '${moduleId}' denied registry access.`);
                    return undefined;
                }
                if (allowed.has(prop) || prop in target) {
                    return target[prop];
                }
                return undefined;
            },
            set: (target, prop, value) => {
                if (allowed.has(prop)) {
                    console.error(`[Sandbox] Module '${moduleId}' blocked from mutating '${prop.toString()}'.`);
                    return false;
                }
                target[prop] = value;
                return true;
            }
        });
    }

    startModule(moduleId) {
        const mod = this.modules.get(moduleId);
        if (!mod) return console.error(`[ModuleRegistry] Unknown module: ${moduleId}`);
        if (mod.active) return console.warn(`[ModuleRegistry] Module already active: ${moduleId}`);

        if (typeof mod.instance.init === 'function') {
            mod.instance.init(mod.context);
            mod.active = true;
            console.log(`[ModuleRegistry] Started: ${moduleId}`);
            if (this.runtime) this.runtime.publish('module:started', { id: moduleId });
        }
    }

    stopModule(moduleId) {
        const mod = this.modules.get(moduleId);
        if (!mod) return;
        if (typeof mod.instance.destroy === 'function') {
            mod.instance.destroy();
        }
        mod.active = false;
        if (this.runtime) this.runtime.publish('module:stopped', { id: moduleId });
    }

    getModule(moduleId) {
        return this.modules.get(moduleId) || null;
    }

    listModules() {
        return Array.from(this.modules.values()).map(m => ({
            id: m.id,
            active: m.active,
            dependencies: m.manifest.dependencies || [],
            permissions: m.manifest.permissions || []
        }));
    }
}

if (typeof window !== 'undefined') {
    window.RawrModuleRegistry = new RawrModuleRegistry();
}
