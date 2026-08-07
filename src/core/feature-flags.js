// ============================================================================
// feature-flags.js - Entitlement Engine & Dynamic Flags
// Sensitivity-gated feature toggles with access control
// ============================================================================

class RawrFeatureFlagEngine {
    constructor() {
        this.flags = new Map();
        this.runtime = window.RawrRuntime;
        this.initializeDefaultFlags();
    }

    initializeDefaultFlags() {
        this.setFlag('panel.crypto.analytics', true, 'high');
        this.setFlag('panel.system.diagnostics', true, 'low');
        this.setFlag('panel.engine.manager', true, 'low');
        this.setFlag('panel.telemetry.dashboard', true, 'medium');
        this.setFlag('panel.session.manager', true, 'high');
        this.setFlag('engine.hot.module.reload', false, 'critical');
        this.setFlag('telemetry.verbose.logging', false, 'low');
        this.setFlag('debug.developer.tools', false, 'critical');
        this.setFlag('experimental.self.healing', true, 'medium');
    }

    setFlag(key, value, sensitivity = 'low') {
        this.flags.set(key, { value, sensitivity, lastModified: Date.now() });
        if (this.runtime) this.runtime.publish('flags:updated', { key, value });
    }

    evaluate(key, context = {}) {
        if (!this.flags.has(key)) {
            console.warn(`[FeatureFlags] Unknown flag: "${key}". Defaulting to false.`);
            return false;
        }

        const flag = this.flags.get(key);

        if (flag.sensitivity === 'critical' && context.clearanceLevel !== 'administrator') {
            console.warn(`[FeatureFlags] Access denied for critical flag: "${key}"`);
            return false;
        }

        if (flag.sensitivity === 'high' && !context.clearanceLevel) {
            console.warn(`[FeatureFlags] Access denied for high-sensitivity flag: "${key}"`);
            return false;
        }

        return flag.value;
    }

    getFlag(key) {
        return this.flags.get(key) || null;
    }

    getAllFlags() {
        const result = {};
        this.flags.forEach((val, key) => {
            result[key] = { value: val.value, sensitivity: val.sensitivity };
        });
        return result;
    }

    exportSnapshot() {
        const obj = {};
        this.flags.forEach((val, key) => { obj[key] = val.value; });
        return obj;
    }

    importSnapshot(snapshot) {
        if (!snapshot || typeof snapshot !== 'object') return;
        Object.entries(snapshot).forEach(([key, value]) => {
            if (this.flags.has(key)) {
                this.flags.get(key).value = !!value;
            }
        });
    }
}

if (typeof window !== 'undefined') {
    window.RawrFeatureFlagEngine = new RawrFeatureFlagEngine();
}
