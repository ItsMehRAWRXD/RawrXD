// ============================================================================
// RawrRuntime - Unified Shared Runtime
// Singleton DI container, event broker, fail-safe DOM contract
// ============================================================================

class RawrRuntime {
    constructor() {
        this.services = new Map();
        this.events = new Map();
        this.isInitialized = false;
    }

    static getInstance() {
        if (!window.__RawrRuntimeInstance) {
            window.__RawrRuntimeInstance = new RawrRuntime();
        }
        return window.__RawrRuntimeInstance;
    }

    register(serviceName, instance) {
        if (this.services.has(serviceName)) {
            console.warn(`[RawrRuntime] Service '${serviceName}' already registered. Overwriting.`);
        }
        this.services.set(serviceName, instance);
        return this;
    }

    resolve(serviceName) {
        const service = this.services.get(serviceName);
        if (!service) {
            throw new Error(`[RawrRuntime] Critical Service Missing: ${serviceName}`);
        }
        return service;
    }

    has(serviceName) {
        return this.services.has(serviceName);
    }

    // --- Zero-Coupling Event Broker ---
    publish(event, data) {
        if (!this.events.has(event)) return;
        this.events.get(event).forEach(callback => {
            try { callback(data); } catch (e) { console.error(`[RawrRuntime] Event Error [${event}]:`, e); }
        });
    }

    subscribe(event, callback) {
        if (!this.events.has(event)) this.events.set(event, []);
        this.events.get(event).push(callback);
        return () => {
            const arr = this.events.get(event);
            if (arr) this.events.set(event, arr.filter(cb => cb !== callback));
        };
    }

    once(event, callback) {
        const wrapper = (data) => {
            callback(data);
            const arr = this.events.get(event);
            if (arr) this.events.set(event, arr.filter(cb => cb !== wrapper));
        };
        return this.subscribe(event, wrapper);
    }

    broadcast(event, data) {
        this.publish(event, data);
    }

    // --- Fail-Safe DOM Contract ---
    requireElement(id) {
        const element = document.getElementById(id);
        if (element) return element;

        console.warn(`[RawrRuntime] DOM Target Missing: #${id}. Creating placeholder.`);
        const placeholder = document.createElement('div');
        placeholder.id = id;
        placeholder.className = 'rawr-placeholder-fallback';
        placeholder.style.display = 'none';
        document.body.appendChild(placeholder);
        return placeholder;
    }

    // --- Logger ---
    log(level, message, data) {
        const entry = { timestamp: Date.now(), level, message, data };
        this.publish('log:entry', entry);
        const fn = console[level] || console.log;
        fn(`[RawrRuntime] ${message}`, data || '');
    }

    // --- Diagnostics ---
    getDiagnostics() {
        return {
            services: Array.from(this.services.keys()),
            events: Array.from(this.events.keys()),
            initialized: this.isInitialized,
            memory: performance?.memory ? {
                usedJSHeap: performance.memory.usedJSHeapSize,
                totalJSHeap: performance.memory.totalJSHeapSize
            } : null
        };
    }
}

window.RawrRuntime = RawrRuntime.getInstance();
