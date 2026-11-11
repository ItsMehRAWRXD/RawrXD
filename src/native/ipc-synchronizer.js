// ============================================================================
// ipc-synchronizer.js - Active IPC Channel State Coordination
// Abstracted bridge with browser fallback simulation
// ============================================================================

class RawrIpcSynchronizer {
    constructor() {
        this.runtime = window.RawrRuntime;
        this.bridge = null;
        this.activeSubscriptions = new Map();
        this.initializeBridge();
    }

    initializeBridge() {
        if (typeof window !== 'undefined' && window.electronAPI) {
            this.bridge = window.electronAPI;
            console.log('[IPC] Native Electron bridge attached.');
        } else {
            console.warn('[IPC] Electron absent. Initializing simulated mesh.');
            this.initializeSimulatedMesh();
        }
    }

    initializeSimulatedMesh() {
        this.bridge = {
            send: (channel, data) => {
                console.info(`[IPC Sim Outbound] [${channel}]:`, data);
                if (channel === 'engine:start') {
                    setTimeout(() => this.triggerVirtualInbound('engine:status', { active: true, load: 12 }), 150);
                }
                if (channel === 'state:persist') {
                    try {
                        localStorage.setItem('rawr_persisted_state', JSON.stringify(data));
                    } catch (e) { console.error('[IPC Sim] Persist failed:', e); }
                }
                if (channel === 'state:load') {
                    try {
                        const saved = localStorage.getItem('rawr_persisted_state');
                        if (saved) this.triggerVirtualInbound('state:restored', JSON.parse(saved));
                    } catch (e) { console.error('[IPC Sim] Load failed:', e); }
                }
            },
            on: (channel, callback) => {
                if (!this.activeSubscriptions.has(channel)) {
                    this.activeSubscriptions.set(channel, []);
                }
                this.activeSubscriptions.get(channel).push(callback);
                return () => {
                    const arr = this.activeSubscriptions.get(channel);
                    if (arr) this.activeSubscriptions.set(channel, arr.filter(cb => cb !== callback));
                };
            },
            invoke: (channel, data) => {
                console.info(`[IPC Sim Invoke] [${channel}]:`, data);
                return Promise.resolve({ simulated: true, channel, timestamp: Date.now() });
            },
            removeAll: (channel) => {
                this.activeSubscriptions.delete(channel);
            }
        };
    }

    triggerVirtualInbound(channel, data) {
        if (this.activeSubscriptions.has(channel)) {
            this.activeSubscriptions.get(channel).forEach(cb => {
                try { cb(data); } catch (e) { console.error(`[IPC] Inbound error [${channel}]:`, e); }
            });
        }
    }

    emit(channel, payload = {}) {
        try {
            const wrapped = { origin: 'RawrRuntime', timestamp: Date.now(), payload };
            this.bridge.send(channel, wrapped);
        } catch (e) {
            console.error(`[IPC] Emit failure on ${channel}:`, e);
        }
    }

    listen(channel, runtimeEventName) {
        return this.bridge.on(channel, (incomingData) => {
            const clean = incomingData?.payload !== undefined ? incomingData.payload : incomingData;
            if (this.runtime) this.runtime.publish(runtimeEventName, clean);
        });
    }

    request(channel, data) {
        if (this.bridge.invoke) {
            return this.bridge.invoke(channel, data);
        }
        return Promise.reject(new Error('No invoke available'));
    }
}

if (typeof window !== 'undefined') {
    window.RawrIpcSynchronizer = new RawrIpcSynchronizer();
}
