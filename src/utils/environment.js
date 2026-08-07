// ============================================================================
// environment.js - Context-Aware Consumer Verification
// Returns native bridge or browser fallback
// ============================================================================

export function getNativeBridge() {
    if (typeof window !== 'undefined' && window.electronAPI) {
        return window.electronAPI;
    }

    console.warn('[Environment] Electron context absent. Operating in browser fallback mode.');
    return {
        send: (channel, data) => console.info(`[Web Fallback Outbound] ${channel}:`, data),
        on: (channel, cb) => {
            console.info(`[Web Fallback Inbound Subscription] ${channel}`);
            return () => {};
        },
        invoke: () => Promise.reject(new Error('No native bridge')),
        removeAll: () => {}
    };
}

export function isElectron() {
    return typeof window !== 'undefined' && !!window.electronAPI;
}

export function isBrowser() {
    return typeof window !== 'undefined' && !window.electronAPI;
}
