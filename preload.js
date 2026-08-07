// ============================================================================
// preload.js - Hardened Electron Bridge
// Context-isolated IPC with validated channel whitelist
// ============================================================================

const { contextBridge, ipcRenderer } = require('electron');

const VALID_CHANNELS = {
    OUTBOUND: [
        'engine:start',
        'engine:stop',
        'panel:request',
        'telemetry:emit',
        'state:persist',
        'state:load',
        'log:flush'
    ],
    INBOUND: [
        'engine:status',
        'panel:render',
        'runtime:error',
        'theme:sync',
        'state:restored',
        'telemetry:ack'
    ]
};

contextBridge.exposeInMainWorld('electronAPI', {
    send: (channel, data) => {
        if (VALID_CHANNELS.OUTBOUND.includes(channel)) {
            ipcRenderer.send(channel, data);
        } else {
            console.error(`[preload] Blocked unmapped outbound channel: ${channel}`);
        }
    },

    on: (channel, callback) => {
        if (VALID_CHANNELS.INBOUND.includes(channel)) {
            const subscription = (_event, ...args) => callback(...args);
            ipcRenderer.on(channel, subscription);
            return () => ipcRenderer.removeListener(channel, subscription);
        } else {
            console.error(`[preload] Blocked unmapped inbound channel: ${channel}`);
            return () => {};
        }
    },

    invoke: (channel, data) => {
        if (VALID_CHANNELS.OUTBOUND.includes(channel)) {
            return ipcRenderer.invoke(channel, data);
        }
        console.error(`[preload] Blocked unmapped invoke channel: ${channel}`);
        return Promise.reject(new Error(`Invalid channel: ${channel}`));
    },

    removeAll: (channel) => {
        ipcRenderer.removeAllListeners(channel);
    }
});
