// ============================================================================
// rollback-daemon.js - Active State Synchronization & Rollback Daemon
// Watchdog timer that monitors state health and triggers rollback
// ============================================================================

class RawrRollbackDaemon {
    constructor() {
        this.runtime = window.RawrRuntime;
        this.stateManager = window.RawrStateManager;
        this.ipc = window.RawrIpcSynchronizer;
        this.heartbeatInterval = 3000;
        this.watchdogTimer = null;
        this.expectedChecksum = null;
        this.lastHealthyState = null;
        this.startWatchdog();
    }

    startWatchdog() {
        if (this.watchdogTimer) clearInterval(this.watchdogTimer);
        this.watchdogTimer = setInterval(() => this.evaluateSystemHealth(), this.heartbeatInterval);
        console.log('[RollbackDaemon] Watchdog active (interval: ' + this.heartbeatInterval + 'ms)');
    }

    evaluateSystemHealth() {
        if (!this.stateManager) return;

        const current = this.stateManager.getState();
        const checksum = this.generateChecksum(JSON.stringify(current));

        // Detect frozen state during processing
        if (current.engineStatus === 'processing' && this.expectedChecksum === checksum) {
            console.warn('[RollbackDaemon] State freeze detected. Triggering rollback.');
            this.triggerEmergencyRollback();
            return;
        }

        // Detect rapid state corruption
        if (this.lastHealthyState && current.errors && current.errors.length > 5) {
            console.warn('[RollbackDaemon] Error threshold exceeded. Triggering rollback.');
            this.triggerEmergencyRollback();
            return;
        }

        this.expectedChecksum = checksum;
        this.lastHealthyState = current;
    }

    triggerEmergencyRollback() {
        if (!this.stateManager || typeof this.stateManager.rollback !== 'function') {
            console.error('[RollbackDaemon] Cannot rollback - state manager unavailable.');
            return;
        }

        const success = this.stateManager.rollback();
        if (success) {
            console.log('[RollbackDaemon] Rollback successful.');
            if (this.ipc) {
                this.ipc.emit('telemetry:emit', {
                    alertClass: 'WATCHDOG_RECOVERY',
                    detail: { timestamp: Date.now(), status: 'RECOVERED' }
                });
            }
        } else {
            console.error('[RollbackDaemon] Rollback failed. Forcing state reset.');
            if (this.runtime) {
                this.runtime.publish('runtime:error', { severe: true, code: 'WATCHDOG_EXHAUSTED' });
            }
        }
    }

    generateChecksum(data) {
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash) + data.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash).toString(16);
    }

    stopWatchdog() {
        if (this.watchdogTimer) {
            clearInterval(this.watchdogTimer);
            this.watchdogTimer = null;
        }
    }
}

if (typeof window !== 'undefined') {
    window.RawrRollbackDaemon = new RawrRollbackDaemon();
}
