// ============================================================================
// crash-recovery.js - Telemetry Pipeline & Crash Recovery
// Global error interceptor with state rollback and telemetry flush
// ============================================================================

class RawrCrashRecovery {
    constructor() {
        this.ipc = window.RawrIpcSynchronizer;
        this.stateManager = window.RawrStateManager;
        this.runtime = window.RawrRuntime;
        this.isRecovering = false;
        this.crashCount = 0;
        this.maxCrashesBeforeReload = 3;
        this.bindGlobalInterceptors();
    }

    bindGlobalInterceptors() {
        window.addEventListener('error', (event) => {
            this.handleSystemFault({
                type: 'Runtime Script Error',
                message: event.message,
                source: event.filename,
                line: event.lineno,
                col: event.colno,
                stack: event.error?.stack || null
            });
        });

        window.addEventListener('unhandledrejection', (event) => {
            this.handleSystemFault({
                type: 'Unhandled Promise Rejection',
                message: event.reason?.message || String(event.reason),
                stack: event.reason?.stack || null
            });
        });
    }

    handleSystemFault(errorEnvelope) {
        console.error('[CrashRecovery] Fault intercepted:', errorEnvelope.type, errorEnvelope.message);

        if (this.isRecovering) return;
        this.isRecovering = true;
        this.crashCount++;

        // 1. Flush telemetry
        if (this.ipc && typeof this.ipc.emit === 'function') {
            this.ipc.emit('telemetry:emit', {
                alertClass: 'FATAL_EXCEPTION',
                detail: errorEnvelope,
                crashCount: this.crashCount
            });
        }

        // 2. Log to state
        if (this.stateManager && typeof this.stateManager.dispatch === 'function') {
            this.stateManager.dispatch('ERROR_PUSH', {
                type: errorEnvelope.type,
                message: errorEnvelope.message,
                source: errorEnvelope.source
            });
        }

        // 3. Attempt rollback
        if (this.stateManager && typeof this.stateManager.rollback === 'function') {
            const success = this.stateManager.rollback();
            if (success) {
                console.log('[CrashRecovery] State rollback successful.');
                this.isRecovering = false;
                return;
            }
        }

        // 4. Last resort: reload if too many crashes
        if (this.crashCount >= this.maxCrashesBeforeReload) {
            console.warn('[CrashRecovery] Max crashes reached. Reloading...');
            setTimeout(() => window.location.reload(), 2000);
        } else {
            this.isRecovering = false;
        }
    }

    getCrashReport() {
        return {
            crashCount: this.crashCount,
            isRecovering: this.isRecovering,
            maxCrashesBeforeReload: this.maxCrashesBeforeReload
        };
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.RawrCrashRecovery = new RawrCrashRecovery();
});
