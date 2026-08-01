// ============================================================================
// state-manager.js - Atomic State & Transaction Logger
// Immutable state with rolling transaction history for rollback
// ============================================================================

class RawrStateManager {
    constructor() {
        this.state = {};
        this.listeners = new Set();
        this.transactionHistory = [];
        this.maxHistory = 100;
        this.initialized = false;
    }

    initialize(initialState = {}) {
        this.state = JSON.parse(JSON.stringify(initialState));
        this.transactionHistory = [{
            timestamp: Date.now(),
            action: 'SYSTEM_INIT',
            payload: {},
            stateSnapshot: this.getState()
        }];
        this.initialized = true;
        this.notify();
    }

    getState() {
        return JSON.parse(JSON.stringify(this.state));
    }

    dispatch(actionType, payload = {}) {
        if (!this.initialized) this.initialize();
        const previousState = this.getState();
        const nextState = this.reducer(previousState, actionType, payload);
        this.state = nextState;
        this.logTransaction(actionType, payload);
        this.notify();
    }

    reducer(state, actionType, payload) {
        switch (actionType) {
            case 'ENGINE_UPDATE_STATUS':
                return { ...state, engineStatus: payload.status, engineLastActive: Date.now() };
            case 'PANEL_SET_ACTIVE':
                return { ...state, activePanelId: payload.id };
            case 'TELEMETRY_APPEND': {
                const metrics = [...(state.metrics || [])];
                metrics.push({ ...payload.data, timestamp: Date.now() });
                if (metrics.length > 50) metrics.shift();
                return { ...state, metrics };
            }
            case 'SETTINGS_UPDATE':
                return { ...state, settings: { ...(state.settings || {}), ...payload } };
            case 'SESSION_SET':
                return { ...state, session: { ...payload, lastActive: Date.now() } };
            case 'SESSION_CLEAR':
                const { session, ...rest } = state;
                return rest;
            case 'ERROR_PUSH': {
                const errors = [...(state.errors || [])];
                errors.push({ ...payload, timestamp: Date.now() });
                if (errors.length > 20) errors.shift();
                return { ...state, errors };
            }
            case 'STATE_RESET':
                return { version: state.version };
            default:
                return state;
        }
    }

    logTransaction(action, payload) {
        this.transactionHistory.push({
            timestamp: Date.now(),
            action,
            payload: JSON.parse(JSON.stringify(payload)),
            stateSnapshot: this.getState()
        });
        if (this.transactionHistory.length > this.maxHistory) {
            this.transactionHistory.shift();
        }
    }

    rollback() {
        if (this.transactionHistory.length <= 1) return false;
        this.transactionHistory.pop();
        const targetTx = this.transactionHistory[this.transactionHistory.length - 1];
        this.state = JSON.parse(JSON.stringify(targetTx.stateSnapshot));
        console.warn(`[StateManager] Rolled back to: ${targetTx.action}`);
        this.notify();
        return true;
    }

    subscribe(callback) {
        this.listeners.add(callback);
        return () => this.listeners.delete(callback);
    }

    notify() {
        const snapshot = this.getState();
        this.listeners.forEach(cb => {
            try { cb(snapshot); } catch (e) { console.error('[StateManager] Listener error:', e); }
        });
    }

    getTransactionLog() {
        return this.transactionHistory.map(t => ({
            timestamp: t.timestamp,
            action: t.action,
            payloadSize: JSON.stringify(t.payload).length
        }));
    }
}

if (typeof window !== 'undefined') {
    window.RawrStateManager = new RawrStateManager();
}
