// ============================================================================
// ledger-committer.js - Transaction Journal & Persistent Storage
// Async mutation journaling with periodic disk flush
// ============================================================================

class RawrLedgerCommitter {
    constructor() {
        this.stateManager = window.RawrStateManager;
        this.ipc = window.RawrIpcSynchronizer;
        this.isDirty = false;
        this.journalQueue = [];
        this.flushInterval = 2000;
        this.storageKey = 'rawr_ledger_journal';
        this.startJournalTimer();
        this.attachToStateManager();
    }

    attachToStateManager() {
        if (this.stateManager && typeof this.stateManager.subscribe === 'function') {
            this.stateManager.subscribe((snapshot) => this.enqueueMutation(snapshot));
            console.log('[Ledger] Attached to state manager.');
        }
    }

    enqueueMutation(stateSnapshot) {
        const entry = {
            txId: `tx-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            timestamp: Date.now(),
            checksum: this.generateChecksum(JSON.stringify(stateSnapshot)),
            data: stateSnapshot
        };
        this.journalQueue.push(entry);
        this.isDirty = true;
    }

    startJournalTimer() {
        setInterval(() => {
            if (!this.isDirty || this.journalQueue.length === 0) return;
            this.flushJournalToDisk();
        }, this.flushInterval);
    }

    flushJournalToDisk() {
        const pending = [...this.journalQueue];
        this.journalQueue = [];
        this.isDirty = false;

        console.log(`[Ledger] Flushing ${pending.length} transactions...`);

        // IPC telemetry
        if (this.ipc && typeof this.ipc.emit === 'function') {
            this.ipc.emit('telemetry:emit', {
                alertClass: 'PERSISTENCE_SYNC',
                detail: {
                    batchCount: pending.length,
                    latestTxId: pending[pending.length - 1].txId,
                    latestChecksum: pending[pending.length - 1].checksum
                }
            });
        }

        // LocalStorage persistence
        try {
            const latest = pending[pending.length - 1].data;
            localStorage.setItem('rawr_system_config', JSON.stringify(latest));
            localStorage.setItem(this.storageKey, JSON.stringify(pending.slice(-10)));
        } catch (e) {
            console.error('[Ledger] Persist failed:', e);
        }
    }

    generateChecksum(data) {
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash) + data.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash).toString(16).padStart(8, '0');
    }

    getJournal() {
        try {
            const raw = localStorage.getItem(this.storageKey);
            return raw ? JSON.parse(raw) : [];
        } catch {
            return [];
        }
    }
}

if (typeof window !== 'undefined') {
    window.RawrLedgerCommitter = new RawrLedgerCommitter();
}
