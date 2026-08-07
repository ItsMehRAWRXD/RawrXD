// ============================================================================
// migration-engine.js - Schema Migration & Version Control
// Automatic state migration with version tracking
// ============================================================================

class RawrMigrationEngine {
    constructor(storageKey = 'rawr_system_config') {
        this.storageKey = storageKey;
        this.migrations = new Map();
        this.registerDefaultMigrations();
    }

    registerDefaultMigrations() {
        this.registerMigration(1, (oldState) => ({
            version: 1,
            activePanelId: 'system-diagnostics',
            metrics: [],
            engineStatus: 'stopped',
            engineLastActive: 0,
            settings: { theme: 'dark', fontSize: 14 }
        }));

        this.registerMigration(2, (oldState) => {
            if (!oldState.securityContext) {
                oldState.securityContext = {
                    activePermissions: ['ipc:telemetry'],
                    isolationLevel: 'high'
                };
            }
            oldState.version = 2;
            return oldState;
        });

        this.registerMigration(3, (oldState) => {
            if (!oldState.session) {
                oldState.session = { lastActive: 0, token: null };
            }
            if (!oldState.errors) {
                oldState.errors = [];
            }
            oldState.version = 3;
            return oldState;
        });
    }

    registerMigration(targetVersion, migrationFn) {
        this.migrations.set(targetVersion, migrationFn);
    }

    processMigrationPipeline() {
        let rawData;
        try {
            rawData = localStorage.getItem(this.storageKey);
        } catch (e) {
            console.warn('[Migration] localStorage unavailable, using defaults.');
            rawData = null;
        }

        let currentState = rawData ? JSON.parse(rawData) : { version: 0 };
        const currentVersion = currentState.version || 0;
        let workingVersion = currentVersion;

        console.log(`[Migration] Current schema v${currentVersion}`);

        while (this.migrations.has(workingVersion + 1)) {
            workingVersion++;
            const transform = this.migrations.get(workingVersion);
            try {
                currentState = transform(currentState);
                console.log(`[Migration] Applied v${workingVersion}`);
            } catch (e) {
                console.error(`[Migration] Failed at v${workingVersion}:`, e);
                break;
            }
        }

        currentState.version = workingVersion;
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(currentState));
        } catch (e) {
            console.error('[Migration] Failed to persist migrated state:', e);
        }
        return currentState;
    }

    getCurrentVersion() {
        try {
            const raw = localStorage.getItem(this.storageKey);
            if (!raw) return 0;
            return JSON.parse(raw).version || 0;
        } catch {
            return 0;
        }
    }

    resetToFactory() {
        try {
            localStorage.removeItem(this.storageKey);
        } catch (e) {
            console.error('[Migration] Failed to reset:', e);
        }
        return this.processMigrationPipeline();
    }
}

if (typeof window !== 'undefined') {
    window.RawrMigrationEngine = new RawrMigrationEngine();
}
