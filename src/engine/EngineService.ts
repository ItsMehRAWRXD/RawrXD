/**
 * EngineService.ts
 * 
 * Encapsulates all communication with the Sovereign Inference Orchestration (SIO) backend.
 * This service is the single source of truth for engine state. UI components should subscribe
 * to state changes rather than making direct API calls.
 * 
 * Governance: This service is UI-agnostic and framework-independent.
 * Drop into any React useEffect, Vue onMounted, or vanilla setInterval.
 */

export interface EngineStatus {
    status: string;
    session_id: string;
    startup_epoch_ms: number;
    status_seq: number;
    last_update_epoch_ms: number;
    model_loaded: boolean;
    active_model: string;
    loader_context: {
        state: string;
        last_error_tag: string;
        win32_error_code: number;
        retry_count: number;
        retry_budget_rem: number;
        can_retry: boolean;
        terminal_fault: boolean;
        fault_class: string;
        suggested_action: string;
        pending_inference: boolean;
        last_completed_request_id: number;
        unload_requested: boolean;
    };
}

export interface FaultSidecar {
    source: string;
    process_id: number;
    session_id: string;
    startup_epoch_ms: number;
    status_seq: number;
    last_update_epoch_ms: number;
    active_model: string;
    loader_context: {
        state: string;
        last_error_tag: string;
        win32_error_code: number;
        retry_count: number;
        retry_budget_rem: number;
        can_retry: boolean;
        terminal_fault: boolean;
        fault_class: string;
        suggested_action: string;
    };
}

export type EngineStateCode = 'IDLE' | 'LOADING' | 'READY' | 'FAULT' | 'UNKNOWN';

export class EngineService {
    private endpoint: string;
    private pollingInterval: NodeJS.Timer | null = null;
    private lastStatus: EngineStatus | null = null;
    private statusCallbacks: Array<(status: EngineStatus) => void> = [];
    private faultCallbacks: Array<(fault: FaultSidecar | null) => void> = [];
    private pollFrequencyMs: number = 1000; // 1Hz default

    constructor(endpoint: string = 'http://127.0.0.1:11435') {
        this.endpoint = endpoint;
    }

    /**
     * Start polling the engine status at the configured frequency.
     * On poll failure, immediately attempt sidecar read.
     */
    public startPolling(): void {
        if (this.pollingInterval) {
            console.warn('Polling already started');
            return;
        }

        this.pollingInterval = setInterval(async () => {
            await this.pollStatus();
        }, this.pollFrequencyMs);

        console.log(`[EngineService] Started polling ${this.endpoint} every ${this.pollFrequencyMs}ms`);
    }

    /**
     * Stop polling the engine.
     */
    public stopPolling(): void {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
            console.log('[EngineService] Polling stopped');
        }
    }

    /**
     * Subscribe to status updates.
     * Callback fires every time status is fetched (whether changed or not).
     */
    public onStatusChange(callback: (status: EngineStatus) => void): () => void {
        this.statusCallbacks.push(callback);
        return () => {
            this.statusCallbacks = this.statusCallbacks.filter((cb) => cb !== callback);
        };
    }

    /**
     * Subscribe to fault events (when sidecar is read due to poll failure).
     */
    public onFaultDetected(callback: (fault: FaultSidecar | null) => void): () => void {
        this.faultCallbacks.push(callback);
        return () => {
            this.faultCallbacks = this.faultCallbacks.filter((cb) => cb !== callback);
        };
    }

    /**
     * Get the current cached status.
     */
    public getStatus(): EngineStatus | null {
        return this.lastStatus;
    }

    /**
     * Map numeric state code to human-readable string.
     */
    public getStateLabel(stateCode: string): EngineStateCode {
        switch (stateCode) {
            case 'idle':
                return 'IDLE';
            case 'loading':
                return 'LOADING';
            case 'ready':
                return 'READY';
            case 'fault':
                return 'FAULT';
            default:
                return 'UNKNOWN';
        }
    }

    /**
     * Poll the engine status endpoint.
     * On success: update internal state and notify subscribers.
     * On failure: trigger sidecar read.
     */
    private async pollStatus(): Promise<void> {
        try {
            const response = await fetch(`${this.endpoint}/status`, {
                method: 'GET',
                timeout: 1500, // Fail fast if endpoint is unresponsive
            });

            if (!response.ok) {
                console.warn(`[EngineService] Status poll returned ${response.status}; attempting sidecar read`);
                await this.readSidecar();
                return;
            }

            const data: EngineStatus = await response.json();
            this.lastStatus = data;

            // Notify all subscribers
            this.statusCallbacks.forEach((cb) => cb(data));
        } catch (err) {
            console.error('[EngineService] Status poll failed:', err);
            await this.readSidecar();
        }
    }

    /**
     * Attempt to read the sidecar file from the local filesystem.
     * This is typically done via an Electron IPC call or a backend endpoint that serves it.
     * 
     * Placeholder: Assumes your backend has a `/fault_sidecar` endpoint.
     */
    private async readSidecar(): Promise<void> {
        try {
            const response = await fetch(`${this.endpoint}/fault_sidecar`, {
                method: 'GET',
                timeout: 500,
            });

            if (response.ok) {
                const sidecar: FaultSidecar = await response.json();
                this.faultCallbacks.forEach((cb) => cb(sidecar));
                console.log('[EngineService] Sidecar read successfully:', sidecar);
                return;
            }
        } catch (err) {
            console.error('[EngineService] Sidecar read failed:', err);
        }

        // If we get here, both poll and sidecar failed
        this.faultCallbacks.forEach((cb) => cb(null));
    }

    /**
     * Check if the engine is currently ready to accept inferences.
     */
    public isReady(): boolean {
        return this.lastStatus?.loader_context?.state === 'ready' ?? false;
    }

    /**
     * Check if the engine is in a fault state.
     */
    public isFaulted(): boolean {
        return this.lastStatus?.loader_context?.state === 'fault' ?? false;
    }

    /**
     * Get the suggested action from the engine policy.
     */
    public getSuggestedAction(): string {
        return this.lastStatus?.loader_context?.suggested_action ?? 'UNKNOWN';
    }

    /**
     * Get the recommended model from the engine.
     */
    public getRecommendedModel(): string {
        return this.lastStatus?.active_model ?? 'none';
    }

    /**
     * Get the current session ID (for tracing).
     */
    public getSessionId(): string {
        return this.lastStatus?.session_id ?? 'unknown';
    }

    /**
     * Get the current status sequence number (for freshness validation).
     */
    public getStatusSeq(): number {
        return this.lastStatus?.status_seq ?? -1;
    }
}

/**
 * Singleton instance for easy import and use.
 */
export const engineService = new EngineService();
