/**
 * RawrXD Native Sidecar Client
 * 
 * Manages the native C++ sidecar process and named pipe communication.
 * This moves agent orchestration out of Node.js into zero-overhead native code.
 */

import { spawn, ChildProcess } from 'child_process';
import * as net from 'net';
import * as path from 'path';
import { EventEmitter } from 'events';

export interface SidecarMessage {
    id: string;
    type: 'request' | 'response' | 'event' | 'error';
    payload: unknown;
    timestamp: number;
}

export interface AgentRequest {
    action: 'plan' | 'execute' | 'stop' | 'status';
    goal?: string;
    taskId?: string;
    context?: {
        filePath?: string;
        selection?: string;
        languageId?: string;
    };
}

export interface AgentResponse {
    status: 'success' | 'error' | 'streaming';
    taskId?: string;
    result?: unknown;
    error?: string;
}

export interface AgentEvent {
    type: 'log' | 'step_start' | 'step_complete' | 'step_failed' | 'task_complete';
    taskId: string;
    stepId?: string;
    message: string;
    data?: unknown;
}

/**
 * SidecarClient - Manages native sidecar process and IPC
 * 
 * Architecture:
 * VSCode Extension (TS) ←→ Named Pipe ←→ Native Sidecar (C++23)
 *                                    ↓
 *                              GPU Dispatch (RDNA4)
 */
export class SidecarClient extends EventEmitter {
    private process: ChildProcess | null = null;
    private pipe: net.Socket | null = null;
    private readonly pipePath = '\\\\.\\pipe\\RawrXD_Agent_Sidecar';
    private connected: boolean = false;
    private messageQueue: SidecarMessage[] = [];
    private responseHandlers: Map<string, (response: AgentResponse) => void> = new Map();
    private reconnectAttempts: number = 0;
    private maxReconnectAttempts: number = 3;

    /**
     * Start the native sidecar process and connect to named pipe
     */
    async start(): Promise<void> {
        // Path to native sidecar executable
        const sidecarPath = path.join(
            __dirname, '..', '..', '..', 'native', 'sidecar', 'RawrXD_Sidecar.exe'
        );

        console.log('[RawrXD] Starting native sidecar:', sidecarPath);

        // Spawn native process
        this.process = spawn(sidecarPath, [], {
            detached: false,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
            env: {
                ...process.env,
                'RAWRXD_PIPE_PATH': this.pipePath
            }
        });

        // Wait for sidecar to initialize
        await new Promise<void>((resolve, reject) => {
            let stdoutBuffer = '';
            
            this.process?.stdout?.on('data', (data: Buffer) => {
                stdoutBuffer += data.toString();
                
                // Look for ready signal
                if (stdoutBuffer.includes('Waiting for VSCode extension')) {
                    resolve();
                }
            });

            this.process?.stderr?.on('data', (data: Buffer) => {
                console.error('[RawrXD Sidecar stderr]:', data.toString());
            });

            this.process?.once('error', (err) => {
                reject(new Error(`Sidecar process error: ${err.message}`));
            });

            this.process?.once('exit', (code) => {
                reject(new Error(`Sidecar exited with code ${code}`));
            });

            // Timeout after 10 seconds
            setTimeout(() => {
                reject(new Error('Sidecar startup timeout'));
            }, 10000);
        });

        // Connect to named pipe
        await this._connectPipe();
        
        console.log('[RawrXD] Native sidecar linked successfully');
    }

    /**
     * Connect to the named pipe
     */
    private async _connectPipe(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.pipe = new net.Socket();
            
            this.pipe.connect(this.pipePath, () => {
                this.connected = true;
                this.reconnectAttempts = 0;
                this.emit('connected');
                
                // Flush queued messages
                this._flushQueue();
                resolve();
            });

            this.pipe.on('data', (data: Buffer) => {
                this._handleMessage(data.toString());
            });

            this.pipe.on('error', (err: Error) => {
                console.error('[RawrXD] Pipe error:', err);
                this.emit('error', err);
                
                if (!this.connected) {
                    reject(err);
                } else {
                    this._attemptReconnect();
                }
            });

            this.pipe.on('close', () => {
                console.log('[RawrXD] Pipe closed');
                this.connected = false;
                this.emit('disconnected');
                this._attemptReconnect();
            });

            // Timeout connection attempt
            setTimeout(() => {
                if (!this.connected) {
                    reject(new Error('Pipe connection timeout'));
                }
            }, 5000);
        });
    }

    /**
     * Attempt to reconnect to sidecar
     */
    private async _attemptReconnect(): Promise<void> {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('[RawrXD] Max reconnection attempts reached');
            this.emit('failed');
            return;
        }

        this.reconnectAttempts++;
        console.log(`[RawrXD] Reconnecting... attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);

        setTimeout(() => {
            this._connectPipe().catch(() => {
                // Reconnection failed, will retry
            });
        }, 1000 * this.reconnectAttempts);
    }

    /**
     * Send a request to the sidecar
     */
    async sendRequest(request: AgentRequest): Promise<AgentResponse> {
        const message: SidecarMessage = {
            id: `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            type: 'request',
            payload: request,
            timestamp: Date.now()
        };

        return new Promise((resolve, reject) => {
            // Set up response handler
            this.responseHandlers.set(message.id, resolve);
            
            // Send message
            this._send(message);

            // Timeout after 30 seconds
            setTimeout(() => {
                if (this.responseHandlers.has(message.id)) {
                    this.responseHandlers.delete(message.id);
                    reject(new Error('Request timeout'));
                }
            }, 30000);
        });
    }

    /**
     * Send raw message to sidecar
     */
    private _send(message: SidecarMessage): void {
        if (!this.connected || !this.pipe) {
            this.messageQueue.push(message);
            return;
        }
        
        const data = JSON.stringify(message) + '\n';
        this.pipe.write(data);
    }

    /**
     * Flush queued messages
     */
    private _flushQueue(): void {
        while (this.messageQueue.length > 0 && this.connected) {
            const message = this.messageQueue.shift();
            if (message) {
                this._send(message);
            }
        }
    }

    /**
     * Handle incoming message from sidecar
     */
    private _handleMessage(data: string): void {
        // Handle multiple messages in one chunk
        const lines = data.split('\n').filter(line => line.trim());
        
        for (const line of lines) {
            try {
                const message: SidecarMessage = JSON.parse(line);
                
                if (message.type === 'response') {
                    const handler = this.responseHandlers.get(message.id);
                    if (handler) {
                        handler(message.payload as AgentResponse);
                        this.responseHandlers.delete(message.id);
                    }
                } else if (message.type === 'event') {
                    this.emit('event', message.payload as AgentEvent);
                } else if (message.type === 'error') {
                    this.emit('error', message.payload);
                }
            } catch (e) {
                console.error('[RawrXD] Failed to parse sidecar message:', e);
            }
        }
    }

    /**
     * RAG: Index workspace for semantic search
     */
    async indexWorkspace(workspacePath: string): Promise<{ status: string; documentsIndexed?: number; indexSizeMB?: number; error?: string }> {
        return this.sendRequest({
            action: 'rag_index',
            workspacePath,
            taskId: `rag-index-${Date.now()}`
        }) as Promise<{ status: string; documentsIndexed?: number; indexSizeMB?: number; error?: string }>;
    }

    /**
     * RAG: Semantic search
     */
    async search(query: string, maxResults: number = 10): Promise<{ status: string; results?: SearchResult[]; count?: number; error?: string }> {
        return this.sendRequest({
            action: 'rag_search',
            query,
            maxResults,
            taskId: `rag-search-${Date.now()}`
        }) as Promise<{ status: string; results?: SearchResult[]; count?: number; error?: string }>;
    }

    /**
     * RAG: Get context for agent
     */
    async getContext(query: string, filePath: string, maxTokens: number = 2048): Promise<{ status: string; context?: string; tokens?: number; error?: string }> {
        return this.sendRequest({
            action: 'rag_context',
            query,
            context: { filePath },
            maxTokens,
            taskId: `rag-context-${Date.now()}`
        }) as Promise<{ status: string; context?: string; tokens?: number; error?: string }>;
    }

    /**
     * Check if connected to sidecar
     */
    isConnected(): boolean {
        return this.connected;
    }

    /**
     * Stop the sidecar process
     */
    stop(): void {
        this.connected = false;
        
        if (this.pipe) {
            this.pipe.end();
            this.pipe = null;
        }
        
        if (this.process) {
            this.process.kill();
            this.process = null;
        }
        
        this.emit('disconnected');
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        this.stop();
        this.removeAllListeners();
    }
}

// Search result interface
export interface SearchResult {
    docId: string;
    score: number;
    document: {
        id: string;
        filePath: string;
        lineStart: number;
        lineEnd: number;
        content: string;
    };
}

export { SidecarClient as default };
