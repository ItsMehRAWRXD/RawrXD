"use strict";
/**
 * RawrXD Native Sidecar Client
 *
 * Manages the native C++ sidecar process and named pipe communication.
 * This moves agent orchestration out of Node.js into zero-overhead native code.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = exports.SidecarClient = void 0;
const child_process_1 = require("child_process");
const net = __importStar(require("net"));
const path = __importStar(require("path"));
const events_1 = require("events");
/**
 * SidecarClient - Manages native sidecar process and IPC
 *
 * Architecture:
 * VSCode Extension (TS) ←→ Named Pipe ←→ Native Sidecar (C++23)
 *                                    ↓
 *                              GPU Dispatch (RDNA4)
 */
class SidecarClient extends events_1.EventEmitter {
    process = null;
    pipe = null;
    pipePath = '\\\\.\\pipe\\RawrXD_Agent_Sidecar';
    connected = false;
    messageQueue = [];
    responseHandlers = new Map();
    reconnectAttempts = 0;
    maxReconnectAttempts = 3;
    /**
     * Start the native sidecar process and connect to named pipe
     */
    async start() {
        // Path to native sidecar executable
        const sidecarPath = path.join(__dirname, '..', '..', '..', 'native', 'sidecar', 'RawrXD_Sidecar.exe');
        console.log('[RawrXD] Starting native sidecar:', sidecarPath);
        // Spawn native process
        this.process = (0, child_process_1.spawn)(sidecarPath, [], {
            detached: false,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
            env: {
                ...process.env,
                'RAWRXD_PIPE_PATH': this.pipePath
            }
        });
        // Wait for sidecar to initialize
        await new Promise((resolve, reject) => {
            let stdoutBuffer = '';
            this.process?.stdout?.on('data', (data) => {
                stdoutBuffer += data.toString();
                // Look for ready signal
                if (stdoutBuffer.includes('Waiting for VSCode extension')) {
                    resolve();
                }
            });
            this.process?.stderr?.on('data', (data) => {
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
    async _connectPipe() {
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
            this.pipe.on('data', (data) => {
                this._handleMessage(data.toString());
            });
            this.pipe.on('error', (err) => {
                console.error('[RawrXD] Pipe error:', err);
                this.emit('error', err);
                if (!this.connected) {
                    reject(err);
                }
                else {
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
    async _attemptReconnect() {
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
    async sendRequest(request) {
        const message = {
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
    _send(message) {
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
    _flushQueue() {
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
    _handleMessage(data) {
        // Handle multiple messages in one chunk
        const lines = data.split('\n').filter(line => line.trim());
        for (const line of lines) {
            try {
                const message = JSON.parse(line);
                if (message.type === 'response') {
                    const handler = this.responseHandlers.get(message.id);
                    if (handler) {
                        handler(message.payload);
                        this.responseHandlers.delete(message.id);
                    }
                }
                else if (message.type === 'event') {
                    this.emit('event', message.payload);
                }
                else if (message.type === 'error') {
                    this.emit('error', message.payload);
                }
            }
            catch (e) {
                console.error('[RawrXD] Failed to parse sidecar message:', e);
            }
        }
    }
    /**
     * RAG: Index workspace for semantic search
     */
    async indexWorkspace(workspacePath) {
        return this.sendRequest({
            action: 'rag_index',
            workspacePath,
            taskId: `rag-index-${Date.now()}`
        });
    }
    /**
     * RAG: Semantic search
     */
    async search(query, maxResults = 10) {
        return this.sendRequest({
            action: 'rag_search',
            query,
            maxResults,
            taskId: `rag-search-${Date.now()}`
        });
    }
    /**
     * RAG: Get context for agent
     */
    async getContext(query, filePath, maxTokens = 2048) {
        return this.sendRequest({
            action: 'rag_context',
            query,
            context: { filePath },
            maxTokens,
            taskId: `rag-context-${Date.now()}`
        });
    }
    /**
     * Check if connected to sidecar
     */
    isConnected() {
        return this.connected;
    }
    /**
     * Stop the sidecar process
     */
    stop() {
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
    dispose() {
        this.stop();
        this.removeAllListeners();
    }
}
exports.SidecarClient = SidecarClient;
exports.default = SidecarClient;
//# sourceMappingURL=sidecarProtocol.js.map