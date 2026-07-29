// Sovereign Substrate - WebSocket Client Example
// Shows how to connect to the Control Plane UI from a web application

class SovereignClient {
    constructor(url = 'ws://localhost:8080') {
        this.url = url;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.messageHandlers = new Map();
        this.requestId = 0;
        this.pendingRequests = new Map();
    }

    // Connect to the Sovereign Substrate
    async connect() {
        return new Promise((resolve, reject) => {
            try {
                this.ws = new WebSocket(this.url);

                this.ws.onopen = () => {
                    console.log('✓ Connected to Sovereign Substrate');
                    this.reconnectAttempts = 0;
                    this.onConnect();
                    resolve();
                };

                this.ws.onmessage = (event) => {
                    this.handleMessage(JSON.parse(event.data));
                };

                this.ws.onclose = () => {
                    console.log('Disconnected from Sovereign Substrate');
                    this.onDisconnect();
                    this.attemptReconnect();
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    reject(error);
                };
            } catch (error) {
                reject(error);
            }
        });
    }

    // Attempt to reconnect
    attemptReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        console.log(`Reconnecting... (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

        setTimeout(() => {
            this.connect().catch(() => {
                // Reconnection failed, will try again
            });
        }, this.reconnectDelay * this.reconnectAttempts);
    }

    // Handle incoming messages
    handleMessage(message) {
        // Handle responses to pending requests
        if (message.requestId && this.pendingRequests.has(message.requestId)) {
            const { resolve, reject } = this.pendingRequests.get(message.requestId);
            this.pendingRequests.delete(message.requestId);

            if (message.error) {
                reject(new Error(message.error));
            } else {
                resolve(message.data);
            }
            return;
        }

        // Handle events
        if (message.type && this.messageHandlers.has(message.type)) {
            this.messageHandlers.get(message.type).forEach(handler => {
                try {
                    handler(message.data);
                } catch (error) {
                    console.error('Message handler error:', error);
                }
            });
        }
    }

    // Send a request and wait for response
    async sendRequest(type, data) {
        return new Promise((resolve, reject) => {
            if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
                reject(new Error('Not connected'));
                return;
            }

            const requestId = ++this.requestId;
            this.pendingRequests.set(requestId, { resolve, reject });

            // Set timeout
            setTimeout(() => {
                if (this.pendingRequests.has(requestId)) {
                    this.pendingRequests.delete(requestId);
                    reject(new Error('Request timeout'));
                }
            }, 30000);

            this.ws.send(JSON.stringify({
                requestId,
                type,
                data
            }));
        });
    }

    // Register a message handler
    on(type, handler) {
        if (!this.messageHandlers.has(type)) {
            this.messageHandlers.set(type, []);
        }
        this.messageHandlers.get(type).push(handler);

        // Return unsubscribe function
        return () => {
            const handlers = this.messageHandlers.get(type);
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        };
    }

    // Connection event handlers
    onConnect() {
        // Override in subclass
    }

    onDisconnect() {
        // Override in subclass
    }

    // API Methods

    // Execute an intent
    async executeIntent(action, params = {}) {
        return this.sendRequest('execute_intent', { action, params });
    }

    // Execute a tool
    async executeTool(toolName, params = {}) {
        return this.sendRequest('execute_tool', { toolName, params });
    }

    // Get system status
    async getStatus() {
        return this.sendRequest('get_status', {});
    }

    // Get repository memory graph
    async getMemoryGraph() {
        return this.sendRequest('get_memory_graph', {});
    }

    // Query the memory graph
    async queryMemory(query) {
        return this.sendRequest('query_memory', { query });
    }

    // Get telemetry data
    async getTelemetry(since = null) {
        return this.sendRequest('get_telemetry', { since });
    }

    // Subscribe to events
    async subscribe(eventTypes) {
        return this.sendRequest('subscribe', { eventTypes });
    }

    // Unsubscribe from events
    async unsubscribe(eventTypes) {
        return this.sendRequest('unsubscribe', { eventTypes });
    }

    // Disconnect
    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Example usage
async function main() {
    const client = new SovereignClient('ws://localhost:8080');

    // Handle connection
    client.onConnect = () => {
        console.log('Connected!');
    };

    // Subscribe to events
    client.on('intent_executed', (data) => {
        console.log('Intent executed:', data);
    });

    client.on('tool_executed', (data) => {
        console.log('Tool executed:', data);
    });

    client.on('telemetry', (data) => {
        console.log('Telemetry:', data);
    });

    try {
        // Connect
        await client.connect();

        // Get system status
        const status = await client.getStatus();
        console.log('System status:', status);

        // Execute a tool
        const result = await client.executeTool('read_file', {
            file_path: 'src/main.cpp'
        });
        console.log('File content:', result);

        // Execute an intent
        const intentResult = await client.executeIntent('analyze_code', {
            target: 'src/main.cpp'
        });
        console.log('Analysis result:', intentResult);

        // Subscribe to events
        await client.subscribe(['intent_executed', 'tool_executed', 'telemetry']);

        // Keep connection alive
        await new Promise(() => {});

    } catch (error) {
        console.error('Error:', error);
    } finally {
        client.disconnect();
    }
}

// Run if executed directly
if (typeof window === 'undefined') {
    main().catch(console.error);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SovereignClient };
}
