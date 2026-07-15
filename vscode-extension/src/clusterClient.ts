import { EventEmitter } from 'events';
import * as http from 'http';

export interface CompletionRequest {
    uri: string;
    languageId: string;
    prefix: string;
    line: number;
    character: number;
    maxTokens: number;
    temperature: number;
}

export interface CompletionItem {
    label: string;
    insertText: string;
    kind?: string;
    score: number;
    tokens?: number;
}

export interface CompletionResponse {
    items: CompletionItem[];
    latencyMs: number;
}

export interface ClusterStatus {
    nodes: number;
    tps: number;
    healthy: boolean;
}

export interface StreamingCompletionRequest extends CompletionRequest {
    onToken: (token: string) => void;
    onComplete: () => void;
    onError: (error: Error) => void;
}

export class RawrXDClusterClient extends EventEmitter {
    private endpoint: string;
    private requestQueue: CompletionRequest[] = [];
    private isProcessing = false;

    constructor(endpoint: string) {
        super();
        this.endpoint = endpoint;
    }

    async complete(request: CompletionRequest): Promise<CompletionResponse> {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            
            // Build HTTP request to cluster
            const postData = JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'textDocument/completion',
                params: {
                    textDocument: { uri: request.uri },
                    position: { line: request.line, character: request.character },
                    context: request.prefix,
                    options: {
                        max_tokens: request.maxTokens,
                        temperature: request.temperature
                    }
                }
            });

            const options = {
                hostname: this.extractHostname(this.endpoint),
                port: this.extractPort(this.endpoint),
                path: '/v1/completions',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    'X-Request-ID': `req-${Date.now()}`
                },
                timeout: 5000 // 5 second timeout
            };

            const req = http.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    try {
                        const response = JSON.parse(data);
                        const latencyMs = Date.now() - startTime;
                        
                        if (response.error) {
                            reject(new Error(response.error.message));
                            return;
                        }

                        resolve({
                            items: response.result?.items || [],
                            latencyMs
                        });
                    } catch (e) {
                        reject(new Error(`Parse error: ${e}`));
                    }
                });
            });

            req.on('error', (e) => reject(e));
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            req.write(postData);
            req.end();
        });
    }

    /**
     * Streaming completion - calls onToken for each chunk
     * This is the king style real-time streaming for Copilot parity
     */
    async completeStreaming(request: StreamingCompletionRequest): Promise<void> {
        return new Promise((resolve, reject) => {
            const postData = JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'textDocument/completion',
                params: {
                    textDocument: { uri: request.uri },
                    position: { line: request.line, character: request.character },
                    context: request.prefix,
                    options: {
                        max_tokens: request.maxTokens,
                        temperature: request.temperature,
                        stream: true // Enable streaming
                    }
                }
            });

            const options = {
                hostname: this.extractHostname(this.endpoint),
                port: this.extractPort(this.endpoint),
                path: '/v1/completions',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    'X-Request-ID': `req-${Date.now()}`,
                    'Accept': 'text/event-stream'
                },
                timeout: 30000 // 30 second timeout for streaming
            };

            let buffer = '';
            
            const req = http.request(options, (res) => {
                res.on('data', (chunk: Buffer) => {
                    buffer += chunk.toString();
                    
                    // Process SSE format: data: {...}\n\n
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || ''; // Keep incomplete line
                    
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const data = line.slice(6);
                            if (data === '[DONE]') {
                                request.onComplete();
                                resolve();
                                return;
                            }
                            
                            try {
                                const parsed = JSON.parse(data);
                                if (parsed.choices?.[0]?.text) {
                                    request.onToken(parsed.choices[0].text);
                                }
                            } catch (e) {
                                // Ignore parse errors for malformed chunks
                            }
                        }
                    }
                });

                res.on('end', () => {
                    request.onComplete();
                    resolve();
                });
            });

            req.on('error', (e) => {
                request.onError(e);
                reject(e);
            });

            req.on('timeout', () => {
                req.destroy();
                const error = new Error('Streaming request timeout');
                request.onError(error);
                reject(error);
            });

            req.write(postData);
            req.end();
        });
    }

    async getStatus(): Promise<ClusterStatus> {
        return new Promise((resolve) => {
            const options = {
                hostname: this.extractHostname(this.endpoint),
                port: this.extractPort(this.endpoint),
                path: '/health',
                method: 'GET',
                timeout: 2000
            };

            const req = http.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    try {
                        const status = JSON.parse(data);
                        resolve({
                            nodes: status.nodes || 0,
                            tps: status.tps || 0,
                            healthy: res.statusCode === 200
                        });
                    } catch (e) {
                        resolve({ nodes: 0, tps: 0, healthy: false });
                    }
                });
            });

            req.on('error', () => resolve({ nodes: 0, tps: 0, healthy: false }));
            req.on('timeout', () => {
                req.destroy();
                resolve({ nodes: 0, tps: 0, healthy: false });
            });

            req.end();
        });
    }

    dispose() {
        this.removeAllListeners();
    }

    private extractHostname(endpoint: string): string {
        const url = new URL(endpoint);
        return url.hostname;
    }

    private extractPort(endpoint: string): number {
        const url = new URL(endpoint);
        return parseInt(url.port) || 80;
    }
}
