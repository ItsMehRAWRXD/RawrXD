import * as vscode from 'vscode';

export class ThrottleInterceptor {
    private disposables: vscode.Disposable[] = [];
    private requestCount = 0;
    private throttledCount = 0;

    activate() {
        // Intercept HTTP requests to local models
        this.interceptLocalModelRequests();
        
        // Monitor Copilot chat requests
        this.monitorCopilotChat();
        
        console.log('[CopilotThrottle] Interceptor activated');
    }

    deactivate() {
        this.disposables.forEach(d => d.dispose());
        this.disposables = [];
        console.log('[CopilotThrottle] Interceptor deactivated');
    }

    private interceptLocalModelRequests() {
        const config = vscode.workspace.getConfiguration('copilotThrottle');
        const patterns = config.get<string[]>('localModelPatterns', ['rawrxd', 'ollama', 'localhost']);
        
        // Hook into fetch/HTTP requests
        const originalFetch = globalThis.fetch;
        
        globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = input.toString();
            
            // Check if this is a local model request
            const isLocalModel = patterns.some(p => url.includes(p));
            
            if (isLocalModel && init?.body) {
                try {
                    const body = JSON.parse(init.body.toString());
                    
                    // Apply throttling
                    const maxTokens = config.get<number>('maxTokens', 2048);
                    const maxChars = config.get<number>('maxChars', 8000);
                    
                    // Limit max_tokens
                    if (body.max_tokens && body.max_tokens > maxTokens) {
                        console.log(`[CopilotThrottle] Reducing max_tokens: ${body.max_tokens} -> ${maxTokens}`);
                        body.max_tokens = maxTokens;
                    }
                    
                    // Ensure streaming is enabled for large requests
                    if (!body.stream && JSON.stringify(body).length > 1000) {
                        console.log('[CopilotThrottle] Enabling streaming for large request');
                        body.stream = true;
                    }
                    
                    // Add response size hint
                    body.options = body.options || {};
                    body.options.num_ctx = Math.min(body.options.num_ctx || 4096, 4096);
                    
                    init.body = JSON.stringify(body);
                    this.requestCount++;
                    
                } catch (e) {
                    // Not JSON, ignore
                }
            }
            
            return originalFetch(input, init);
        };
    }

    private monitorCopilotChat() {
        // Listen for Copilot chat events
        const chatDisposable = vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('github.copilot')) {
                this.applyCopilotLimits();
            }
        });
        
        this.disposables.push(chatDisposable);
        
        // Apply limits immediately
        this.applyCopilotLimits();
    }

    private applyCopilotLimits() {
        const config = vscode.workspace.getConfiguration('copilotThrottle');
        const maxTokens = config.get<number>('maxTokens', 2048);
        
        // Set environment variable that RawrXD can read
        process.env.RAWRXD_MAX_TOKENS = maxTokens.toString();
        process.env.RAWRXD_STREAMING_ENABLED = '1';
        
        console.log(`[CopilotThrottle] Applied limits: ${maxTokens} tokens, streaming enabled`);
    }

    getStats() {
        return {
            requestsProcessed: this.requestCount,
            requestsThrottled: this.throttledCount
        };
    }
}
