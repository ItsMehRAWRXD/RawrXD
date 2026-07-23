// Copilot Throttle Proxy Server
// Intercepts local/cloud model requests and applies throttling + error recovery

const http = require('http');
const https = require('https');
const { URL } = require('url');

const PROXY_PORT = 9091;  // Throttle proxy port
const TARGET_PORT = 9090; // RawrXD actual port

// Throttle configuration
const MAX_TOKENS = parseInt(process.env.THROTTLE_MAX_TOKENS || '2048');
const MAX_CHARS = parseInt(process.env.THROTTLE_MAX_CHARS || '8000');
const STREAM_CHUNK_SIZE = parseInt(process.env.THROTTLE_CHUNK_SIZE || '512');
const MAX_RETRIES = parseInt(process.env.THROTTLE_MAX_RETRIES || '2');

// Known cloud endpoints that need throttling / error recovery
const CLOUD_ENDPOINTS = [
    { host: 'api.openai.com', path: '/v1/chat/completions' },
    { host: 'api.anthropic.com', path: '/v1/messages' },
    { host: 'api.groq.com', path: '/openai/v1/chat/completions' },
    { host: 'api.together.xyz', path: '/v1/chat/completions' },
    { host: 'api.deepseek.com', path: '/chat/completions' },
    { host: 'generativelanguage.googleapis.com', path: '/v1beta/models' },
    { host: 'api.minimax.chat', path: '/v1/text/chatcompletion_v2' },
    { host: 'api.moonshot.cn', path: '/v1/chat/completions' },
    { host: 'api.glm.ai', path: '/v4/chat/completions' },
    { host: 'api.kimi.com', path: '/v1/chat/completions' }
];

function isCloudEndpoint(targetUrl) {
    try {
        const u = new URL(targetUrl);
        return CLOUD_ENDPOINTS.some(ep => u.hostname === ep.host || u.hostname.endsWith('.' + ep.host));
    } catch {
        return false;
    }
}

function getTargetFromRequest(req) {
    // Check for X-Target-Url header (used by extension to forward cloud requests)
    const targetHeader = req.headers['x-target-url'];
    if (targetHeader) return targetHeader;
    
    // Default to local RawrXD
    return `http://127.0.0.1:${TARGET_PORT}`;
}

console.log(`[CopilotThrottle] Proxy starting on port ${PROXY_PORT}`);
console.log(`[CopilotThrottle] Default target: RawrXD on port ${TARGET_PORT}`);
console.log(`[CopilotThrottle] Limits: ${MAX_TOKENS} tokens, ${MAX_CHARS} chars`);

function applyThrottle(data, reqUrl) {
    // Apply throttling
    if (data.max_tokens && data.max_tokens > MAX_TOKENS) {
        console.log(`[Throttle] Reducing max_tokens: ${data.max_tokens} -> ${MAX_TOKENS}`);
        data.max_tokens = MAX_TOKENS;
    }
    
    // Force streaming for chat completions
    if (reqUrl?.includes('/v1/chat/completions') || reqUrl?.includes('/api/generate')) {
        if (!data.stream) {
            console.log('[Throttle] Enabling streaming for chat request');
            data.stream = true;
        }
    }
    
    // Limit context window
    if (data.options?.num_ctx && data.options.num_ctx > 4096) {
        data.options.num_ctx = 4096;
    }
    
    return data;
}

function proxyRequest(req, res, body, targetUrl, attempt = 0) {
    const parsed = new URL(targetUrl);
    
    const options = {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: req.method,
        headers: {
            ...req.headers,
            host: parsed.host
        }
    };
    
    // Use http or https module based on target
    const client = parsed.protocol === 'https:' ? https : http;
    
    const proxyReq2 = client.request(options, (proxyRes) => {
        // Handle 410 Gone / 404 / 500 errors from cloud endpoints
        if (proxyRes.statusCode >= 400 && proxyRes.statusCode !== 401) {
            console.log(`[Throttle] Target returned ${proxyRes.statusCode} for ${req.url}`);
            
            // Collect error body
            let errorBody = '';
            proxyRes.on('data', chunk => errorBody += chunk);
            proxyRes.on('end', () => {
                // Try fallback to local RawrXD for chat completions
                if (attempt < MAX_RETRIES && req.url?.includes('/chat/completions')) {
                    console.log(`[Throttle] Falling back to RawrXD (attempt ${attempt + 1})`);
                    proxyRequest(req, res, body, `http://127.0.0.1:${TARGET_PORT}${req.url}`, attempt + 1);
                    return;
                }
                
                if (!res.headersSent) {
                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                    res.end(errorBody || JSON.stringify({ error: 'Upstream error', status: proxyRes.statusCode }));
                }
            });
            return;
        }
        
        // Stream the response back
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    
    proxyReq2.on('error', (err) => {
        console.error('[Throttle] Proxy error:', err.message);
        
        // Fallback to RawrXD on connection error
        if (attempt < MAX_RETRIES && targetUrl !== `http://127.0.0.1:${TARGET_PORT}${req.url}`) {
            console.log(`[Throttle] Connection failed, falling back to RawrXD`);
            proxyRequest(req, res, body, `http://127.0.0.1:${TARGET_PORT}${req.url}`, attempt + 1);
            return;
        }
        
        if (!res.headersSent) {
            res.writeHead(502);
            res.end(JSON.stringify({ error: 'Proxy error', message: err.message }));
        }
    });
    
    if (body) {
        proxyReq2.write(body);
    }
    
    proxyReq2.end();
}

const server = http.createServer((req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Target-Url');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    // Determine target URL
    let targetUrl = getTargetFromRequest(req);
    const isCloud = isCloudEndpoint(targetUrl);
    
    console.log(`[Throttle] ${req.method} ${req.url} -> ${targetUrl} ${isCloud ? '(cloud)' : '(local)'}`);
    
    // Intercept request body for modification
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        try {
            let proxyBody = body;
            
            // Only modify POST/PUT requests with JSON body
            if (body && body.length > 0) {
                try {
                    const data = JSON.parse(body);
                    const throttled = applyThrottle(data, req.url);
                    proxyBody = JSON.stringify(throttled);
                    req.headers['content-length'] = Buffer.byteLength(proxyBody).toString();
                } catch (e) {
                    // Not JSON, pass through unchanged
                }
            }
            
            proxyRequest(req, res, proxyBody, targetUrl);
            
        } catch (e) {
            console.error('[Throttle] Error:', e.message);
            res.writeHead(500);
            res.end(JSON.stringify({ error: 'Internal error', message: e.message }));
        }
    });
});

server.listen(PROXY_PORT, () => {
    console.log(`[CopilotThrottle] Proxy running on http://127.0.0.1:${PROXY_PORT}`);
    console.log('[CopilotThrottle] Configure Copilot to use this port for local and cloud models');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n[CopilotThrottle] Shutting down...');
    server.close();
    process.exit(0);
});
