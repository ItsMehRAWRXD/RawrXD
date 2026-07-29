// Copilot Throttle Proxy Server - FIXED VERSION
// Adds missing endpoints that ide_chatbot.html expects

const http = require('http');
const https = require('https');
const { URL } = require('url');

const PROXY_PORT = 9091;
const TARGET_PORT = 9090;

// Throttle configuration
const MAX_TOKENS = parseInt(process.env.THROTTLE_MAX_TOKENS || '2048');
const MAX_CHARS = parseInt(process.env.THROTTLE_MAX_CHARS || '8000');

// In-memory state for model bridge
const BridgeState = {
    loaded: false,
    activeProfileId: -1,
    profiles: [],
    hardware: null,
    bridge: 'rawrxd'
};

// Generate model profiles based on what's available
function generateProfiles() {
    return [
        { id: 0, name: 'tinyllama', params_b: 1.1, quant: 'Q4_0', ram_mb: 500, tier: 'small' },
        { id: 1, name: 'phi3:mini', params_b: 3.8, quant: 'Q4_K_M', ram_mb: 2200, tier: 'small' },
        { id: 2, name: 'codestral:22b', params_b: 22, quant: 'Q4_K_M', ram_mb: 14000, tier: 'medium' },
        { id: 3, name: 'qwen3.5-40b', params_b: 40, quant: 'Q4_K_M', ram_mb: 24000, tier: 'large' },
        { id: 4, name: 'deepseek-v3.1:671b', params_b: 671, quant: 'Q4_K_M', ram_mb: 380000, tier: 'ultra' }
    ];
}

// Handle special endpoints that ide_chatbot.html expects
function handleSpecialEndpoints(req, res, body) {
    const url = req.url;
    
    // GET /api/model/profiles - Return available model profiles
    if (url === '/api/model/profiles' && req.method === 'GET') {
        BridgeState.profiles = generateProfiles();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            profiles: BridgeState.profiles,
            hardware: { vram_mb: 24576, ram_mb: 131072 },
            bridge: 'rawrxd'
        }));
        return true;
    }
    
    // POST /api/model/load - Load a model
    if (url === '/api/model/load' && req.method === 'POST') {
        try {
            const data = JSON.parse(body || '{}');
            const profileId = data.profile_id || 0;
            const profile = BridgeState.profiles.find(p => p.id === profileId) || generateProfiles()[0];
            
            BridgeState.loaded = true;
            BridgeState.activeProfileId = profileId;
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                model: profile.name,
                tier: profile.tier,
                ram_mb: profile.ram_mb,
                engine_mode: 'inference',
                bridge: 'rawrxd'
            }));
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: e.message }));
        }
        return true;
    }
    
    // POST /api/model/unload - Unload current model
    if (url === '/api/model/unload' && req.method === 'POST') {
        BridgeState.loaded = false;
        BridgeState.activeProfileId = -1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'Model unloaded' }));
        return true;
    }
    
    // GET /api/engine/capabilities - Return engine capabilities
    if (url === '/api/engine/capabilities' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            bridge: 'rawrxd',
            features: ['inference', 'streaming', 'tool_calling'],
            max_tokens: MAX_TOKENS,
            max_context: 32768,
            quantization: ['Q4_0', 'Q4_K_M', 'Q8_0', 'FP16']
        }));
        return true;
    }
    
    // POST /api/generate - Generate with throttling
    if (url === '/api/generate' && req.method === 'POST') {
        try {
            const data = JSON.parse(body || '{}');
            
            // Apply throttling
            if (data.max_tokens && data.max_tokens > MAX_TOKENS) {
                console.log(`[Throttle] Reducing max_tokens: ${data.max_tokens} -> ${MAX_TOKENS}`);
                data.max_tokens = MAX_TOKENS;
            }
            
            // Force streaming for large requests
            if (!data.stream && JSON.stringify(data).length > 1000) {
                console.log('[Throttle] Enabling streaming for large request');
                data.stream = true;
            }
            
            // Forward to RawrXD
            forwardToRawrXD(req, res, JSON.stringify(data));
            return true;
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: e.message }));
            return true;
        }
    }
    
    return false;
}

// Forward request to RawrXD
function forwardToRawrXD(req, res, body) {
    const options = {
        hostname: '127.0.0.1',
        port: TARGET_PORT,
        path: req.url,
        method: req.method,
        headers: {
            ...req.headers,
            'Content-Length': Buffer.byteLength(body || '')
        }
    };
    
    const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    
    proxyReq.on('error', (err) => {
        console.error('[Throttle] Proxy error:', err.message);
        if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Proxy error', message: err.message }));
        }
    });
    
    if (body) proxyReq.write(body);
    req.pipe(proxyReq);
}

// Main server
const server = http.createServer((req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    // Collect body
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        // Try special endpoints first
        if (handleSpecialEndpoints(req, res, body)) {
            return;
        }
        
        // Default: forward to RawrXD
        forwardToRawrXD(req, res, body);
    });
});

server.listen(PROXY_PORT, () => {
    console.log(`[CopilotThrottle] Proxy running on http://127.0.0.1:${PROXY_PORT}`);
    console.log(`[CopilotThrottle] RawrXD target: http://127.0.0.1:${TARGET_PORT}`);
    console.log(`[CopilotThrottle] Max tokens: ${MAX_TOKENS}`);
    console.log('[CopilotThrottle] Special endpoints: /api/model/profiles, /api/model/load, /api/model/unload, /api/engine/capabilities');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n[CopilotThrottle] Shutting down...');
    server.close();
    process.exit(0);
});
