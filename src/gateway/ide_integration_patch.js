// ============================================================================
// RawrXD IDE Integration Patch
// Overrides hardcoded backend URLs to use RawrXD Gateway
// Install: Add this script to the beginning of ide_chatbot.html <body>
// ============================================================================

(function() {
    'use strict';
    
    console.log('[RawrXD Patch] Initializing IDE integration...');
    
    // Configuration
    const RAWRXD_CONFIG = {
        primary: {
            name: 'RawrXD Gateway',
            url: 'http://127.0.0.1:8080',
            priority: 100,
            type: 'native'
        },
        deep2: {
            name: 'Deep2 Native',
            url: 'http://127.0.0.1:11436',
            priority: 90,
            type: 'native'
        },
        legacy: {
            name: 'Win32IDE',
            url: 'http://127.0.0.1:11435',
            priority: 50,
            type: 'legacy'
        },
        fallback: {
            name: 'Ollama',
            url: 'http://127.0.0.1:11434',
            priority: 10,
            type: 'fallback'
        }
    };
    
    // State
    let activeBackend = null;
    let backendCapabilities = null;
    
    // ============================================================================
    // Backend Discovery
    // ============================================================================
    
    async function probeBackend(config) {
        try {
            console.log(`[RawrXD Patch] Probing ${config.name} at ${config.url}...`);
            
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3000);
            
            const response = await fetch(`${config.url}/health`, {
                signal: controller.signal,
                headers: { 'Accept': 'application/json' }
            });
            
            clearTimeout(timeout);
            
            if (response.ok) {
                const data = await response.json();
                console.log(`[RawrXD Patch] ✅ ${config.name} is online:`, data);
                return { ...config, ...data, available: true };
            }
        } catch (e) {
            console.log(`[RawrXD Patch] ❌ ${config.name} unavailable:`, e.message);
        }
        return null;
    }
    
    async function discoverBackends() {
        console.log('[RawrXD Patch] Starting backend discovery...');
        
        const backends = [
            RAWRXD_CONFIG.primary,
            RAWRXD_CONFIG.deep2,
            RAWRXD_CONFIG.legacy
        ];
        
        for (const config of backends) {
            const backend = await probeBackend(config);
            if (backend) {
                activeBackend = backend;
                console.log(`[RawrXD Patch] Selected backend: ${backend.name}`);
                return backend;
            }
        }
        
        // Fallback to Ollama if nothing else works
        console.log('[RawrXD Patch] No native backends found, using Ollama fallback');
        activeBackend = RAWRXD_CONFIG.fallback;
        return activeBackend;
    }
    
    // ============================================================================
    // API Wrappers
    // ============================================================================
    
    async function rawrxdFetch(endpoint, options = {}) {
        if (!activeBackend) {
            await discoverBackends();
        }
        
        const url = `${activeBackend.url}${endpoint}`;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        };
        
        return fetch(url, { ...defaultOptions, ...options });
    }
    
    // ============================================================================
    // Override Native Fetch
    // ============================================================================
    
    const originalFetch = window.fetch;
    
    window.fetch = async function(url, options = {}) {
        // Convert URL to string if it's a Request object
        const urlString = url.toString();
        
        // Intercept backend API calls
        if (urlString.includes('localhost:11435') || 
            urlString.includes('localhost:11434') ||
            urlString.includes('127.0.0.1:11435') ||
            urlString.includes('127.0.0.1:11434')) {
            
            // Rewrite to use RawrXD Gateway
            const endpoint = urlString.replace(/.*:\/\/[^\/]+/, '');
            console.log(`[RawrXD Patch] Intercepted: ${urlString} -> ${activeBackend?.url || RAWRXD_CONFIG.primary.url}${endpoint}`);
            
            return rawrxdFetch(endpoint, options);
        }
        
        // Pass through all other requests
        return originalFetch.apply(this, arguments);
    };
    
    // ============================================================================
    // ModelBridge Integration
    // ============================================================================
    
    window.RawrXDModelBridge = {
        async getCapabilities() {
            const response = await rawrxdFetch('/api/capabilities');
            if (!response.ok) throw new Error('Failed to get capabilities');
            return response.json();
        },
        
        async getModels() {
            const response = await rawrxdFetch('/api/models');
            if (!response.ok) throw new Error('Failed to get models');
            return response.json();
        },
        
        async loadModel(modelPath) {
            const response = await rawrxdFetch('/api/models/load', {
                method: 'POST',
                body: JSON.stringify({ model: modelPath })
            });
            if (!response.ok) throw new Error('Failed to load model');
            return response.json();
        },
        
        async unloadModel() {
            const response = await rawrxdFetch('/api/models/unload', {
                method: 'POST'
            });
            if (!response.ok) throw new Error('Failed to unload model');
            return response.json();
        },
        
        async chat(messages, options = {}) {
            const response = await rawrxdFetch('/api/chat', {
                method: 'POST',
                body: JSON.stringify({ messages, ...options })
            });
            if (!response.ok) throw new Error('Chat failed');
            return response.json();
        },
        
        async generate(prompt, options = {}) {
            const response = await rawrxdFetch('/api/generate', {
                method: 'POST',
                body: JSON.stringify({ prompt, ...options })
            });
            if (!response.ok) throw new Error('Generation failed');
            return response.json();
        }
    };
    
    // ============================================================================
    // Phase Status Integration
    // ============================================================================
    
    window.RawrXDPhaseManager = {
        async getPhases() {
            const response = await rawrxdFetch('/api/phases');
            if (!response.ok) throw new Error('Failed to get phases');
            return response.json();
        },
        
        async getPhaseStatus() {
            const response = await rawrxdFetch('/api/phases/status');
            if (!response.ok) throw new Error('Failed to get phase status');
            return response.json();
        },
        
        async getPhaseDetail(phaseId) {
            const response = await rawrxdFetch(`/api/phases/${phaseId}`);
            if (!response.ok) throw new Error(`Failed to get phase ${phaseId}`);
            return response.json();
        }
    };
    
    // ============================================================================
    // UI Integration
    // ============================================================================
    
    function updateBackendStatusUI() {
        // Find or create status element
        let statusEl = document.getElementById('rawrxd-backend-status');
        if (!statusEl) {
            statusEl = document.createElement('div');
            statusEl.id = 'rawrxd-backend-status';
            statusEl.style.cssText = `
                position: fixed;
                top: 10px;
                right: 10px;
                padding: 8px 16px;
                background: #1a1a2e;
                border: 1px solid #00ff88;
                border-radius: 4px;
                color: #00ff88;
                font-family: monospace;
                font-size: 12px;
                z-index: 10000;
            `;
            document.body.appendChild(statusEl);
        }
        
        if (activeBackend) {
            statusEl.textContent = `🟢 ${activeBackend.name} (${activeBackend.url})`;
            statusEl.style.borderColor = '#00ff88';
            statusEl.style.color = '#00ff88';
        } else {
            statusEl.textContent = `🔴 No backend`;
            statusEl.style.borderColor = '#ff4466';
            statusEl.style.color = '#ff4466';
        }
    }
    
    // ============================================================================
    // Initialization
    // ============================================================================
    
    async function initialize() {
        console.log('[RawrXD Patch] Starting initialization...');
        
        // Discover backends
        await discoverBackends();
        
        // Update UI
        updateBackendStatusUI();
        
        // Override hardcoded backend URL
        if (window.BACKEND_URL) {
            console.log(`[RawrXD Patch] Overriding BACKEND_URL: ${window.BACKEND_URL} -> ${activeBackend.url}`);
            window.BACKEND_URL = activeBackend.url;
        }
        
        // Override any existing backend configuration
        if (window.config && window.config.backend) {
            console.log(`[RawrXD Patch] Overriding config.backend: ${window.config.backend} -> ${activeBackend.url}`);
            window.config.backend = activeBackend.url;
        }
        
        console.log('[RawrXD Patch] Initialization complete');
        console.log('[RawrXD Patch] Active backend:', activeBackend);
    }
    
    // Start initialization
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
    
    // Expose to global scope
    window.RAWRXD_CONFIG = RAWRXD_CONFIG;
    window.RAWRXD_PATCH_VERSION = '1.0.0';
    
    console.log('[RawrXD Patch] Loaded version', window.RAWRXD_PATCH_VERSION);
})();
