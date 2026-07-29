// ============================================================================
// IDE Backend Override - Deep2 Production Integration
// Overrides hardcoded Win32IDE/Ollama URLs with Deep2 Native
// ============================================================================

(function() {
    'use strict';
    
    console.log('[Deep2Override] Initializing production backend override...');
    
    // Production backend configuration
    const DEEP2_CONFIG = {
        primary: {
            name: 'Deep2 Native',
            url: 'http://127.0.0.1:11436',
            priority: 100,
            wsPort: 11437
        },
        secondary: {
            name: 'RawrXD',
            url: 'http://127.0.0.1:8080',
            priority: 50
        },
        fallback: {
            name: 'Ollama',
            url: 'http://127.0.0.1:11434',
            priority: 10
        }
    };
    
    // Override localStorage to persist Deep2 as default
    const originalSetItem = localStorage.setItem;
    const originalGetItem = localStorage.getItem;
    
    localStorage.setItem = function(key, value) {
        // Intercept backend URL saves
        if (key === 'backend_url' || key === 'ollama_url') {
            console.log('[Deep2Override] Intercepting backend URL save:', value);
            // Don't save Win32IDE URLs
            if (value.includes('11435')) {
                console.log('[Deep2Override] Blocking Win32IDE URL, using Deep2');
                value = DEEP2_CONFIG.primary.url;
            }
        }
        return originalSetItem.call(localStorage, key, value);
    };
    
    localStorage.getItem = function(key) {
        let value = originalGetItem.call(localStorage, key);
        
        // Override backend URL reads
        if ((key === 'backend_url' || key === 'ollama_url') && (!value || value.includes('11435'))) {
            console.log('[Deep2Override] Returning Deep2 URL instead of:', value);
            return DEEP2_CONFIG.primary.url;
        }
        
        return value;
    };
    
    // Override window.location for backend detection
    Object.defineProperty(window, 'BACKEND_URL', {
        get: function() {
            return DEEP2_CONFIG.primary.url;
        },
        set: function(value) {
            console.log('[Deep2Override] Blocking backend URL change to:', value);
        },
        configurable: true
    });
    
    // Patch fetch to route through Deep2
    const originalFetch = window.fetch;
    window.fetch = async function(url, options) {
        let urlStr = url.toString();
        
        // Redirect Win32IDE/Ollama calls to Deep2
        if (urlStr.includes('11435') || urlStr.includes('11434')) {
            const newUrl = urlStr.replace(/127\.0\.0\.1:1143[45]/, '127.0.0.1:11436');
            console.log('[Deep2Override] Redirecting:', urlStr, '->', newUrl);
            url = newUrl;
        }
        
        return originalFetch.call(window, url, options);
    };
    
    // Patch WebSocket to use Deep2
    const OriginalWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        if (url.includes('11435')) {
            url = url.replace('11435', '11437'); // Deep2 WebSocket port
            console.log('[Deep2Override] WebSocket redirected to Deep2:', url);
        }
        return new OriginalWebSocket(url, protocols);
    };
    
    // Backend discovery with priority
    window.discoverBackends = async function() {
        const backends = [DEEP2_CONFIG.primary, DEEP2_CONFIG.secondary, DEEP2_CONFIG.fallback];
        const results = [];
        
        for (const backend of backends) {
            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 3000);
                
                const response = await fetch(backend.url + '/api/health', {
                    signal: controller.signal
                });
                
                clearTimeout(timeout);
                
                if (response.ok) {
                    const data = await response.json();
                    results.push({
                        ...backend,
                        status: 'online',
                        info: data
                    });
                    console.log('[Deep2Override] Backend online:', backend.name);
                }
            } catch (e) {
                results.push({
                    ...backend,
                    status: 'offline',
                    error: e.message
                });
            }
        }
        
        // Sort by priority
        results.sort((a, b) => b.priority - a.priority);
        
        // Set active backend
        const active = results.find(b => b.status === 'online');
        if (active) {
            window.ACTIVE_BACKEND = active.url;
            console.log('[Deep2Override] Active backend:', active.name);
        }
        
        return results;
    };
    
    // Auto-discover on load
    window.addEventListener('load', async () => {
        console.log('[Deep2Override] Running backend discovery...');
        const backends = await window.discoverBackends();
        
        // Update UI if backend switcher exists
        const switcher = document.getElementById('backend-switcher');
        if (switcher) {
            switcher.innerHTML = backends.map(b => `
                <div class="backend-option ${b.status}" data-url="${b.url}">
                    <strong>${b.name}</strong>
                    <span class="status">${b.status}</span>
                    <span class="priority">P${b.priority}</span>
                </div>
            `).join('');
        }
        
        // Force backend URL in input
        const urlInput = document.getElementById('backend-url');
        if (urlInput && window.ACTIVE_BACKEND) {
            urlInput.value = window.ACTIVE_BACKEND;
        }
    });
    
    // Patch ModelBridge to use Deep2
    if (window.ModelBridge) {
        const originalLoad = window.ModelBridge.prototype.loadModel;
        window.ModelBridge.prototype.loadModel = async function(modelId) {
            console.log('[Deep2Override] ModelBridge loading via Deep2:', modelId);
            
            // Ensure we're using Deep2
            this.backendUrl = window.ACTIVE_BACKEND || DEEP2_CONFIG.primary.url;
            
            try {
                const response = await fetch(`${this.backendUrl}/api/models/load`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ model: modelId })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                
                return await response.json();
            } catch (e) {
                console.error('[Deep2Override] Model load failed:', e);
                throw e;
            }
        };
    }
    
    console.log('[Deep2Override] Production backend override active');
    console.log('[Deep2Override] Primary backend:', DEEP2_CONFIG.primary.url);
    
})();
