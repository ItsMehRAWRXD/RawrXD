// RawrXD Web UI Application

class RawrXDApp {
    constructor() {
        this.serverUrl = localStorage.getItem('serverUrl') || 'http://localhost:8080';
        this.apiKey = localStorage.getItem('apiKey') || '';
        this.currentView = 'chat';
        this.models = [];
        this.chatHistory = [];
        this.isGenerating = false;
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadModels();
        this.setupNavigation();
        this.checkServerStatus();
        
        // Check server status periodically
        setInterval(() => this.checkServerStatus(), 30000);
    }
    
    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.switchView(view);
            });
        });
        
        // Chat
        const chatInput = document.getElementById('chat-input');
        const sendButton = document.getElementById('send-button');
        
        chatInput.addEventListener('input', () => {
            this.autoResizeTextarea(chatInput);
            sendButton.disabled = chatInput.value.trim() === '';
        });
        
        chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (!sendButton.disabled) {
                    this.sendMessage();
                }
            }
        });
        
        sendButton.addEventListener('click', () => this.sendMessage());
        
        // Suggested prompts
        document.querySelectorAll('.prompt-chip').forEach(chip => {
            chip.addEventListener('click', (e) => {
                const prompt = e.currentTarget.dataset.prompt;
                chatInput.value = prompt;
                this.autoResizeTextarea(chatInput);
                sendButton.disabled = false;
            });
        });
        
        // Pull model modal
        const pullModelBtn = document.getElementById('pull-model-btn');
        const pullModelModal = document.getElementById('pull-model-modal');
        const modalClose = document.querySelector('.modal-close');
        const modalCancel = document.querySelector('.modal-cancel');
        const confirmPullBtn = document.getElementById('confirm-pull-model');
        
        pullModelBtn.addEventListener('click', () => {
            pullModelModal.classList.add('active');
        });
        
        [modalClose, modalCancel].forEach(btn => {
            btn.addEventListener('click', () => {
                pullModelModal.classList.remove('active');
            });
        });
        
        confirmPullBtn.addEventListener('click', () => this.pullModel());
        
        // Playground
        const runPlaygroundBtn = document.getElementById('run-playground');
        const clearOutputBtn = document.getElementById('clear-output');
        
        runPlaygroundBtn.addEventListener('click', () => this.runPlayground());
        clearOutputBtn.addEventListener('click', () => this.clearPlaygroundOutput());
        
        // Parameter sliders
        document.querySelectorAll('.param-row input[type="range"]').forEach(slider => {
            slider.addEventListener('input', (e) => {
                const valueSpan = e.target.parentElement.querySelector('.param-value');
                valueSpan.textContent = e.target.value;
            });
        });
        
        // Settings
        const saveServerSettingsBtn = document.getElementById('save-server-settings');
        saveServerSettingsBtn.addEventListener('click', () => this.saveSettings());
        
        // Close modal on outside click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });
    }
    
    setupNavigation() {
        // Set initial active state
        const savedView = localStorage.getItem('currentView') || 'chat';
        this.switchView(savedView);
    }
    
    switchView(viewName) {
        // Update nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.view === viewName) {
                item.classList.add('active');
            }
        });
        
        // Update views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.remove('active');
        });
        document.getElementById(`${viewName}-view`).classList.add('active');
        
        this.currentView = viewName;
        localStorage.setItem('currentView', viewName);
        
        // View-specific initialization
        if (viewName === 'models') {
            this.loadModels();
        } else if (viewName === 'monitoring') {
            this.loadMetrics();
        }
    }
    
    async checkServerStatus() {
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.querySelector('.status-text');
        
        try {
            const response = await fetch(`${this.serverUrl}/health`, {
                method: 'GET',
                headers: this.getHeaders()
            });
            
            if (response.ok) {
                statusIndicator.classList.add('online');
                statusText.textContent = 'Connected';
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            statusIndicator.classList.remove('online');
            statusText.textContent = 'Disconnected';
        }
    }
    
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };
        if (this.apiKey) {
            headers['Authorization'] = `Bearer ${this.apiKey}`;
        }
        return headers;
    }
    
    async loadModels() {
        try {
            const response = await fetch(`${this.serverUrl}/v1/models`, {
                headers: this.getHeaders()
            });
            
            if (response.ok) {
                const data = await response.json();
                this.models = data.data || [];
                this.updateModelSelectors();
                this.renderModelsGrid();
            }
        } catch (error) {
            console.error('Failed to load models:', error);
            // Use mock data for demo
            this.models = [
                { id: 'llama-2-7b-chat', object: 'model' },
                { id: 'mistral-7b-instruct', object: 'model' }
            ];
            this.updateModelSelectors();
            this.renderModelsGrid();
        }
    }
    
    updateModelSelectors() {
        const selectors = ['chat-model-select', 'playground-model'];
        
        selectors.forEach(selectorId => {
            const select = document.getElementById(selectorId);
            if (!select) return;
            
            const currentValue = select.value;
            select.innerHTML = '<option value="">Select model...</option>';
            
            this.models.forEach(model => {
                const option = document.createElement('option');
                option.value = model.id;
                option.textContent = model.id;
                select.appendChild(option);
            });
            
            if (currentValue) {
                select.value = currentValue;
            }
        });
    }
    
    renderModelsGrid() {
        const grid = document.getElementById('models-grid');
        if (!grid) return;
        
        // Mock model data for demo
        const mockModels = [
            {
                name: 'Llama 2 7B Chat',
                id: 'llama-2-7b-chat',
                description: 'Meta\'s Llama 2 7B model, optimized for conversation',
                size: '3.8 GB',
                parameters: '7B',
                quantization: 'Q4_K_M',
                status: 'downloaded'
            },
            {
                name: 'Mistral 7B Instruct',
                id: 'mistral-7b-instruct',
                description: 'Mistral AI\'s 7B model with superior performance',
                size: '4.1 GB',
                parameters: '7B',
                quantization: 'Q4_K_M',
                status: 'available'
            },
            {
                name: 'CodeLlama 7B',
                id: 'codellama-7b',
                description: 'Meta\'s CodeLlama 7B for code generation',
                size: '3.8 GB',
                parameters: '7B',
                quantization: 'Q4_K_M',
                status: 'available'
            }
        ];
        
        grid.innerHTML = mockModels.map(model => `
            <div class="model-card">
                <div class="model-card-header">
                    <div class="model-name">${model.name}</div>
                    ${model.status === 'downloaded' ? '<span class="model-badge">Downloaded</span>' : ''}
                </div>
                <div class="model-description">${model.description}</div>
                <div class="model-meta">
                    <div class="model-meta-item">
                        <span>📦</span> ${model.size}
                    </div>
                    <div class="model-meta-item">
                        <span>🧠</span> ${model.parameters}
                    </div>
                    <div class="model-meta-item">
                        <span>⚡</span> ${model.quantization}
                    </div>
                </div>
                <div class="model-actions">
                    ${model.status === 'downloaded' 
                        ? `<button class="btn btn-primary btn-sm" onclick="app.loadModel('${model.id}')">Load</button>
                           <button class="btn btn-secondary btn-sm" onclick="app.deleteModel('${model.id}')">Delete</button>`
                        : `<button class="btn btn-primary btn-sm" onclick="app.pullModelById('${model.id}')">Download</button>`
                    }
                </div>
            </div>
        `).join('');
    }
    
    async sendMessage() {
        const input = document.getElementById('chat-input');
        const sendButton = document.getElementById('send-button');
        const modelSelect = document.getElementById('chat-model-select');
        
        const message = input.value.trim();
        if (!message || this.isGenerating) return;
        
        const model = modelSelect.value;
        if (!model) {
            alert('Please select a model first');
            return;
        }
        
        // Clear welcome message if present
        const welcomeMessage = document.querySelector('.welcome-message');
        if (welcomeMessage) {
            welcomeMessage.remove();
        }
        
        // Add user message
        this.addMessage('user', message);
        input.value = '';
        this.autoResizeTextarea(input);
        sendButton.disabled = true;
        
        // Add assistant message placeholder
        const assistantMessageId = this.addMessage('assistant', '', true);
        this.isGenerating = true;
        
        try {
            const response = await fetch(`${this.serverUrl}/v1/chat/completions`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({
                    model: model,
                    messages: [
                        { role: 'user', content: message }
                    ],
                    stream: true,
                    max_tokens: 1024
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let fullResponse = '';
            
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                const chunk = decoder.decode(value);
                const lines = chunk.split('\n');
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6);
                        if (data === '[DONE]') continue;
                        
                        try {
                            const parsed = JSON.parse(data);
                            const content = parsed.choices?.[0]?.delta?.content || '';
                            fullResponse += content;
                            this.updateMessage(assistantMessageId, fullResponse);
                        } catch (e) {
                            // Ignore parse errors
                        }
                    }
                }
            }
            
        } catch (error) {
            console.error('Error:', error);
            this.updateMessage(assistantMessageId, `Error: ${error.message}. Make sure the server is running.`);
        } finally {
            this.isGenerating = false;
            sendButton.disabled = false;
        }
    }
    
    addMessage(role, content, isStreaming = false) {
        const messagesContainer = document.getElementById('chat-messages');
        const messageId = 'msg-' + Date.now();
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${role}`;
        messageDiv.id = messageId;
        
        const avatar = role === 'user' ? '👤' : '🤖';
        const author = role === 'user' ? 'You' : 'Assistant';
        
        messageDiv.innerHTML = `
            <div class="message-avatar">${avatar}</div>
            <div class="message-content">
                <div class="message-header">
                    <span class="message-author">${author}</span>
                    <span class="message-time">${new Date().toLocaleTimeString()}</span>
                </div>
                <div class="message-text">${isStreaming ? '<div class="spinner"></div>' : this.formatMessage(content)}</div>
            </div>
        `;
        
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        
        return messageId;
    }
    
    updateMessage(messageId, content) {
        const messageDiv = document.getElementById(messageId);
        if (messageDiv) {
            const textDiv = messageDiv.querySelector('.message-text');
            textDiv.innerHTML = this.formatMessage(content);
            
            // Highlight code blocks
            messageDiv.querySelectorAll('pre code').forEach(block => {
                hljs.highlightElement(block);
            });
        }
    }
    
    formatMessage(content) {
        // Convert markdown to HTML
        let html = marked.parse(content);
        
        // Add copy buttons to code blocks
        html = html.replace(/<pre><code/g, '<pre><button class="copy-button">Copy</button><code');
        
        return html;
    }
    
    autoResizeTextarea(textarea) {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 200) + 'px';
    }
    
    async runPlayground() {
        const modelSelect = document.getElementById('playground-model');
        const promptInput = document.getElementById('playground-prompt');
        const outputDiv = document.getElementById('playground-output');
        const statsDiv = document.getElementById('output-stats');
        
        const model = modelSelect.value;
        const prompt = promptInput.value.trim();
        
        if (!model || !prompt) {
            alert('Please select a model and enter a prompt');
            return;
        }
        
        const temperature = document.getElementById('temperature').value;
        const maxTokens = document.getElementById('max-tokens').value;
        const topP = document.getElementById('top-p').value;
        
        outputDiv.innerHTML = '<div class="spinner"></div>';
        statsDiv.innerHTML = '';
        
        const startTime = Date.now();
        
        try {
            const response = await fetch(`${this.serverUrl}/v1/completions`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({
                    model: model,
                    prompt: prompt,
                    temperature: parseFloat(temperature),
                    max_tokens: parseInt(maxTokens),
                    top_p: parseFloat(topP)
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            const duration = Date.now() - startTime;
            
            outputDiv.innerHTML = this.formatMessage(data.choices[0].text);
            
            statsDiv.innerHTML = `
                <span>⏱️ ${duration}ms</span>
                <span>📝 ${data.usage.completion_tokens} tokens</span>
                <span>📊 ${data.usage.total_tokens} total</span>
            `;
            
        } catch (error) {
            outputDiv.innerHTML = `<div style="color: var(--error)">Error: ${error.message}</div>`;
        }
    }
    
    clearPlaygroundOutput() {
        document.getElementById('playground-output').innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">📝</span>
                <p>Run a prompt to see the output</p>
            </div>
        `;
        document.getElementById('output-stats').innerHTML = '';
    }
    
    async pullModel() {
        const nameInput = document.getElementById('pull-model-name');
        const quantizationSelect = document.getElementById('pull-model-quantization');
        
        const modelName = nameInput.value.trim();
        const quantization = quantizationSelect.value;
        
        if (!modelName) {
            alert('Please enter a model name');
            return;
        }
        
        // Close modal
        document.getElementById('pull-model-modal').classList.remove('active');
        
        // Show notification
        this.showNotification(`Downloading ${modelName}...`, 'info');
        
        // In a real implementation, this would call the model manager API
        setTimeout(() => {
            this.showNotification(`Model ${modelName} downloaded successfully!`, 'success');
            this.loadModels();
        }, 2000);
    }
    
    pullModelById(modelId) {
        document.getElementById('pull-model-name').value = modelId;
        document.getElementById('pull-model-modal').classList.add('active');
    }
    
    loadModel(modelId) {
        this.showNotification(`Loading model: ${modelId}`, 'info');
        // In a real implementation, this would load the model into the server
    }
    
    deleteModel(modelId) {
        if (confirm(`Are you sure you want to delete ${modelId}?`)) {
            this.showNotification(`Deleted model: ${modelId}`, 'success');
            this.loadModels();
        }
    }
    
    loadMetrics() {
        // Mock metrics for demo
        document.getElementById('metric-rpm').textContent = '1,234';
        document.getElementById('metric-latency').textContent = '45ms';
        document.getElementById('metric-tps').textContent = '2,456';
        document.getElementById('metric-gpu').textContent = '78%';
    }
    
    saveSettings() {
        const serverUrl = document.getElementById('server-url').value;
        const apiKey = document.getElementById('api-key').value;
        
        this.serverUrl = serverUrl;
        this.apiKey = apiKey;
        
        localStorage.setItem('serverUrl', serverUrl);
        localStorage.setItem('apiKey', apiKey);
        
        this.showNotification('Settings saved successfully!', 'success');
        this.checkServerStatus();
    }
    
    showNotification(message, type = 'info') {
        // Simple notification implementation
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 24px;
            background: ${type === 'success' ? 'var(--success)' : 'var(--accent-primary)'};
            color: white;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            z-index: 9999;
            animation: slideIn 0.3s ease;
        `;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }
}

// Initialize app
const app = new RawrXDApp();

// Add slide-in animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);
