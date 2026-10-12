#!/bin/bash

# RawrXD - Simple Local Web UI Server
# Provides a user-friendly interface for local AI interactions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="${SCRIPT_DIR}/local-ui"
PORT="${UI_PORT:-8081}"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RawrXD - Local Web UI                                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "Error: Python not found. Please install Python 3.6+"
    exit 1
fi

PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

# Create UI directory if it doesn't exist
mkdir -p "${UI_DIR}"

# Create simple HTML UI if it doesn't exist
if [ ! -f "${UI_DIR}/index.html" ]; then
    cat > "${UI_DIR}/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD - Local AI</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .chat-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .chat-messages {
            height: 500px;
            overflow-y: auto;
            padding: 20px;
            background: #f8f9fa;
        }
        
        .message {
            margin-bottom: 15px;
            padding: 12px 16px;
            border-radius: 10px;
            max-width: 80%;
            word-wrap: break-word;
        }
        
        .message.user {
            background: #667eea;
            color: white;
            margin-left: auto;
            text-align: right;
        }
        
        .message.assistant {
            background: white;
            border: 1px solid #e1e4e8;
        }
        
        .message.system {
            background: #fff3cd;
            border: 1px solid #ffc107;
            max-width: 100%;
            text-align: center;
            font-size: 0.9em;
        }
        
        .input-container {
            padding: 20px;
            background: white;
            border-top: 1px solid #e1e4e8;
        }
        
        .input-group {
            display: flex;
            gap: 10px;
        }
        
        #promptInput {
            flex: 1;
            padding: 12px 16px;
            border: 2px solid #e1e4e8;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        #promptInput:focus {
            outline: none;
            border-color: #667eea;
        }
        
        #sendButton {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        #sendButton:hover:not(:disabled) {
            background: #5568d3;
        }
        
        #sendButton:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .status-bar {
            padding: 10px 20px;
            background: #f8f9fa;
            border-top: 1px solid #e1e4e8;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.9em;
            color: #666;
        }
        
        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-indicator.online { background: #28a745; }
        .status-indicator.offline { background: #dc3545; }
        
        .controls {
            margin-bottom: 20px;
            background: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .controls label {
            display: inline-block;
            margin-right: 15px;
            color: #333;
        }
        
        .controls input, .controls select {
            padding: 5px 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-left: 5px;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦖 RawrXD Local AI</h1>
            <p>100% Private • Completely Offline • Zero Limits</p>
        </div>
        
        <div class="controls">
            <label>
                Max Tokens:
                <input type="number" id="maxTokens" value="512" min="1" max="4096">
            </label>
            <label>
                Temperature:
                <input type="number" id="temperature" value="0.7" min="0" max="2" step="0.1">
            </label>
            <label>
                <input type="checkbox" id="streamMode" checked> Stream
            </label>
            <button onclick="clearChat()" style="float: right; padding: 5px 15px; border: none; background: #dc3545; color: white; border-radius: 4px; cursor: pointer;">
                Clear Chat
            </button>
        </div>
        
        <div class="chat-container">
            <div class="chat-messages" id="chatMessages"></div>
            <div class="input-container">
                <div class="input-group">
                    <input 
                        type="text" 
                        id="promptInput" 
                        placeholder="Type your message here..."
                        onkeypress="handleKeyPress(event)"
                    >
                    <button id="sendButton" onclick="sendMessage()">Send</button>
                </div>
            </div>
            <div class="status-bar">
                <div>
                    <span class="status-indicator" id="statusIndicator"></span>
                    <span id="statusText">Checking connection...</span>
                </div>
                <div id="modelInfo">Model: Loading...</div>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = 'http://localhost:8080';
        let isProcessing = false;
        
        // Check server status
        async function checkStatus() {
            try {
                const response = await fetch(`${API_BASE}/health`);
                if (response.ok) {
                    document.getElementById('statusIndicator').className = 'status-indicator online';
                    document.getElementById('statusText').textContent = 'Server Online';
                    
                    // Try to get model info
                    try {
                        const modelsResp = await fetch(`${API_BASE}/v1/models`);
                        if (modelsResp.ok) {
                            const modelsData = await modelsResp.json();
                            if (modelsData.data && modelsData.data.length > 0) {
                                document.getElementById('modelInfo').textContent = 
                                    `Model: ${modelsData.data[0].id || 'Unknown'}`;
                            }
                        }
                    } catch (e) {
                        console.log('Could not fetch model info');
                    }
                } else {
                    throw new Error('Server not responding');
                }
            } catch (error) {
                document.getElementById('statusIndicator').className = 'status-indicator offline';
                document.getElementById('statusText').textContent = 'Server Offline';
                document.getElementById('modelInfo').textContent = 'Start with: rawrxd-serve';
            }
        }
        
        // Add message to chat
        function addMessage(content, type) {
            const messagesDiv = document.getElementById('chatMessages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${type}`;
            messageDiv.textContent = content;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        // Clear chat
        function clearChat() {
            document.getElementById('chatMessages').innerHTML = '';
            addMessage('Chat cleared. Ready for new conversation!', 'system');
        }
        
        // Handle key press
        function handleKeyPress(event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                sendMessage();
            }
        }
        
        // Send message
        async function sendMessage() {
            if (isProcessing) return;
            
            const input = document.getElementById('promptInput');
            const prompt = input.value.trim();
            
            if (!prompt) return;
            
            // Add user message
            addMessage(prompt, 'user');
            input.value = '';
            
            // Disable input
            isProcessing = true;
            document.getElementById('sendButton').disabled = true;
            document.getElementById('promptInput').disabled = true;
            
            // Show loading
            const loadingMsg = document.createElement('div');
            loadingMsg.className = 'message assistant';
            loadingMsg.innerHTML = '<div class="loading"></div>';
            document.getElementById('chatMessages').appendChild(loadingMsg);
            
            try {
                const maxTokens = parseInt(document.getElementById('maxTokens').value);
                const temperature = parseFloat(document.getElementById('temperature').value);
                
                const response = await fetch(`${API_BASE}/v1/completions`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        prompt: prompt,
                        max_tokens: maxTokens,
                        temperature: temperature,
                        stream: false
                    })
                });
                
                if (!response.ok) {
                    throw new Error(`Server error: ${response.status}`);
                }
                
                const data = await response.json();
                
                // Remove loading message
                loadingMsg.remove();
                
                // Add assistant response
                const assistantText = data.choices?.[0]?.text || 'No response';
                addMessage(assistantText, 'assistant');
                
            } catch (error) {
                loadingMsg.remove();
                addMessage(`Error: ${error.message}. Make sure server is running!`, 'system');
            } finally {
                isProcessing = false;
                document.getElementById('sendButton').disabled = false;
                document.getElementById('promptInput').disabled = false;
                document.getElementById('promptInput').focus();
            }
        }
        
        // Initialize
        checkStatus();
        setInterval(checkStatus, 5000);
        addMessage('Welcome to RawrXD Local AI! Your messages are 100% private and never leave your machine.', 'system');
        document.getElementById('promptInput').focus();
    </script>
</body>
</html>
HTMLEOF
fi

# Start simple HTTP server
echo -e "${GREEN}[✓]${NC} Starting local web UI..."
echo ""
echo "  Web UI: http://localhost:${PORT}"
echo "  API Server: http://localhost:8080 (must be running separately)"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

cd "${UI_DIR}"
$PYTHON_CMD -m http.server ${PORT} 2>/dev/null || python -m SimpleHTTPServer ${PORT}
