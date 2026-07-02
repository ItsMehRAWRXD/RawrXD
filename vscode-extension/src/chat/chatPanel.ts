import * as vscode from 'vscode';
import { ChatSession } from './chatSession';

export class ChatPanel {
    public static currentPanel: ChatPanel | undefined;
    public static readonly viewType = 'rawrxd.chatPanel';
    
    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];
    private _session: ChatSession;
    private _ws: WebSocket | undefined;
    private _currentResponse: string = '';
    
    public static createOrShow(extensionUri: vscode.Uri): ChatPanel {
        const column = vscode.ViewColumn.Beside;
        
        if (ChatPanel.currentPanel) {
            ChatPanel.currentPanel._panel.reveal(column);
            return ChatPanel.currentPanel;
        }
        
        const panel = vscode.window.createWebviewPanel(
            ChatPanel.viewType,
            'RawrXD Chat',
            column,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')]
            }
        );
        
        ChatPanel.currentPanel = new ChatPanel(panel, extensionUri);
        return ChatPanel.currentPanel;
    }
    
    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._session = new ChatSession();
        
        this._connectWebSocket();
        this._update();
        
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        this._panel.webview.onDidReceiveMessage(
            message => this._handleMessage(message),
            null,
            this._disposables
        );
    }
    
    private _connectWebSocket() {
        try {
            this._ws = new WebSocket('ws://localhost:8081');
            
            this._ws.onopen = () => {
                console.log('RawrXD Chat: WebSocket connected');
            };
            
            this._ws.onmessage = (event) => {
                const data = JSON.parse(event.data.toString());
                if (data.type === 'token') {
                    this._currentResponse += data.token;
                    this._panel.webview.postMessage({ 
                        command: 'streamToken', 
                        token: data.token,
                        fullText: this._currentResponse
                    });
                } else if (data.type === 'end') {
                    this._session.addAssistantMessage(this._currentResponse);
                    this._panel.webview.postMessage({ 
                        command: 'receiveMessage', 
                        text: this._currentResponse 
                    });
                    this._currentResponse = '';
                }
            };
            
            this._ws.onerror = (error) => {
                console.error('RawrXD Chat: WebSocket error:', error);
                this._panel.webview.postMessage({ 
                    command: 'error', 
                    text: 'Connection error. Retrying...' 
                });
            };
            
            this._ws.onclose = () => {
                console.log('RawrXD Chat: WebSocket closed, reconnecting...');
                setTimeout(() => this._connectWebSocket(), 3000);
            };
        } catch (error) {
            console.error('RawrXD Chat: Failed to connect WebSocket:', error);
        }
    }
    
    private _handleMessage(message: any) {
        switch (message.command) {
            case 'sendMessage':
                this._session.addUserMessage(message.text);
                this._currentResponse = '';
                if (this._ws?.readyState === WebSocket.OPEN) {
                    this._ws.send(JSON.stringify({
                        type: 'chat',
                        message: message.text,
                        model: 'rawrxd-default'
                    }));
                }
                return;
            case 'clearChat':
                this._session.clear();
                this._update();
                return;
        }
    }
    
    private _update() {
        this._panel.webview.html = this._getHtmlForWebview();
    }
    
    private _getHtmlForWebview(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Chat</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            background: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            margin: 0;
            padding: 20px;
        }
        .chat-container {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            margin-bottom: 20px;
        }
        .message {
            margin: 10px 0;
            padding: 10px;
            border-radius: 8px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .message.user {
            background: var(--vscode-button-background);
            margin-left: 20%;
        }
        .message.assistant {
            background: var(--vscode-input-background);
            margin-right: 20%;
        }
        .message.streaming {
            border-left: 3px solid var(--vscode-progressBar-background);
        }
        .input-container {
            display: flex;
            gap: 10px;
        }
        input {
            flex: 1;
            padding: 10px;
            border: 1px solid var(--vscode-input-border);
            background: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            border-radius: 4px;
        }
        button {
            padding: 10px 20px;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: var(--vscode-button-hoverBackground);
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .typing-indicator {
            color: var(--vscode-descriptionForeground);
            font-style: italic;
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="messages" id="messages"></div>
        <div class="input-container">
            <input type="text" id="messageInput" placeholder="Ask RawrXD..." />
            <button id="sendBtn" onclick="sendMessage()">Send</button>
        </div>
    </div>
    <script>
        const vscode = acquireVsCodeApi();
        let streamingMessageDiv = null;
        
        function sendMessage() {
            const input = document.getElementById('messageInput');
            const btn = document.getElementById('sendBtn');
            const text = input.value.trim();
            if (text) {
                vscode.postMessage({ command: 'sendMessage', text });
                addMessage(text, 'user');
                input.value = '';
                btn.disabled = true;
                input.disabled = true;
                
                // Create streaming message container
                streamingMessageDiv = document.createElement('div');
                streamingMessageDiv.className = 'message assistant streaming';
                streamingMessageDiv.textContent = '';
                document.getElementById('messages').appendChild(streamingMessageDiv);
            }
        }
        
        function addMessage(text, role) {
            const messages = document.getElementById('messages');
            const div = document.createElement('div');
            div.className = 'message ' + role;
            div.textContent = text;
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
            return div;
        }
        
        document.getElementById('messageInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });
        
        window.addEventListener('message', event => {
            const message = event.data;
            const btn = document.getElementById('sendBtn');
            const input = document.getElementById('messageInput');
            
            if (message.command === 'streamToken' && streamingMessageDiv) {
                streamingMessageDiv.textContent = message.fullText;
                const messages = document.getElementById('messages');
                messages.scrollTop = messages.scrollHeight;
            } else if (message.command === 'receiveMessage') {
                if (streamingMessageDiv) {
                    streamingMessageDiv.classList.remove('streaming');
                    streamingMessageDiv = null;
                }
                btn.disabled = false;
                input.disabled = false;
                input.focus();
            } else if (message.command === 'error') {
                addMessage(message.text, 'assistant');
                btn.disabled = false;
                input.disabled = false;
            }
        });
    </script>
</body>
</html>`;
    }
    
    public dispose() {
        ChatPanel.currentPanel = undefined;
        this._ws?.close();
        this._panel.dispose();
        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) x.dispose();
        }
    }
}
