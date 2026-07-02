import * as WebSocket from 'ws';
import { EventEmitter } from 'events';

export interface ChatRequest {
    sessionId: string;
    messages: Array<{role: string; content: string}>;
    model: string;
    temperature: number;
    maxTokens: number;
}

export class WebSocketServer extends EventEmitter {
    private wss: WebSocket.Server | null = null;
    private port: number;
    
    constructor(port: number = 8081) {
        super();
        this.port = port;
    }
    
    public start(): void {
        this.wss = new WebSocket.Server({ port: this.port });
        
        this.wss.on('connection', (ws) => {
            console.log('RawrXD: Client connected to chat server');
            
            ws.on('message', (data) => {
                try {
                    const request: ChatRequest = JSON.parse(data.toString());
                    this.handleChatRequest(ws, request);
                } catch (e) {
                    ws.send(JSON.stringify({ error: 'Invalid request format' }));
                }
            });
            
            ws.on('close', () => {
                console.log('RawrXD: Client disconnected');
            });
        });
        
        console.log(`RawrXD: WebSocket server running on ws://localhost:${this.port}`);
    }
    
    private async handleChatRequest(ws: WebSocket, request: ChatRequest): Promise<void> {
        // Stream tokens back to client
        const tokens = this.generateMockResponse(request.messages);
        
        for (const token of tokens) {
            ws.send(JSON.stringify({ type: 'token', content: token }));
            await new Promise(resolve => setTimeout(resolve, 50)); // Simulate generation delay
        }
        
        ws.send(JSON.stringify({ 
            type: 'done', 
            usage: { promptTokens: 100, completionTokens: tokens.length, totalTokens: 100 + tokens.length }
        }));
    }
    
    private generateMockResponse(messages: Array<{role: string; content: string}>): string[] {
        const lastMessage = messages[messages.length - 1]?.content || '';
        
        // Simple mock response - in production this calls the MASM inference engine
        const response = `I understand you're asking about: "${lastMessage.substring(0, 50)}..."

Here's my analysis:

1. **Context**: Based on your message, this appears to be a coding question
2. **Approach**: I recommend breaking this down into smaller components
3. **Implementation**: Consider using the following pattern:

\`\`\`python
def solve_problem():
    # Your implementation here
    pass
\`\`\`

Would you like me to elaborate on any specific part?`;
        
        // Split into tokens (words)
        return response.split(/(\s+)/);
    }
    
    public stop(): void {
        this.wss?.close();
    }
}
