import { EventEmitter } from 'events';

export interface ChatMessage {
    id: string;
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: number;
    tokens?: number;
    latencyMs?: number;
}

export class ChatSession extends EventEmitter {
    private _messages: ChatMessage[] = [];
    private _sessionId: string;
    
    constructor() {
        super();
        this._sessionId = `session-${Date.now()}`;
        this._loadFromStorage();
    }
    
    public addUserMessage(text: string): void {
        const userMessage: ChatMessage = {
            id: `msg-${Date.now()}`,
            role: 'user',
            content: text,
            timestamp: Date.now()
        };
        
        this._messages.push(userMessage);
        this.emit('message', userMessage);
        this._saveToStorage();
    }
    
    public addAssistantMessage(text: string): void {
        const assistantMessage: ChatMessage = {
            id: `msg-${Date.now()}-response`,
            role: 'assistant',
            content: text,
            timestamp: Date.now()
        };
        
        this._messages.push(assistantMessage);
        this.emit('message', assistantMessage);
        this._saveToStorage();
    }
    
    public async sendMessage(text: string): Promise<void> {
        this.addUserMessage(text);
        
        // Legacy mock response - now handled via WebSocket streaming
        const startTime = Date.now();
        await new Promise(resolve => setTimeout(resolve, 500));
        
        this.addAssistantMessage(`I received: "${text}"\n\n(This is a mock response. Full AI integration coming in Q4.)`);
    }
    
    public getMessages(): ChatMessage[] {
        return [...this._messages];
    }
    
    public clear(): void {
        this._messages = [];
        this.emit('clear');
        this._saveToStorage();
    }
    
    private _loadFromStorage(): void {
        // TODO: Implement persistent storage
    }
    
    private _saveToStorage(): void {
        // TODO: Implement persistent storage
    }
}
