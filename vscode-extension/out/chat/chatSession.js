"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ChatSession = void 0;
const events_1 = require("events");
class ChatSession extends events_1.EventEmitter {
    _messages = [];
    _sessionId;
    constructor() {
        super();
        this._sessionId = `session-${Date.now()}`;
        this._loadFromStorage();
    }
    addUserMessage(text) {
        const userMessage = {
            id: `msg-${Date.now()}`,
            role: 'user',
            content: text,
            timestamp: Date.now()
        };
        this._messages.push(userMessage);
        this.emit('message', userMessage);
        this._saveToStorage();
    }
    addAssistantMessage(text) {
        const assistantMessage = {
            id: `msg-${Date.now()}-response`,
            role: 'assistant',
            content: text,
            timestamp: Date.now()
        };
        this._messages.push(assistantMessage);
        this.emit('message', assistantMessage);
        this._saveToStorage();
    }
    async sendMessage(text) {
        this.addUserMessage(text);
        // Legacy mock response - now handled via WebSocket streaming
        const startTime = Date.now();
        await new Promise(resolve => setTimeout(resolve, 500));
        this.addAssistantMessage(`I received: "${text}"\n\n(This is a mock response. Full AI integration coming in Q4.)`);
    }
    getMessages() {
        return [...this._messages];
    }
    clear() {
        this._messages = [];
        this.emit('clear');
        this._saveToStorage();
    }
    _loadFromStorage() {
        // TODO: Implement persistent storage
    }
    _saveToStorage() {
        // TODO: Implement persistent storage
    }
}
exports.ChatSession = ChatSession;
//# sourceMappingURL=chatSession.js.map