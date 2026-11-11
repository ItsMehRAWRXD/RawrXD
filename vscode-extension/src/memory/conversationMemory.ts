import { EventEmitter } from 'events';

export interface ConversationMessage {
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: number;
}

export interface ConversationSession {
    id: string;
    messages: ConversationMessage[];
    context?: string; // File path or context identifier
}

/**
 * Conversation memory for inline chat
 * Enables follow-up prompts with context
 */
export class ConversationMemory extends EventEmitter {
    private sessions: Map<string, ConversationSession> = new Map();
    private activeSessionId: string | undefined;
    private maxMessages = 20; // Keep last 20 messages

    /**
     * Start a new conversation session
     */
    startSession(context?: string): string {
        const sessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        this.sessions.set(sessionId, {
            id: sessionId,
            messages: [],
            context
        });
        this.activeSessionId = sessionId;
        return sessionId;
    }

    /**
     * Get or create active session
     */
    getActiveSession(): ConversationSession | undefined {
        if (!this.activeSessionId) {
            return undefined;
        }
        return this.sessions.get(this.activeSessionId);
    }

    /**
     * Add user message to active session
     */
    addUserMessage(content: string): void {
        const session = this.getActiveSession();
        if (!session) return;

        session.messages.push({
            role: 'user',
            content,
            timestamp: Date.now()
        });

        this._trimMessages(session);
        this.emit('message', session);
    }

    /**
     * Add assistant message to active session
     */
    addAssistantMessage(content: string): void {
        const session = this.getActiveSession();
        if (!session) return;

        session.messages.push({
            role: 'assistant',
            content,
            timestamp: Date.now()
        });

        this._trimMessages(session);
        this.emit('message', session);
    }

    /**
     * Build conversation context for prompts
     * Returns formatted conversation history
     */
    buildContext(): string {
        const session = this.getActiveSession();
        if (!session || session.messages.length === 0) {
            return '';
        }

        const parts: string[] = [];
        parts.push('Previous conversation:');
        
        for (const msg of session.messages) {
            const role = msg.role === 'user' ? 'User' : 'Assistant';
            parts.push(`${role}: ${msg.content}`);
        }
        
        parts.push('\nCurrent request:');
        return parts.join('\n');
    }

    /**
     * Clear active session
     */
    clearSession(): void {
        if (this.activeSessionId) {
            this.sessions.delete(this.activeSessionId);
            this.activeSessionId = undefined;
        }
    }

    /**
     * Check if we have an active conversation
     */
    hasActiveConversation(): boolean {
        const session = this.getActiveSession();
        return session !== undefined && session.messages.length > 0;
    }

    /**
     * Get conversation duration in ms
     */
    getConversationDuration(): number {
        const session = this.getActiveSession();
        if (!session || session.messages.length === 0) return 0;
        
        const first = session.messages[0].timestamp;
        const last = session.messages[session.messages.length - 1].timestamp;
        return last - first;
    }

    private _trimMessages(session: ConversationSession): void {
        if (session.messages.length > this.maxMessages) {
            session.messages = session.messages.slice(-this.maxMessages);
        }
    }

    dispose(): void {
        this.sessions.clear();
        this.activeSessionId = undefined;
        this.removeAllListeners();
    }
}
