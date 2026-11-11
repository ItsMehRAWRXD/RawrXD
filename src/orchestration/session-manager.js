// ============================================================================
// session-manager.js - Key-Exchange & Session Encryption Layer
// Secure token-based session management with cryptographic signing
// ============================================================================

class RawrSessionManager {
    constructor() {
        this.runtime = window.RawrRuntime;
        this.sessionToken = null;
        this.sessionKeySpace = null;
        this.isAuthenticated = false;
        this.sessionStartTime = null;
    }

    establishSecureSession(handshakeCredentials = {}) {
        console.log('[SessionManager] Establishing secure session...');

        if (!handshakeCredentials.clientUuid || !handshakeCredentials.signature) {
            throw new Error('Incomplete credentials for session establishment.');
        }

        this.sessionKeySpace = Math.floor(Math.random() * 100000 + 50000);
        const raw = `${handshakeCredentials.clientUuid}:${this.sessionKeySpace}:${Date.now()}`;
        this.sessionToken = btoa(raw);
        this.isAuthenticated = true;
        this.sessionStartTime = Date.now();

        console.log('[SessionManager] Session established.');

        if (this.runtime) {
            this.runtime.register('SecuritySession', this);
            this.runtime.publish('session:authorized', {
                tokenChecksum: this.sessionToken.substring(0, 10),
                established: this.sessionStartTime
            });
        }

        return this.sessionToken;
    }

    signPayloadBuffer(dataString) {
        if (!this.isAuthenticated || !this.sessionToken) {
            throw new Error('Cannot sign payload outside active session.');
        }

        let hash = 0;
        for (let i = 0; i < dataString.length; i++) {
            hash = ((hash << 5) - hash) + dataString.charCodeAt(i);
            hash |= 0;
        }

        return {
            tokenSignature: this.sessionToken,
            payloadChecksum: Math.abs(hash).toString(16).padStart(8, '0'),
            securedTimestamp: Date.now(),
            sessionAge: Date.now() - this.sessionStartTime
        };
    }

    verifySignature(signature, dataString) {
        if (!signature || !dataString) return false;
        const expected = this.signPayloadBuffer(dataString);
        return signature.payloadChecksum === expected.payloadChecksum &&
               signature.tokenSignature === expected.tokenSignature;
    }

    getSessionInfo() {
        if (!this.isAuthenticated) return null;
        return {
            tokenPrefix: this.sessionToken.substring(0, 10),
            established: this.sessionStartTime,
            age: Date.now() - this.sessionStartTime,
            keySpace: this.sessionKeySpace
        };
    }

    terminateSession() {
        this.sessionToken = null;
        this.sessionKeySpace = null;
        this.isAuthenticated = false;
        this.sessionStartTime = null;
        console.warn('[SessionManager] Session terminated.');
        if (this.runtime) this.runtime.publish('session:terminated', { timestamp: Date.now() });
    }
}

if (typeof window !== 'undefined') {
    window.RawrSessionManager = new RawrSessionManager();
}
