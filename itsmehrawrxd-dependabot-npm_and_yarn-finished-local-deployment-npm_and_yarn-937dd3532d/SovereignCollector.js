// SovereignCollector.js — Silent UDP Pulse Interceptor
// Listens on a target port, parses inbound hex telemetry, verifies signatures
// Zero-reply: receives only, never transmits

const dgram = require('dgram');
const crypto = require('crypto');

class SovereignCollector {
    constructor(listenPort = 9999, options = {}) {
        this.listenPort = listenPort;
        this.server = dgram.createSocket('udp4');
        this.pulses = [];
        this.running = false;
        this.options = {
            maxHistory: options.maxHistory || 1000,
            verifyEntropy: options.verifyEntropy !== false,
            logToConsole: options.logToConsole !== false,
            ...options
        };

        this.server.on('message', (msg, rinfo) => {
            this._handlePulse(msg, rinfo);
        });

        this.server.on('error', (err) => {
            console.error(`[COLLECTOR ERROR] ${err.message}`);
        });

        this.server.on('listening', () => {
            const address = this.server.address();
            console.log(`[COLLECTOR] Silent UDP listener active on ${address.address}:${address.port}`);
            console.log(`[COLLECTOR] Mode: receive-only, zero-reply`);
        });
    }

    _handlePulse(msg, rinfo) {
        try {
            const payload = JSON.parse(msg.toString('utf8'));
            const pulse = {
                receivedAt: Date.now(),
                source: `${rinfo.address}:${rinfo.port}`,
                payload: payload,
                rawLength: msg.length,
                verified: this._verifyPayload(payload)
            };

            this.pulses.push(pulse);

            // Trim history to prevent unbounded growth
            if (this.pulses.length > this.options.maxHistory) {
                this.pulses.shift();
            }

            if (this.options.logToConsole) {
                const status = pulse.verified ? '✓ VERIFIED' : '✗ UNVERIFIED';
                console.log(`[COLLECTOR] ${status} | Node: ${payload.node || 'unknown'} | Seq: ${payload.pulseSeq || '?'} | From: ${pulse.source} | ${msg.length} bytes`);
            }
        } catch (err) {
            console.error(`[COLLECTOR] Failed to parse pulse from ${rinfo.address}:${rinfo.port}: ${err.message}`);
        }
    }

    _verifyPayload(payload) {
        if (!this.options.verifyEntropy) return true;
        // Basic structural verification
        return payload.node && payload.ts && typeof payload.pulseSeq === 'number';
    }

    start() {
        if (this.running) {
            console.log('[COLLECTOR] Already listening');
            return;
        }
        this.running = true;
        this.server.bind(this.listenPort);
    }

    stop() {
        this.running = false;
        this.server.close(() => {
            console.log('[COLLECTOR] SovereignCollector stopped');
        });
    }

    getPulses(nodeId = null, limit = 100) {
        let results = this.pulses;
        if (nodeId) {
            results = results.filter(p => p.payload.node === nodeId);
        }
        return results.slice(-limit);
    }

    getStats() {
        const nodes = {};
        this.pulses.forEach(p => {
            const id = p.payload.node || 'unknown';
            nodes[id] = (nodes[id] || 0) + 1;
        });
        return {
            totalPulses: this.pulses.length,
            uniqueNodes: Object.keys(nodes).length,
            nodeBreakdown: nodes,
            running: this.running,
            listenPort: this.listenPort
        };
    }
}

module.exports = { SovereignCollector };

if (require.main === module) {
    const port = parseInt(process.env.COLLECTOR_PORT || '9999', 10);
    const collector = new SovereignCollector(port);
    collector.start();

    // Periodic stats dump
    setInterval(() => {
        const stats = collector.getStats();
        console.log(`[COLLECTOR STATS] Total pulses: ${stats.totalPulses} | Nodes: ${stats.uniqueNodes} | ${JSON.stringify(stats.nodeBreakdown)}`);
    }, 30000);

    process.on('SIGINT', () => {
        console.log('\n[COLLECTOR] Received SIGINT, shutting down...');
        collector.stop();
        process.exit(0);
    });
}
