// SovereignBeacon.js — Unidirectional UDP Pulse Emitter
// Zero-weight, connectionless, outbound-only telemetry
// No handshake, no reply, no TCP overhead

const dgram = require('dgram');
const crypto = require('crypto');
const os = require('os');

class SovereignBeaconStreamer {
    constructor(nodeId, targetHost, targetPort, options = {}) {
        this.nodeId = nodeId;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.client = dgram.createSocket('udp4');
        this.running = false;
        this.pulseCount = 0;
        this.lastPulseTime = null;
        this.options = {
            includeSysinfo: options.includeSysinfo !== false,
            includeEntropy: options.includeEntropy !== false,
            jitter: options.jitter !== false,
            ...options
        };

        this.client.on('error', (err) => {
            console.error(`[BEACON ERROR] UDP socket error: ${err.message}`);
        });
    }

    _gatherTelemetry() {
        const telemetry = {
            node: this.nodeId,
            ts: Math.floor(Date.now() / 1000),
            uptime: process.uptime(),
            pulseSeq: ++this.pulseCount
        };

        if (this.options.includeSysinfo) {
            const freemem = os.freemem();
            const totalmem = os.totalmem();
            telemetry.sys = {
                platform: os.platform(),
                arch: os.arch(),
                hostname: os.hostname(),
                loadAvg: os.loadavg(),
                freemem: freemem,
                totalmem: totalmem,
                memUsedPct: ((totalmem - freemem) / totalmem * 100).toFixed(2),
                cpuCount: os.cpus().length
            };
        }

        if (this.options.includeEntropy) {
            telemetry.entropy = crypto.randomBytes(8).toString('hex');
            telemetry.nonce = crypto.randomBytes(4).toString('hex');
        }

        return telemetry;
    }

    transmitPulse(statusString = 'ZERO_WEIGHT_STABLE') {
        const payload = JSON.stringify({
            ...this._gatherTelemetry(),
            status: statusString
        });

        const buffer = Buffer.from(payload);

        this.client.send(buffer, 0, buffer.length, this.targetPort, this.targetHost, (err) => {
            this.lastPulseTime = Date.now();
            if (err) {
                console.error(`[BEACON FAIL] Pulse ${this.pulseCount} failed: ${err.message}`);
            } else {
                console.log(`[PULSE] Unidirectional telemetry signature fired -> ${this.targetHost}:${this.targetPort} (seq=${this.pulseCount}, ${buffer.length} bytes)`);
            }
        });
    }

    start(minSeconds = 5, maxSeconds = 15) {
        if (this.running) {
            console.log('[BEACON] Already running');
            return;
        }
        this.running = true;
        console.log(`[BEACON] SovereignBeaconStreamer initialized: ${this.nodeId} -> ${this.targetHost}:${this.targetPort}`);
        console.log(`[BEACON] Jitter range: ${minSeconds}s - ${maxSeconds}s`);

        const loop = () => {
            if (!this.running) return;
            this.transmitPulse();
            const nextInterval = Math.floor(Math.random() * (maxSeconds - minSeconds + 1) + minSeconds) * 1000;
            setTimeout(loop, nextInterval);
        };
        loop();
    }

    stop() {
        this.running = false;
        this.client.close(() => {
            console.log('[BEACON] SovereignBeaconStreamer stopped');
        });
    }

    getStatus() {
        return {
            running: this.running,
            nodeId: this.nodeId,
            target: `${this.targetHost}:${this.targetPort}`,
            pulseCount: this.pulseCount,
            lastPulseTime: this.lastPulseTime,
            uptime: process.uptime()
        };
    }
}

module.exports = { SovereignBeaconStreamer };

if (require.main === module) {
    const nodeId = process.env.BEACON_NODE_ID || 'node-rawrz-standalone';
    const targetHost = process.env.BEACON_TARGET_HOST || '127.0.0.1';
    const targetPort = parseInt(process.env.BEACON_TARGET_PORT || '9999', 10);
    const minSeconds = parseInt(process.env.BEACON_MIN_INTERVAL || '5', 10);
    const maxSeconds = parseInt(process.env.BEACON_MAX_INTERVAL || '15', 10);

    const streamer = new SovereignBeaconStreamer(nodeId, targetHost, targetPort);
    streamer.start(minSeconds, maxSeconds);

    process.on('SIGINT', () => {
        console.log('\n[BEACON] Received SIGINT, shutting down...');
        streamer.stop();
        process.exit(0);
    });
}
