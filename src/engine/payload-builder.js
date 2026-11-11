// ============================================================================
// payload-builder.js - Secure Encrypted Payload Builder
// XOR obfuscation, schema validation, checksum generation
// ============================================================================

class RawrPayloadBuilder {
    constructor() {
        this.runtime = window.RawrRuntime;
        this.state = window.RawrStateManager;
    }

    compilePayloadStructure(configData = {}) {
        console.log('[PayloadBuilder] Compiling payload...');

        const blueprint = {
            header: {
                magic: 0x52415752,
                timestamp: Date.now(),
                targetPlatform: configData.platform || 'x64_windows',
                version: configData.version || '1.0.0'
            },
            configuration: {
                routingKey: configData.routingKey || 'default_mesh_key',
                beaconInterval: configData.beaconInterval || 60,
                activePanels: configData.panels || [],
                features: configData.features || {}
            },
            obfuscationKey: Math.floor(Math.random() * 255) + 1
        };

        // Validate
        if (blueprint.configuration.beaconInterval < 5) {
            throw new Error('Beacon interval too low (< 5s).');
        }

        const serialized = JSON.stringify(blueprint);
        const encrypted = this.applyObfuscationStream(serialized, blueprint.obfuscationKey);
        const checksum = this.generateChecksum(encrypted);

        console.log('[PayloadBuilder] Payload ready.');
        return {
            raw: blueprint,
            encryptedStream: encrypted,
            checksum,
            size: encrypted.length
        };
    }

    applyObfuscationStream(input, key) {
        let output = '';
        for (let i = 0; i < input.length; i++) {
            const charCode = input.charCodeAt(i) ^ key;
            output += String.fromCharCode(charCode);
        }
        return btoa(output);
    }

    deobfuscateStream(encoded, key) {
        const input = atob(encoded);
        let output = '';
        for (let i = 0; i < input.length; i++) {
            const charCode = input.charCodeAt(i) ^ key;
            output += String.fromCharCode(charCode);
        }
        return output;
    }

    generateChecksum(data) {
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash) + data.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash).toString(16).padStart(8, '0');
    }

    validatePayload(payload) {
        if (!payload || !payload.encryptedStream || !payload.checksum) {
            return { valid: false, reason: 'Missing fields' };
        }
        const computed = this.generateChecksum(payload.encryptedStream);
        if (computed !== payload.checksum) {
            return { valid: false, reason: `Checksum mismatch: ${computed} vs ${payload.checksum}` };
        }
        return { valid: true };
    }
}

if (typeof window !== 'undefined') {
    window.RawrPayloadBuilder = new RawrPayloadBuilder();
}
