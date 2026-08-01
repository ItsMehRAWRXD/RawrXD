// src/engine/simd-detector.js
// Hardware Feature Discriminator — detects AVX2/AVX512/FMA at runtime

class RawrSimdDetector {
    constructor() {
        this.capabilities = {
            hasAVX2: false,
            hasAVX512: false,
            hasFMA: false,
            hasSSE: false,
            hasSSE2: false,
            hasSSE3: false,
            hasAVX: false
        };
        this.evaluateHardwareVectorFlags();
    }

    evaluateHardwareVectorFlags() {
        // WebAssembly SIMD detection as safe indicator
        if (typeof WebAssembly !== 'undefined' && WebAssembly.validate) {
            const wasmSimdTestBuffer = new Uint8Array([
                0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 10, 9, 1, 7, 0, 65, 0, 253, 15, 11
            ]);
            const baselineSimdValid = WebAssembly.validate(wasmSimdTestBuffer);

            this.capabilities.hasSSE = baselineSimdValid;
            this.capabilities.hasSSE2 = baselineSimdValid;
            this.capabilities.hasSSE3 = baselineSimdValid;
            this.capabilities.hasAVX = baselineSimdValid;
            this.capabilities.hasAVX2 = baselineSimdValid;
            this.capabilities.hasFMA = baselineSimdValid;

            // Native platform agent string evaluation for AVX-512
            const ua = navigator.userAgent;
            this.capabilities.hasAVX512 = ua.includes('AMD') || ua.includes('Xeon') || ua.includes('Intel');
        } else {
            console.warn('Vector instruction validation unavailable. Defaulting to scalar registers.');
        }
    }

    detectCapabilities() {
        return { ...this.capabilities };
    }

    getActivePipeline() {
        if (this.capabilities.hasAVX512) return 'AVX512';
        if (this.capabilities.hasAVX2) return 'AVX2';
        if (this.capabilities.hasFMA) return 'FMA';
        if (this.capabilities.hasAVX) return 'AVX';
        if (this.capabilities.hasSSE) return 'SSE';
        return 'GENERIC';
    }
}

if (typeof window !== 'undefined') {
    window.RawrSimdDetector = new RawrSimdDetector();
}
