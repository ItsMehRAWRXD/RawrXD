#include "rawrxd_inference.h"
#include <iostream>

// B009-P4: Default residency pool size = 4096 MB (4 GB)
size_t RawrXDInference::s_residencyPoolMaxBytes = 4ULL * 1024 * 1024 * 1024;

// RawrXD Inference Engine - Production Implementation
// Bridges header declarations with actual inference pipeline

extern "C" {
    // Stub function kept for backward compatibility
    void RawrXDInference_Stub() {
        // No-op: real inference is handled by RawrXDInference class inline methods
    }
}


