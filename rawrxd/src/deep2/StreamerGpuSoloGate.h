// StreamerGpuSoloGate.h
// STREAMER-CERT-001 support.
//
// A device probe only. It is explicitly NOT an admission policy: there is no
// field here that expresses "too large", and nothing in this header or its
// implementation may be used to reject a model on the basis of model size or
// available RAM. Admission is decided by attempting the model and reporting
// Deep2's actual result.

#pragma once

#include <string>

namespace rawrxd::streamer {

struct GpuSoloReport {
    bool        queried       = false;
    bool        usable        = false;
    unsigned    adapterCount  = 0;
    std::string firstAdapter;
    double      dedicatedMiB  = 0.0;
    std::string detail;
};

// Enumerates DXGI adapters and reports what is present. Returns usable=true
// even when no adapter exists, because the streamer executes on CPU.
GpuSoloReport probeGpuSolo();

} // namespace rawrxd::streamer
