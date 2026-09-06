// retained_proof_gate.hpp — additive G+1 authority → RX image → Deep2 bind → token proofs
// Compile into k2_runtime_validation only when K2_ENABLE_RETAINED_PROOF_GATE=ON.
// PATCH_HISTORY_IS_NOT_RUNTIME_AUTHORITY: no patch-history parameter on any API.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace k2 {
namespace runtime {

struct RetainedProofGateResult {
    bool authorityOk = false;
    bool rxMapped = false;
    bool deep2Bound = false;
    bool firstTokenOk = false;
    bool streamedTokenOk = false;
    uint64_t generation = 0;
    std::string detail;

    bool ok() const {
        return authorityOk && rxMapped && deep2Bound && firstTokenOk && streamedTokenOk;
    }
};

// Opaque RX-mapped RuntimeImage bytes + callable entry stub (no patch history).
struct BoundRealtimeImage {
    void* imageRx = nullptr;     // PAGE_EXECUTE_READ RuntimeImage copy
    size_t imageBytes = 0;
    void* entryRx = nullptr;     // PAGE_EXECUTE_READ first/stream token stub
    size_t entryBytes = 0;
    void* deep2BridgeSlot = nullptr; // bound entry pointer storage
};

// Full additive unit: verify authority → map RX → bind Deep2 entry → token proofs.
RetainedProofGateResult VerifyAndBindRuntime();

// Release VirtualAlloc'd RX pages from the last successful/failed map attempt.
void ReleaseMappedImage(BoundRealtimeImage& img);

} // namespace runtime
} // namespace k2
