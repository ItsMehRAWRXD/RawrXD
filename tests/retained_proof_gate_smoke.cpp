// retained_proof_gate_smoke.cpp — RX + authority additive unit (no k2_runtime_validation)
#include "../src/runtime/retained_proof_gate.hpp"
#include <cstdio>

int main() {
    std::printf("P1_RETAINED_PROOF_GATE_001 smoke\n");
    auto r = k2::runtime::VerifyAndBindRuntime();
    std::printf("  [%s] PROOF_TABLE path via crash-safe commit (authority)\n",
                r.authorityOk ? "PASS" : "FAIL");
    std::printf("  [%s] map_immutable_RX_RealtimeImage\n", r.rxMapped ? "PASS" : "FAIL");
    std::printf("  [%s] bind_Deep2Bridge_entrypoint\n", r.deep2Bound ? "PASS" : "FAIL");
    std::printf("  [%s] first_token_proof\n", r.firstTokenOk ? "PASS" : "FAIL");
    std::printf("  [%s] streamed_token_proof\n", r.streamedTokenOk ? "PASS" : "FAIL");
    std::printf("  generation=%llu detail=%s\n",
                (unsigned long long)r.generation, r.detail.c_str());
    if (r.ok())
        std::printf("  [PASS] RX_PROTECTION_LAYER (PAGE_EXECUTE_READ at map)\n");
    if (!r.ok()) {
        std::printf("P1_RETAINED_PROOF_GATE_001 FAIL\n");
        return 1;
    }
    std::printf("P1_RETAINED_PROOF_GATE_001 PASS\n");
    return 0;
}
