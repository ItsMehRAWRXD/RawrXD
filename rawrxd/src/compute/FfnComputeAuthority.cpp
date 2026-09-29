// FFN compute authority implementation
// RawrXD FFN Compute Authority - Gates all feed-forward network computation

#include "src/compute/FfnComputeAuthority.h"
#include <iostream>
#include <string>

namespace rawrxd::compute
{
    // Global FFN compute authority state
    struct FfnComputeAuthorityState
    {
        bool entered = false;
        long long gateMs = 0;
        long long upMs = 0;
        long long actMs = 0;
        long long downMs = 0;
        long long ffnTotalMs = 0;
        bool finiteOutput = false;
        std::string verdict = "HOLD";
    };

    // Global state instance
    static FfnComputeAuthorityState g_ffnAuthorityState;

    // Compute gate
    void computeGate(long long durationMs)
    {
        g_ffnAuthorityState.entered = true;
        g_ffnAuthorityState.gateMs = durationMs;
        g_ffnAuthorityState.ffnTotalMs += durationMs;
        std::cout << "[FfnComputeAuthority] Computed gate: " << durationMs << "ms" << std::endl;
    }

    // Compute up
    void computeUp(long long durationMs)
    {
        g_ffnAuthorityState.upMs = durationMs;
        g_ffnAuthorityState.ffnTotalMs += durationMs;
        std::cout << "[FfnComputeAuthority] Computed up: " << durationMs << "ms" << std::endl;
    }

    // Compute activation
    void computeActivation(long long durationMs)
    {
        g_ffnAuthorityState.actMs = durationMs;
        g_ffnAuthorityState.ffnTotalMs += durationMs;
        std::cout << "[FfnComputeAuthority] Computed activation: " << durationMs << "ms" << std::endl;
    }

    // Compute down
    void computeDown(long long durationMs)
    {
        g_ffnAuthorityState.downMs = durationMs;
        g_ffnAuthorityState.ffnTotalMs += durationMs;
        std::cout << "[FfnComputeAuthority] Computed down: " << durationMs << "ms" << std::endl;
    }

    // Write FFN receipt
    void writeFfnReceipt()
    {
        std::cout << "[FfnComputeAuthority] Writing FFN receipt:" << std::endl;
        std::cout << "  FFN_ENTERED=" << g_ffnAuthorityState.entered << std::endl;
        std::cout << "  GATE_MS=" << g_ffnAuthorityState.gateMs << std::endl;
        std::cout << "  UP_MS=" << g_ffnAuthorityState.upMs << std::endl;
        std::cout << "  ACT_MS=" << g_ffnAuthorityState.actMs << std::endl;
        std::cout << "  DOWN_MS=" << g_ffnAuthorityState.downMs << std::endl;
        std::cout << "  FFN_TOTAL_MS=" << g_ffnAuthorityState.ffnTotalMs << std::endl;
        std::cout << "  FINITE_OUTPUT=" << (g_ffnAuthorityState.finiteOutput ? "true" : "false") << std::endl;
        std::cout << "  VERDICT=" << g_ffnAuthorityState.verdict << std::endl;
    }
}