// Logits compute authority implementation
// RawrXD Logits Compute Authority - Gates all logits computation including final norm and LM head

#include "src/compute/LogitsComputeAuthority.h"
#include <iostream>
#include <string>

namespace rawrxd::compute
{
    // Global logits compute authority state
    struct LogitsComputeAuthorityState
    {
        bool entered = false;
        long long finalNormMs = 0;
        long long lmHeadMs = 0;
        int vocabSize = 0;
        bool logitsFinite = false;
        bool logitsNan = false;
        bool logitsInf = false;
        int argmax = 0;
        std::string verdict = "HOLD";
    };

    // Global state instance
    static LogitsComputeAuthorityState g_logitsAuthorityState;

    // Compute final norm
    void computeFinalNorm(long long durationMs)
    {
        g_logitsAuthorityState.entered = true;
        g_logitsAuthorityState.finalNormMs = durationMs;
        std::cout << "[LogitsComputeAuthority] Computed final norm: " << durationMs << "ms" << std::endl;
    }

    // Compute LM head
    void computeLmHead(long long durationMs)
    {
        g_logitsAuthorityState.lmHeadMs = durationMs;
        std::cout << "[LogitsComputeAuthority] Computed LM head: " << durationMs << "ms" << std::endl;
    }

    // Record logit stats
    void recordLogitStats(int vocabSize, bool finite, bool nan, bool inf, int argmax)
    {
        g_logitsAuthorityState.vocabSize = vocabSize;
        g_logitsAuthorityState.logitsFinite = finite;
        g_logitsAuthorityState.logitsNan = nan;
        g_logitsAuthorityState.logitsInf = inf;
        g_logitsAuthorityState.argmax = argmax;
        std::cout << "[LogitsComputeAuthority] Recorded logit stats: vocab=" << vocabSize 
                  << ", finite=" << (finite ? "true" : "false") << ", nan=" << (nan ? "true" : "false")
                  << ", inf=" << (inf ? "true" : "false") << ", argmax=" << argmax << std::endl;
    }

    // Write logits receipt
    void writeLogitsReceipt()
    {
        std::cout << "[LogitsComputeAuthority] Writing logits receipt:" << std::endl;
        std::cout << "  LOGITS_ENTERED=" << g_logitsAuthorityState.entered << std::endl;
        std::cout << "  FINAL_NORM_MS=" << g_logitsAuthorityState.finalNormMs << std::endl;
        std::cout << "  LM_HEAD_MS=" << g_logitsAuthorityState.lmHeadMs << std::endl;
        std::cout << "  VOCAB_SIZE=" << g_logitsAuthorityState.vocabSize << std::endl;
        std::cout << "  LOGITS_FINITE=" << (g_logitsAuthorityState.logitsFinite ? "true" : "false") << std::endl;
        std::cout << "  LOGITS_NAN=" << (g_logitsAuthorityState.logitsNan ? "true" : "false") << std::endl;
        std::cout << "  LOGITS_INF=" << (g_logitsAuthorityState.logitsInf ? "true" : "false") << std::endl;
        std::cout << "  ARGMAX=" << g_logitsAuthorityState.argmax << std::endl;
        std::cout << "  VERDICT=" << g_logitsAuthorityState.verdict << std::endl;
    }
}