// TpsContaminationAuthority.cpp — RAWRXD_TPS_CONTAMINATION_AUTHORITY_001
#include "TpsContaminationAuthority.h"
#include "ReceiptAuthority.h"
#include <atomic>
#include <cstdio>

namespace rawrxd { namespace perf {

static std::atomic<bool> g_debugSpam{false};
static std::atomic<bool> g_fullLogitsScan{false};
static std::atomic<bool> g_perTokenFlush{false};
static std::atomic<bool> g_perTokenStderr{false};
static std::atomic<uint64_t> g_spamLines{0};

void markDebugSpam()            { g_debugSpam.store(true); g_perTokenStderr.store(true); }
void markFullLogitsScan()       { g_fullLogitsScan.store(true); }
void markPerTokenFlush()        { g_perTokenFlush.store(true); }
void markPerTokenStderr()       { g_perTokenStderr.store(true); g_debugSpam.store(true); }

bool isBaselineValid() {
    return !g_debugSpam.load() && !g_fullLogitsScan.load() &&
           !g_perTokenFlush.load() && !g_perTokenStderr.load();
}

void writeContaminationReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_TPS_CONTAMINATION_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "TRACE_SPAM_LINES", (int64_t)g_spamLines.load());
    rawrxd::receipt::writeKeyValueInt(path, "FULL_LOGITS_SCAN_PER_TOKEN", g_fullLogitsScan.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "PER_TOKEN_STDERR", g_perTokenStderr.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "PER_TOKEN_STDOUT_FLUSH", g_perTokenFlush.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "TPS_VALID_FOR_BASELINE", isBaselineValid() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "DEBUG_CONTAMINATED", g_debugSpam.load() ? 1 : 0);
    rawrxd::receipt::endGate(path, isBaselineValid() ? "PASS" : "DIAG_PASS");
}

}} // namespace rawrxd::perf