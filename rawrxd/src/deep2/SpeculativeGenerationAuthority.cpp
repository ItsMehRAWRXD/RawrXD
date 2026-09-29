// SpeculativeGenerationAuthority.cpp — RAWRXD_SPECULATIVE_GENERATION_AUTHORITY_001
#include "SpeculativeGenerationAuthority.h"
#include "ReceiptAuthority.h"
#include <atomic>
namespace rawrxd { namespace spec {
static std::atomic<int> g_draftsBuilt{0};
static std::atomic<int> g_draftsVerified{0};
static std::atomic<uint32_t> g_tokensAccepted{0};
static std::atomic<uint32_t> g_tokensRejected{0};
void buildDraft() { g_draftsBuilt.fetch_add(1); }
void verifyDraft() { g_draftsVerified.fetch_add(1); }
void acceptTokens(uint32_t count) { g_tokensAccepted.fetch_add(count); }
void rejectTokens(uint32_t count) { g_tokensRejected.fetch_add(count); }
void writeSpecReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_SPECULATIVE_GENERATION_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "DRAFTS_BUILT", g_draftsBuilt.load());
    rawrxd::receipt::writeKeyValueInt(path, "DRAFTS_VERIFIED", g_draftsVerified.load());
    rawrxd::receipt::writeKeyValueInt(path, "TOKENS_ACCEPTED", (int64_t)g_tokensAccepted.load());
    rawrxd::receipt::writeKeyValueInt(path, "TOKENS_REJECTED", (int64_t)g_tokensRejected.load());
    uint32_t total = g_tokensAccepted.load() + g_tokensRejected.load();
    double acceptRate = (total > 0) ? (double)g_tokensAccepted.load() / (double)total : 0.0;
    rawrxd::receipt::writeKeyValueFloat(path, "ACCEPT_RATE", acceptRate);
    rawrxd::receipt::endGate(path, (g_tokensAccepted.load() > 0) ? "PASS" : "HOLD");
}
}} // namespace rawrxd::spec