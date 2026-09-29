// StrictCertificationAuthority.cpp — RAWRXD_STRICT_CERTIFICATION_AUTHORITY_001
#include "StrictCertificationAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
namespace rawrxd { namespace cert {
static std::atomic<int> g_sourceGraphChecks{0};
static std::atomic<int> g_realLinkChecks{0};
static std::atomic<int> g_w8Checks{0};
static std::atomic<int> g_chatE2EChecks{0};
static std::atomic<int> g_gpuChecks{0};
static std::atomic<bool> g_sourceGraphPass{false};
static std::atomic<bool> g_realLinkPass{false};
static std::atomic<bool> g_w8Pass{false};
static std::atomic<bool> g_chatE2EPass{false};
static std::atomic<bool> g_gpuPass{false};
bool checkSourceGraphTruth() { g_sourceGraphChecks.fetch_add(1); return g_sourceGraphPass.load(); }
bool checkRealLink()         { g_realLinkChecks.fetch_add(1);    return g_realLinkPass.load(); }
bool checkW8()               { g_w8Checks.fetch_add(1);          return g_w8Pass.load(); }
bool checkChatE2E()          { g_chatE2EChecks.fetch_add(1);     return g_chatE2EPass.load(); }
bool checkGpuCorrectness()   { g_gpuChecks.fetch_add(1);         return g_gpuPass.load(); }
void writeStrictCertReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_STRICT_CERTIFICATION_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "SOURCE_GRAPH_CHECKS", g_sourceGraphChecks.load());
    rawrxd::receipt::writeKeyValueInt(path, "SOURCE_GRAPH_PASS", g_sourceGraphPass.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "REAL_LINK_CHECKS", g_realLinkChecks.load());
    rawrxd::receipt::writeKeyValueInt(path, "REAL_LINK_PASS", g_realLinkPass.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "W8_CHECKS", g_w8Checks.load());
    rawrxd::receipt::writeKeyValueInt(path, "W8_PASS", g_w8Pass.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "CHAT_E2E_CHECKS", g_chatE2EChecks.load());
    rawrxd::receipt::writeKeyValueInt(path, "CHAT_E2E_PASS", g_chatE2EPass.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "GPU_CHECKS", g_gpuChecks.load());
    rawrxd::receipt::writeKeyValueInt(path, "GPU_PASS", g_gpuPass.load() ? 1 : 0);
    bool allPass = g_sourceGraphPass && g_realLinkPass && g_w8Pass && g_chatE2EPass && g_gpuPass;
    rawrxd::receipt::endGate(path, allPass ? "PASS" : "HOLD");
}
}} // namespace rawrxd::cert