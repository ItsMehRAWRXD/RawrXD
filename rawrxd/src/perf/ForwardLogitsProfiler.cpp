// ForwardLogitsProfiler.cpp — RAWRXD_FORWARD_LOGITS_SPEED_001
#include "ForwardLogitsProfiler.h"
#include "../ReceiptAuthority.h"
#include <atomic>
#include <cstring>
namespace rawrxd { namespace perf {
static std::atomic<uint64_t> g_stageNs[15]{};
static std::atomic<int> g_tokenCount{0};
void beginToken() { g_tokenCount.fetch_add(1); }
void recordStage(Stage s, uint64_t ns) { g_stageNs[(int)s].fetch_add(ns); }
const char* stageName(Stage s) {
    switch (s) { case Stage::Embed: return "EMBED"; case Stage::AttnQ: return "ATTN_Q";
        case Stage::AttnK: return "ATTN_K"; case Stage::AttnV: return "ATTN_V";
        case Stage::AttnOut: return "ATTN_OUT"; case Stage::FfnGate: return "FFN_GATE";
        case Stage::FfnUp: return "FFN_UP"; case Stage::FfnAct: return "FFN_ACT";
        case Stage::FfnDown: return "FFN_DOWN"; case Stage::FinalNorm: return "FINAL_NORM";
        case Stage::LmHead: return "LM_HEAD"; case Stage::Logits: return "LOGITS";
        case Stage::Sampler: return "SAMPLER"; case Stage::Callback: return "CALLBACK";
        case Stage::Render: return "RENDER"; default: return "UNKNOWN"; }
}
void writeForwardLogitsReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_FORWARD_LOGITS_SPEED_001");
    rawrxd::receipt::writeKeyValueInt(path, "TOKEN_COUNT", g_tokenCount.load());
    for (int i = 0; i < 15; ++i) {
        uint64_t ns = g_stageNs[i].load();
        if (ns > 0) {
            double ms = ns / 1e6;
            rawrxd::receipt::writeKeyValueFloat(path, std::string("STAGE_MS_") + stageName((Stage)i), ms);
        }
    }
    rawrxd::receipt::endGate(path, "PASS");
}
}} // namespace rawrxd::perf