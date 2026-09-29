// IdeGenerationDiag.cpp — RAWRXD_IDE_GENERATION_UNSILENT_001
#include "IdeGenerationDiag.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
#include <string>
namespace rawrxd { namespace ide_diag {
static std::atomic<int> g_sessionsBegun{0};
static std::atomic<int> g_sessionsEnded{0};
static std::atomic<int> g_stallsRecorded{0};
static std::atomic<int> g_lastStage{(int)Stage::Tokenize};
static const char* stageName(Stage s) {
    switch (s) {
        case Stage::Tokenize:  return "Tokenize";
        case Stage::Prefill:   return "Prefill";
        case Stage::Forward:   return "Forward";
        case Stage::Logits:    return "Logits";
        case Stage::Sampler:   return "Sampler";
        case Stage::Callback:  return "Callback";
        case Stage::Render:    return "Render";
        case Stage::Join:      return "Join";
        case Stage::Done:      return "Done";
        case Stage::Stall:     return "Stall";
    }
    return "Unknown";
}
void beginSession() { g_sessionsBegun.fetch_add(1); g_stallsRecorded.store(0); }
void recordStage(Stage stage) { g_lastStage.store((int)stage); }
void recordStall(Stage stage) { g_stallsRecorded.fetch_add(1); g_lastStage.store((int)stage); }
void endSession() {
    g_sessionsEnded.fetch_add(1);
    rawrxd::receipt::beginGate("ide_generation_diag_receipt.txt", "RAWRXD_IDE_GENERATION_UNSILENT_001");
    rawrxd::receipt::writeKeyValueInt("ide_generation_diag_receipt.txt", "SESSIONS_BEGUN", g_sessionsBegun.load());
    rawrxd::receipt::writeKeyValueInt("ide_generation_diag_receipt.txt", "SESSIONS_ENDED", g_sessionsEnded.load());
    rawrxd::receipt::writeKeyValueInt("ide_generation_diag_receipt.txt", "STALLS_RECORDED", g_stallsRecorded.load());
    rawrxd::receipt::writeKeyValue("ide_generation_diag_receipt.txt", "LAST_STAGE", stageName((Stage)g_lastStage.load()));
    rawrxd::receipt::endGate("ide_generation_diag_receipt.txt", (g_stallsRecorded.load() == 0) ? "PASS" : "FAIL");
}
}} // namespace rawrxd::ide_diag