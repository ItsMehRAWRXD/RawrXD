// ShutdownReasonAuthority.cpp — RAWRXD_SHUTDOWN_REASON_AUTHORITY_001
#include "ShutdownReasonAuthority.h"
#include "../ReceiptAuthority.h"
#include <atomic>
namespace rawrxd { namespace shutdown {
static std::atomic<Reason> g_reason{Reason::Unknown};
void record(Reason r) { g_reason.store(r); }
Reason currentReason() { return g_reason.load(); }
const char* reasonName(Reason r) {
    switch (r) {
        case Reason::WmClose: return "WmClose"; case Reason::WmDestroy: return "WmDestroy";
        case Reason::ChatExitOnDone: return "ChatExitOnDone"; case Reason::CertTimerExpired: return "CertTimerExpired";
        case Reason::AutorunComplete: return "AutorunComplete"; case Reason::Scheduler: return "Scheduler";
        case Reason::ApplicationQuit: return "ApplicationQuit"; case Reason::ExternalClose: return "ExternalClose";
        case Reason::HexMagInitFailed: return "HexMagInitFailed"; case Reason::PostQuit: return "PostQuit";
        case Reason::RebootRequested: return "RebootRequested"; case Reason::Crash: return "Crash";
        case Reason::WatchdogTimeout: return "WatchdogTimeout"; default: return "Unknown";
    }
}
void writeReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_SHUTDOWN_REASON_AUTHORITY_001");
    rawrxd::receipt::writeKeyValue(path, "SHUTDOWN_REASON", reasonName(g_reason.load()));
    rawrxd::receipt::endGate(path, "PASS");
}
}} // namespace rawrxd::shutdown