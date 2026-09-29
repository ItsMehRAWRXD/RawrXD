// ShutdownReasonAuthority.h — RAWRXD_SHUTDOWN_REASON_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace shutdown {
enum class Reason : uint8_t {
    Unknown, WmClose, WmDestroy, ChatExitOnDone, CertTimerExpired,
    AutorunComplete, Scheduler, ApplicationQuit, ExternalClose,
    HexMagInitFailed, PostQuit, RebootRequested, Crash, WatchdogTimeout
};
void record(Reason r);
Reason currentReason();
const char* reasonName(Reason r);
void writeReceipt(const std::string& path);
}} // namespace rawrxd::shutdown