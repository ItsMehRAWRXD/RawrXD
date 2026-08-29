// ============================================================================
// hexmag_ide_send_path.hpp — shared IDE operator-turn entry (no UI)
// ============================================================================
// Same sequencing Win32IDE_HexMag uses for Copilot/HexMag asks:
//   resetSession → HexMagRuntimeController::run → FinalizePolicy (inside)
// Certs and IDE must call this path; do not fork a second controller.
// ============================================================================
#ifndef RAWRXD_HEXMAG_IDE_SEND_PATH_HPP
#define RAWRXD_HEXMAG_IDE_SEND_PATH_HPP

#include "core/hexmag_runtime_controller.hpp"

#include <mutex>
#include <string>

namespace RawrXD {
namespace HexMag {

/// Process-lifetime IDE HexMag session (NEED_INPUT latch is per-turn via reset).
struct IdeHexMagSendPath {
    std::mutex mu;
    LiveHexMagTransport transport;
    HexMagRuntimeController ctrl{&transport};

    ControllerResult operatorTurn(const std::string& prompt,
                                  const std::string& context = {}) {
        std::lock_guard<std::mutex> lock(mu);
        ctrl.resetSession();
        return ctrl.run(prompt, context);
    }

    /// Cert/adversarial: inject transport without touching FinalizePolicy.
    ControllerResult operatorTurnWith(IHexMagTransport* t,
                                      const std::string& prompt,
                                      const std::string& context = {}) {
        std::lock_guard<std::mutex> lock(mu);
        HexMagRuntimeController c(t);
        c.resetSession();
        return c.run(prompt, context);
    }
};

inline IdeHexMagSendPath& ideHexMagSendPath() {
    static IdeHexMagSendPath s;
    return s;
}

enum class IdeUiOutcome : uint8_t {
    Failure = 0,
    NeedInput,
    Final,
};

inline IdeUiOutcome ideUiOutcome(const ControllerResult& r) {
    if (r.finalAuthority)
        return IdeUiOutcome::Final;
    if (r.needInputLatched || r.fail == ControllerFail::NeedInput)
        return IdeUiOutcome::NeedInput;
    return IdeUiOutcome::Failure;
}

} // namespace HexMag
} // namespace RawrXD

#endif
