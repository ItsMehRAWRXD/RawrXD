/* GpuDeviceLostReset — classify code-10/31 / VK lost + reset seq. ≤99. */
#pragma once
#include <cstdint>
#include <cstring>

namespace Deep2 {
namespace GpuLost {

/* VK_ERROR_DEVICE_LOST == -4.
 * Win32/CM: 31 = ERROR_GEN_FAILURE;
 * 10 = CM_PROB_FAILED_START (STATUS_DEVICE_POWER_FAILURE style). */
enum : int { kVkDeviceLost = -4, kWinCode10 = 10, kWinCode31 = 31 };

inline bool IsLostCode(int code) noexcept {
    return code == kVkDeviceLost || code == kWinCode10 || code == kWinCode31;
}

/* Phase: code_10 synonym → power_failure (CM/Win Code 10). */
inline const char* PhaseFor(int code) noexcept {
    if (code == kVkDeviceLost) return "device_lost";
    if (code == kWinCode10) return "power_failure"; /* alias: code_10 */
    if (code == kWinCode31) return "code_31";
    return "none";
}

inline bool IsCode10OrPowerFailurePhase(const char* p) noexcept {
    return p && (!std::strcmp(p, "power_failure") || !std::strcmp(p, "code_10"));
}

struct Seq {
    uint32_t mark = 0;
    uint32_t teardown = 0;
    uint32_t recreate = 0;
    uint32_t retry = 0;
    uint32_t fail_closed = 0;
    int last_code = 0;
    const char* last_phase = "none";
    bool lost = false;
};

bool OptInEnabled() noexcept;
void Mark(Seq& s, int code) noexcept;
/* teardown/recreate must succeed; else fail_closed++ and false. */
bool RunReset(Seq& s, bool (*teardown)(void*), bool (*recreate)(void*),
              void* ud) noexcept;
/* After successful reset, optional one-shot retry callback. */
bool RunResetRetry(Seq& s, bool (*teardown)(void*), bool (*recreate)(void*),
                   bool (*retry)(void*), void* ud) noexcept;

} // namespace GpuLost
} // namespace Deep2
