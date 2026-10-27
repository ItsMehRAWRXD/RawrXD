/* GpuDeviceLostReset — classify code-31 / VK lost + reset seq. ≤99. */
#pragma once
#include <cstdint>

namespace Deep2 {
namespace GpuLost {

/* VK_ERROR_DEVICE_LOST == -4. Win32 ERROR_GEN_FAILURE / CM_PROB = 31. */
enum : int { kVkDeviceLost = -4, kWinCode31 = 31 };

inline bool IsLostCode(int code) noexcept {
    return code == kVkDeviceLost || code == kWinCode31;
}

inline const char* PhaseFor(int code) noexcept {
    if (code == kVkDeviceLost) return "device_lost";
    if (code == kWinCode31) return "code_31";
    return "none";
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
