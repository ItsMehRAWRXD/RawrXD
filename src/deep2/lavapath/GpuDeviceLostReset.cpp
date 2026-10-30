/* GpuDeviceLostReset.cpp — env opt-in + mark/reset + PnP bounce. ≤99. */
#include "GpuDeviceLostReset.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#  include <windows.h>
#endif

namespace Deep2 {
namespace GpuLost {

bool OptInEnabled() noexcept {
    const char* e = std::getenv("DEEP2_GPU_DEVICE_RESET");
    return e && e[0] == '1' && e[1] == '\0';
}

bool PnpBounceOptIn() noexcept {
    const char* e = std::getenv("DEEP2_GPU_PNP_BOUNCE");
    return e && e[0] == '1' && e[1] == '\0';
}

bool TryPnpBounce(int code) noexcept {
    if (!PnpBounceOptIn()) return false;
    if (code != kWinCode10 && code != kWinCode31) return false;
#ifdef _WIN32
    const char* root = std::getenv("RAWRXD_ROOT");
    char cmd[1024];
    if (root && root[0]) {
        std::snprintf(cmd, sizeof(cmd),
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
            "\"%s\\scripts\\Reset-GpuDevicePnp.ps1\"",
            root);
    } else {
        std::snprintf(cmd, sizeof(cmd),
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
            "\"F:\\rawrxd-native-agent-001\\scripts\\Reset-GpuDevicePnp.ps1\"");
    }
    std::fprintf(stderr, "DEEP2_GPU_PNP_BOUNCE spawn code=%d\n", code);
    std::fflush(stderr);
    const int rc = std::system(cmd);
    std::fprintf(stderr, "DEEP2_GPU_PNP_BOUNCE exit=%d\n", rc);
    std::fflush(stderr);
    return rc == 0;
#else
    (void)code;
    return false;
#endif
}

void Mark(Seq& s, int code) noexcept {
    if (!IsLostCode(code)) return;
    s.lost = true;
    s.last_code = code;
    s.last_phase = PhaseFor(code);
    ++s.mark;
    std::fprintf(stderr,
                 "DEEP2_GPU_DEVICE_LOST mark=%u code=%d phase=%s\n",
                 s.mark, code, s.last_phase);
    std::fflush(stderr);
    if (code == kWinCode10 || code == kWinCode31) (void)TryPnpBounce(code);
}

bool RunReset(Seq& s, bool (*teardown)(void*), bool (*recreate)(void*),
              void* ud) noexcept {
    if (!s.lost || !teardown || !recreate) {
        ++s.fail_closed;
        return false;
    }
    std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET teardown_begin\n");
    std::fflush(stderr);
    if (!teardown(ud)) {
        ++s.fail_closed;
        std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET teardown_FAIL\n");
        std::fflush(stderr);
        return false;
    }
    ++s.teardown;
    std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET recreate_begin\n");
    std::fflush(stderr);
    if (!recreate(ud)) {
        ++s.fail_closed;
        std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET recreate_FAIL\n");
        std::fflush(stderr);
        return false;
    }
    ++s.recreate;
    s.lost = false;
    std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET recreate_OK\n");
    std::fflush(stderr);
    return true;
}

bool RunResetRetry(Seq& s, bool (*teardown)(void*), bool (*recreate)(void*),
                   bool (*retry)(void*), void* ud) noexcept {
    if (!RunReset(s, teardown, recreate, ud)) return false;
    if (!retry) {
        ++s.fail_closed;
        return false;
    }
    if (!retry(ud)) {
        ++s.fail_closed;
        std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET retry_FAIL\n");
        std::fflush(stderr);
        return false;
    }
    ++s.retry;
    std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET retry_OK\n");
    std::fflush(stderr);
    return true;
}

} // namespace GpuLost
} // namespace Deep2
