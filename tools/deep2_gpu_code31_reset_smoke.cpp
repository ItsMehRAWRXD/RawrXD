/* deep2_gpu_code31_reset_smoke — inject lost/code31; assert reset seq. */
#include "deep2/lavapath/GpuDeviceLostReset.hpp"
#include <cstdio>
#include <cstring>

namespace {

struct Harness {
    int teardown_n = 0;
    int recreate_n = 0;
    int retry_n = 0;
    bool recreate_ok = true;
    bool retry_ok = true;
};

bool Td(void* ud) {
    auto* h = static_cast<Harness*>(ud);
    ++h->teardown_n;
    return true;
}
bool Rc(void* ud) {
    auto* h = static_cast<Harness*>(ud);
    ++h->recreate_n;
    return h->recreate_ok;
}
bool Rt(void* ud) {
    auto* h = static_cast<Harness*>(ud);
    ++h->retry_n;
    return h->retry_ok;
}

} // namespace

int main() {
    using Deep2::GpuLost::IsLostCode;
    using Deep2::GpuLost::Mark;
    using Deep2::GpuLost::PhaseFor;
    using Deep2::GpuLost::RunReset;
    using Deep2::GpuLost::RunResetRetry;
    using Deep2::GpuLost::Seq;
    using Deep2::GpuLost::kVkDeviceLost;
    using Deep2::GpuLost::kWinCode31;

    int fails = 0;
    if (!IsLostCode(kVkDeviceLost)) {
        std::fprintf(stderr, "FAIL: VK lost not recognized\n");
        ++fails;
    }
    if (!IsLostCode(kWinCode31)) {
        std::fprintf(stderr, "FAIL: code 31 not recognized\n");
        ++fails;
    }
    if (IsLostCode(0) || IsLostCode(-1)) {
        std::fprintf(stderr, "FAIL: false-positive lost code\n");
        ++fails;
    }
    if (std::strcmp(PhaseFor(kVkDeviceLost), "device_lost") != 0 ||
        std::strcmp(PhaseFor(kWinCode31), "code_31") != 0) {
        std::fprintf(stderr, "FAIL: phase map\n");
        ++fails;
    }

    Seq s{};
    Mark(s, kVkDeviceLost);
    if (!s.lost || s.mark != 1 || s.last_code != kVkDeviceLost) {
        std::fprintf(stderr, "FAIL: mark VK lost\n");
        ++fails;
    }
    Mark(s, kWinCode31);
    if (s.mark != 2 || std::strcmp(s.last_phase, "code_31") != 0) {
        std::fprintf(stderr, "FAIL: mark code 31\n");
        ++fails;
    }

    Harness h{};
    if (!RunResetRetry(s, Td, Rc, Rt, &h) || h.teardown_n != 1 ||
        h.recreate_n != 1 || h.retry_n != 1 || s.teardown != 1 ||
        s.recreate != 1 || s.retry != 1 || s.lost) {
        std::fprintf(stderr, "FAIL: reset+retry seq\n");
        ++fails;
    }

    Seq fail{};
    Mark(fail, kVkDeviceLost);
    Harness bad{};
    bad.recreate_ok = false;
    if (RunReset(fail, Td, Rc, &bad) || fail.fail_closed == 0) {
        std::fprintf(stderr, "FAIL: expected fail-closed on recreate\n");
        ++fails;
    }

    if (fails) {
        std::fprintf(stderr, "RESULT=FAIL fails=%d\n", fails);
        return 1;
    }
    std::fprintf(stderr, "RESULT=PASS code31_mapped=1 vk_lost_mapped=1 "
                         "reset_seq=1 fail_closed=1\n");
    return 0;
}
