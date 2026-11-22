// deep2_lostseq_failure_injection.cpp — CPU-only failure-injection for the
// Deep2 device-loss quarantine state machine (GpuLost::Seq).
//
// Exercises the PRODUCTION GpuDeviceLostReset.cpp lifecycle code with injected
// Vulkan/Win32 return codes, WITHOUT a physical Vulkan device. Certifies the
// centralized completion/quarantine contract's bookkeeping:
//   - Mark() on VK_ERROR_DEVICE_LOST / Win 10 / Win 31 sets lost + phase
//   - Mark() on a non-lost code is a no-op
//   - RunReset() success path: teardown -> recreate -> lost cleared
//   - RunReset() teardown failure: fail_closed++, lost retained
//   - RunReset() recreate failure: fail_closed++, lost retained
//   - RunReset() when not lost: fail_closed++ (nothing to reset)
//   - Idempotency: repeated Mark accumulates marks; RunReset is not
//     re-entrant after success (lost already false)
//
// Exit 0 = all controls pass.

#include "deep2/lavapath/GpuDeviceLostReset.hpp"
#include <cstdio>

// VK_SUCCESS == 0. Defined locally so this CPU-only test does not need a
// Vulkan header/device.
#ifndef VK_SUCCESS
#define VK_SUCCESS 0
#endif

using namespace Deep2::GpuLost;

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

// Test doubles for teardown/recreate.
static int g_teardownCalls = 0;
static int g_recreateCalls = 0;
static bool g_teardownOK = true;
static bool g_recreateOK = true;

static bool teardown(void*) { ++g_teardownCalls; return g_teardownOK; }
static bool recreate(void*) { ++g_recreateCalls; return g_recreateOK; }

int main() {
    // --- Mark classification ---
    {
        Seq s;
        Mark(s, kVkDeviceLost);  // -4
        expect(s.lost && s.mark == 1 && s.last_code == -4, "mark_vk_device_lost");
        expect(std::strcmp(s.last_phase, "device_lost") == 0, "mark_phase_device_lost");
    }
    {
        Seq s;
        Mark(s, kWinCode10);
        expect(s.lost && std::strcmp(s.last_phase, "power_failure") == 0,
               "mark_win10_power_failure");
        Mark(s, kWinCode31);
        expect(s.lost && s.mark == 2 && std::strcmp(s.last_phase, "code_31") == 0,
               "mark_win31_code_31");
    }
    {
        Seq s;
        Mark(s, VK_SUCCESS);  // 0, not a lost code
        expect(!s.lost && s.mark == 0, "mark_success_noop");
        Mark(s, -5);  // some other VK error, not lost
        expect(!s.lost && s.mark == 0, "mark_other_error_noop");
    }

    // --- RunReset success path ---
    {
        Seq s;
        Mark(s, kVkDeviceLost);
        g_teardownCalls = g_recreateCalls = 0;
        g_teardownOK = g_recreateOK = true;
        const bool ok = RunReset(s, teardown, recreate, nullptr);
        expect(ok, "reset_success_returns_true");
        expect(g_teardownCalls == 1 && g_recreateCalls == 1, "reset_calls_teardown_recreate");
        expect(!s.lost && s.teardown == 1 && s.recreate == 1, "reset_clears_lost");
        expect(s.fail_closed == 0, "reset_success_no_fail_closed");
    }

    // --- RunReset teardown failure ---
    {
        Seq s;
        Mark(s, kVkDeviceLost);
        g_teardownOK = false; g_recreateOK = true;
        g_teardownCalls = g_recreateCalls = 0;
        const bool ok = RunReset(s, teardown, recreate, nullptr);
        expect(!ok, "reset_teardown_fail_returns_false");
        expect(s.lost, "reset_teardown_fail_retains_lost");
        expect(s.fail_closed == 1, "reset_teardown_fail_fail_closed_1");
        expect(g_recreateCalls == 0, "reset_teardown_fail_skips_recreate");
        g_teardownOK = true;
    }

    // --- RunReset recreate failure ---
    {
        Seq s;
        Mark(s, kVkDeviceLost);
        g_teardownOK = true; g_recreateOK = false;
        g_teardownCalls = g_recreateCalls = 0;
        const bool ok = RunReset(s, teardown, recreate, nullptr);
        expect(!ok, "reset_recreate_fail_returns_false");
        expect(s.lost, "reset_recreate_fail_retains_lost");
        expect(s.fail_closed == 1, "reset_recreate_fail_fail_closed_1");
        g_recreateOK = true;
    }

    // --- RunReset when not lost ---
    {
        Seq s;  // not lost
        g_teardownCalls = g_recreateCalls = 0;
        const bool ok = RunReset(s, teardown, recreate, nullptr);
        expect(!ok, "reset_not_lost_returns_false");
        expect(s.fail_closed == 1, "reset_not_lost_fail_closed_1");
        expect(g_teardownCalls == 0 && g_recreateCalls == 0, "reset_not_lost_no_calls");
    }

    // --- Idempotency: repeated Mark accumulates; RunReset after success is a no-op ---
    {
        Seq s;
        Mark(s, kVkDeviceLost);
        Mark(s, kVkDeviceLost);
        expect(s.mark == 2 && s.lost, "mark_idempotent_accumulates");
        g_teardownOK = g_recreateOK = true;
        const bool ok1 = RunReset(s, teardown, recreate, nullptr);
        expect(ok1 && !s.lost, "reset_first_success");
        // Second RunReset on a non-lost seq -> fail_closed (nothing to reset).
        const bool ok2 = RunReset(s, teardown, recreate, nullptr);
        expect(!ok2 && s.fail_closed == 1, "reset_after_success_fail_closed");
    }

    // --- RunResetRetry success path ---
    {
        Seq s;
        Mark(s, kWinCode31);
        g_teardownOK = g_recreateOK = true;
        g_teardownCalls = g_recreateCalls = 0;
        bool retried = false;
        auto retry = [](void*) -> bool { return true; };
        // Note: RunResetRetry signature is (s, teardown, recreate, retry, ud)
        const bool ok = RunResetRetry(s, teardown, recreate, retry, nullptr);
        expect(ok && !s.lost && s.retry == 1, "reset_retry_success");
    }

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}