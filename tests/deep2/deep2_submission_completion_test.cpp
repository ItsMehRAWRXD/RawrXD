// deep2_submission_completion_test.cpp — CPU-only certification of the
// centralized submission-completion contract (ReapSubmissionCompletion.hpp).
//
// Exercises the PRODUCTION decision function consumed by
// VulkanCompute::endSubmitWait, WITHOUT a physical Vulkan device. Certifies
// the reclaim/retain/terminal-teardown classification for every submission
// state.
//
// Exit 0 = all controls pass.

#include "deep2/ReapSubmissionCompletion.hpp"
#include <cstdio>

using namespace Deep2::Submit;

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

int main() {
    static_assert(kVkSuccess == 0 && kVkTimeout == 2 && kVkErrorDeviceLost == -4,
                  "VkResult ABI drift");
    expect(Classify(0, true) == Completion::Reclaim, "raw_vk_success");
    expect(Classify(1, true) == Completion::Retain, "raw_vk_not_ready");
    expect(Classify(2, true) == Completion::Retain, "raw_vk_timeout");
    expect(Classify(3, true) == Completion::Retain, "raw_vk_event_set");
    expect(Classify(-4, true) == Completion::TerminalTeardown, "raw_vk_device_lost");
    expect(!MayReclaim(Classify(2, true)), "raw_vk_timeout_no_reclaim");

    // Confirmed pre-submit failure (submitted=false) -> Reclaim (nothing in flight).
    expect(Classify(kVkErrorDeviceLost, false) == Completion::Reclaim,
           "presubmit_failure_reclaims");
    expect(Classify(kVkTimeout, false) == Completion::Reclaim,
           "presubmit_timeout_reclaims");

    // Successful completion -> Reclaim (fence/query/cmd safe to free).
    expect(Classify(kVkSuccess, true) == Completion::Reclaim,
           "success_reclaims");
    expect(MayReclaim(Classify(kVkSuccess, true)), "success_may_reclaim");

    // Post-submit timeout -> Retain (may still be in-flight).
    expect(Classify(kVkTimeout, true) == Completion::Retain,
           "postsubmit_timeout_retains");
    expect(!MayReclaim(Classify(kVkTimeout, true)), "timeout_no_reclaim");

    // Completion unknown (other non-success after submit) -> Retain.
    expect(Classify(-5, true) == Completion::Retain,
           "unknown_error_retains");
    expect(Classify(1, true) == Completion::Retain,
           "generic_error_retains");

    // Terminal device loss -> TerminalTeardown (controlled teardown only).
    expect(Classify(kVkErrorDeviceLost, true) == Completion::TerminalTeardown,
           "device_lost_terminal_teardown");
    expect(!MayReclaim(Classify(kVkErrorDeviceLost, true)),
           "device_lost_no_reclaim");

    // MayReclaim is true ONLY for Reclaim.
    expect(MayReclaim(Completion::Reclaim), "reclaim_may_reclaim");
    expect(!MayReclaim(Completion::Retain), "retain_no_reclaim");
    expect(!MayReclaim(Completion::TerminalTeardown), "terminal_no_reclaim");

    // Win32 code 31 (ERROR_GEN_FAILURE) is NOT a Vulkan lost code; after a
    // submit it is an unknown error -> Retain (not terminal teardown).
    expect(Classify(31, true) == Completion::Retain, "win31_after_submit_retains");

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}