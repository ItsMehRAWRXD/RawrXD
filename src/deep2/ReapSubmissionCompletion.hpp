/* ReapSubmissionCompletion.hpp — Deep2 centralized submission-completion contract.
 *
 * Pure, dependency-free decision function extracted from
 * VulkanCompute::endSubmitWait so the completion/quarantine policy can be
 * CPU-tested without a physical Vulkan device. The production path consumes
 * this decision directly.
 *
 * Contract (see RawrXD Deep2 lifetime audit):
 *   Confirmed pre-submit failure -> Reclaim  (nothing in flight)
 *   Successful completion        -> Reclaim  (fence/query/cmd safe to free)
 *   Post-submit timeout          -> Retain  (may still be in-flight)
 *   Completion unknown           -> Retain  (VK_ERROR_* non-lost)
 *   Terminal device loss         -> TerminalTeardown (controlled teardown only)
 */
#pragma once

namespace Deep2 {
namespace Submit {

enum class Completion : int {
    Reclaim = 0,          // confirmed completion or pre-submit failure: free
    Retain = 1,           // timeout / unknown: keep in-flight resources
    TerminalTeardown = 2, // device lost: controlled teardown, never recycle
};

// VK result codes used by the contract (avoid a Vulkan header dependency).
enum : int {
    kVkSuccess = 0,
    kVkTimeout = 2,       // VK_TIMEOUT (VkResult ABI value)
    kVkErrorDeviceLost = -4,
};

// Classify a vkWaitForFences / vkQueueSubmit result into the completion
// decision. `submitted` distinguishes a pre-submit failure (no fence was
// signaled, nothing in flight -> Reclaim) from a post-submit wait result.
inline Completion Classify(int vkResult, bool submitted) noexcept {
    if (!submitted) return Completion::Reclaim;          // pre-submit failure
    if (vkResult == kVkSuccess) return Completion::Reclaim;
    if (vkResult == kVkErrorDeviceLost) return Completion::TerminalTeardown;
    // VK_TIMEOUT or any other non-success after submission: may be in-flight.
    return Completion::Retain;
}

// True when the completion decision permits freeing the fence/query/command
// buffer immediately (confirmed completion or nothing was submitted).
inline bool MayReclaim(Completion c) noexcept {
    return c == Completion::Reclaim;
}

} // namespace Submit
} // namespace Deep2