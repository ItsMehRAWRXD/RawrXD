#pragma once
// Native completion decisions shared by the Deep2 and device-level Vulkan paths.
// A negative result after a queue submission attempt does not establish safety.
namespace Deep2 { namespace Submit {

enum class Completion : int { Reclaim = 0, Retain = 1, TerminalTeardown = 2 };
enum : int { kVkSuccess = 0, kVkTimeout = 2, kVkErrorDeviceLost = -4 };

inline Completion Classify(int result, bool submitted) noexcept {
    if (result == kVkErrorDeviceLost) return Completion::TerminalTeardown;
    if (!submitted || result == kVkSuccess) return Completion::Reclaim;
    return Completion::Retain;
}
inline bool MayReclaim(Completion c) noexcept { return c == Completion::Reclaim; }

// These transitions operate on the root backend's existing shared-fence state.
// The caller serializes their use with the same lock as command recording.
inline bool MayReuseQuant(bool pending, bool failed, bool cleanupQuarantined) noexcept {
    return !pending && !failed && !cleanupQuarantined;
}
inline bool MayReleaseQuantPins(bool pending, bool failed) noexcept {
    return !pending && !failed;
}
// Called only AFTER attempting vkQueueSubmit. Conservatively quarantine any
// rejected submission until an independent completion/idle boundary is proven.
inline bool RecordQuantSubmit(int result, bool& pending, bool& failed) noexcept {
    pending = true;
    failed = result != kVkSuccess;
    return !failed;
}
inline bool RecordQuantWait(int result, bool& pending, bool& failed) noexcept {
    if (!pending) return false;
    const bool complete = MayReclaim(Classify(result, true));
    pending = !complete;
    failed = !complete;
    return complete;
}
// Root backend cleanup remains fail-closed on ALL unsuccessful idle waits.
// This is not a terminal-device-loss teardown authorization.
inline bool RecordIdleWait(int result, bool& cleanupQuarantined) noexcept {
    cleanupQuarantined = result != kVkSuccess;
    return !cleanupQuarantined;
}

} } // namespace Deep2::Submit
