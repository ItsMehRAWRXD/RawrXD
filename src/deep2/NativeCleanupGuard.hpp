// NativeCleanupGuard.hpp — RAII ownership of a cleanup operation.
//
// Serializes cleanup callers so two threads cannot simultaneously destroy the
// same Vulkan resource hierarchy. A deferred cleanup deliberately leaves
// admission closed; it must not reopen merely because cleanup returned early.
#pragma once

#include "SubmissionLifecycle.hpp"

namespace RawrXD {
namespace Deep2 {

class NativeCleanupGuard final {
public:
    explicit NativeCleanupGuard(SubmissionLifecycle& lifecycle)
        : lifecycle_(lifecycle), acquired_(lifecycle_.BeginCleanup()) {}

    NativeCleanupGuard(const NativeCleanupGuard&) = delete;
    NativeCleanupGuard& operator=(const NativeCleanupGuard&) = delete;

    explicit operator bool() const noexcept { return acquired_; }

    bool DestructionAllowed() const { return acquired_ && lifecycle_.CanDestroyResources(); }

    bool Finish() {
        if (!acquired_) return false;
        if (!lifecycle_.FinishCleanup()) return false;
        acquired_ = false;
        return true;
    }

    ~NativeCleanupGuard() {
        if (acquired_) lifecycle_.DeferCleanup();
    }

private:
    SubmissionLifecycle& lifecycle_;
    bool acquired_ = false;
};

} // namespace Deep2
} // namespace RawrXD