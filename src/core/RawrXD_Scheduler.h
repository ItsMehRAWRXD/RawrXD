// ============================================================================
// RawrXD_Scheduler.h — Sovereign Real-Time Thread Lease & Telemetry
// ============================================================================
// Zero-overhead RAII wrapper around MASM scheduler primitives.
// Provides lazy, on-demand thread priority escalation with automatic restore.
// ============================================================================

#pragma once
#include <cstdint>
#include <atomic>

extern "C" {
    // MASM64 exports from RAWRXD_SCHEDULER.asm
    void RawrSched_EnterLease(void* pCtx, int32_t targetPriority, uint64_t targetAffinity);
    void RawrSched_ExitLease(void* pCtx);
    uint64_t RawrSched_ReadCycles();
}

namespace RawrXD {

    // Binary layout must match RAWRXD_SCHEDULER.asm expectations exactly
    struct alignas(8) ThreadLeaseContext {
        int32_t  originalPriority{0};
        uint32_t pad0{0};
        uint64_t originalAffinity{0};
        uint64_t startTSC{0};
        uint64_t accumulatedCycles{0};
        uint32_t leaseActive{0};
        uint32_t pad1{0};
    };

    enum class PriorityTier : int32_t {
        Normal       = 0,   // THREAD_PRIORITY_NORMAL
        AboveNormal  = 1,   // THREAD_PRIORITY_ABOVE_NORMAL
        Highest      = 2,   // THREAD_PRIORITY_HIGHEST
        TimeCritical = 15   // THREAD_PRIORITY_TIME_CRITICAL
    };

    // ============================================================================
    // PerformanceLease — RAII thread priority escalation
    // ============================================================================
    class [[nodiscard]] PerformanceLease {
    public:
        explicit PerformanceLease(
            PriorityTier tier = PriorityTier::TimeCritical,
            uint64_t coreAffinityMask = 0) noexcept
        {
            m_ctx.startTSC = RawrSched_ReadCycles();
            RawrSched_EnterLease(&m_ctx, static_cast<int32_t>(tier), coreAffinityMask);
        }

        ~PerformanceLease() noexcept {
            if (m_ctx.leaseActive) {
                RawrSched_ExitLease(&m_ctx);
            }
        }

        // Non-copyable, non-movable to preserve stack-bound lease semantics
        PerformanceLease(const PerformanceLease&) = delete;
        PerformanceLease& operator=(const PerformanceLease&) = delete;
        PerformanceLease(PerformanceLease&&) = delete;
        PerformanceLease& operator=(PerformanceLease&&) = delete;

        [[nodiscard]] uint64_t elapsedCycles() const noexcept {
            return m_ctx.accumulatedCycles;
        }

        [[nodiscard]] bool isActive() const noexcept {
            return m_ctx.leaseActive != 0;
        }

    private:
        ThreadLeaseContext m_ctx{};
    };

} // namespace RawrXD
