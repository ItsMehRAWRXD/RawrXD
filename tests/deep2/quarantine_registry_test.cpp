// quarantine_registry_test.cpp — CPU-only certification of the owned
// submission-quarantine registry (QuarantineRegistry.hpp).
//
// Exercises the PRODUCTION registry with injected retention/reclaim scenarios,
// WITHOUT a physical Vulkan device. Certifies:
//   - Retain stores actual native deleters (not just kind tags)
//   - Reclaim EXECUTES the deleter (native destruction) and ordering
//   - ConfirmIdle is required before ReclaimGeneration
//   - Retain is fail-closed on capacity exhaustion (no terminate)
//   - Thread-safe concurrent access
//   - ReclaimTicket executes the specific deleter (late completion)
//
// Exit 0 = all controls pass.

#include "deep2/QuarantineRegistry.hpp"
#include <cstdio>
#include <thread>
#include <type_traits>
#include <vector>

using namespace Deep2::Submit;

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

// Mock native deleters that record invocation + ordering.
static int g_destroyCount = 0;
static std::vector<int> g_destroyOrder;

static void mockDeleter(void* ctx) {
    const int id = *static_cast<int*>(ctx);
    ++g_destroyCount;
    g_destroyOrder.push_back(id);
}

static void resetCounters() {
    g_destroyCount = 0;
    g_destroyOrder.clear();
}

int main() {
    // Retain stores actual deleters; Reclaim EXECUTES them (native destruction).
    {
        QuarantineRegistry reg;
        int id1 = 1, id2 = 2, id3 = 3;
        resetCounters();
        const uint64_t t1 = reg.Retain(1, 10, ResourceKind::Fence, mockDeleter, &id1);
        const uint64_t t2 = reg.Retain(1, 10, ResourceKind::CommandBuffer, mockDeleter, &id2);
        const uint64_t t3 = reg.Retain(1, 10, ResourceKind::Arena, mockDeleter, &id3);
        expect(t1 == 1 && t2 == 2 && t3 == 3, "retain_monotonic_tickets");
        expect(reg.Size() == 3, "retain_tracks_entries");

        // Reclaim requires ConfirmIdle evidence first.
        expect(reg.ReclaimGeneration(1) == 0, "reclaim_without_confirm_refused");
        expect(reg.Size() == 3, "reclaim_without_confirm_keeps_entries");

        reg.ConfirmIdle(1);
        const size_t n = reg.ReclaimGeneration(1);
        expect(n == 3, "reclaim_generation_count");
        expect(g_destroyCount == 3, "reclaim_executes_deleters");   // native destruction
        expect(g_destroyOrder == std::vector<int>({1, 2, 3}), "reclaim_destruction_order");
        expect(reg.Empty(), "reclaim_empties_registry");
    }

    // ConfirmIdle is generation-scoped.
    {
        QuarantineRegistry reg;
        int id1 = 1, id2 = 2;
        resetCounters();
        reg.Retain(1, 10, ResourceKind::Fence, mockDeleter, &id1);
        reg.Retain(2, 20, ResourceKind::Arena, mockDeleter, &id2);
        reg.ConfirmIdle(1);
        expect(reg.ReclaimGeneration(1) == 1, "reclaim_gen1_count");
        expect(reg.Size() == 1, "reclaim_gen1_isolated");
        expect(g_destroyOrder == std::vector<int>({1}), "reclaim_gen1_only_destroys_gen1");
        // Gen 2 not confirmed -> refused.
        expect(reg.ReclaimGeneration(2) == 0, "reclaim_gen2_without_confirm_refused");
    }

    // ReclaimTicket enforces completion evidence (late completion).
    {
        QuarantineRegistry reg;
        int id1 = 1, id2 = 2;
        resetCounters();
        const uint64_t t1 = reg.Retain(1, 10, ResourceKind::DescriptorSet, mockDeleter, &id1);
        const uint64_t t2 = reg.Retain(1, 10, ResourceKind::StagingBuffer, mockDeleter, &id2);
        // Without ConfirmIdle -> refused (completion evidence required).
        expect(!reg.ReclaimTicket(t1), "reclaim_ticket_without_confirm_refused");
        expect(g_destroyCount == 0, "reclaim_ticket_without_confirm_no_destroy");
        expect(reg.Contains(t1), "reclaim_ticket_without_confirm_keeps_entry");
        // With ConfirmIdle -> reclaims the specific ticket.
        reg.ConfirmIdle(1);
        expect(reg.ReclaimTicket(t1), "reclaim_ticket_found");
        expect(g_destroyOrder == std::vector<int>({1}), "reclaim_ticket_executes_deleter");
        expect(!reg.Contains(t1) && reg.Contains(t2), "reclaim_ticket_isolated");
        expect(!reg.ReclaimTicket(t1), "reclaim_ticket_idempotent_false");
        expect(g_destroyCount == 1, "reclaim_ticket_no_double_destroy");
    }

    // Capacity exhaustion is fail-closed: Retain returns 0 AND does not register
    // the resource (caller retains ownership of the unregistered resource).
    {
        QuarantineRegistry reg;
        int dummy = 0;
        for (size_t i = 0; i < 4096; ++i)
            reg.Retain(1, 1, ResourceKind::Fence, mockDeleter, &dummy);
        const size_t before = reg.Size();
        const uint64_t overflow = reg.Retain(1, 1, ResourceKind::Fence, mockDeleter, &dummy);
        expect(overflow == 0, "capacity_overflow_returns_zero");
        expect(reg.Size() == before, "capacity_overflow_not_registered");
    }

    // Fail-closed capacity: Retain returns 0 when full (no terminate).
    {
        QuarantineRegistry reg;
        int dummy = 0;
        uint64_t lastTicket = 0;
        for (size_t i = 0; i < 4096; ++i)
            lastTicket = reg.Retain(1, 1, ResourceKind::Fence, mockDeleter, &dummy);
        expect(lastTicket != 0, "capacity_fills_to_limit");
        const uint64_t overflow = reg.Retain(1, 1, ResourceKind::Fence, mockDeleter, &dummy);
        expect(overflow == 0, "capacity_overflow_returns_zero");
        expect(reg.Size() == 4096, "capacity_no_growth_beyond_limit");
    }

    // Thread-safe concurrent Retain (no corruption, no crash).
    {
        QuarantineRegistry reg;
        int dummy = 0;
        std::vector<std::thread> threads;
        for (int t = 0; t < 8; ++t) {
            threads.emplace_back([&] {
                for (int i = 0; i < 100; ++i)
                    reg.Retain(1, 1, ResourceKind::Scratch, mockDeleter, &dummy);
            });
        }
        for (auto& th : threads) th.join();
        expect(reg.Size() == 800, "concurrent_retain_all_counted");
    }

    // Non-copyable is enforced at compile time (deleted copy ctor). A static
    // assertion documents the contract.
    static_assert(!std::is_copy_constructible<QuarantineRegistry>::value,
                  "registry_must_be_noncopyable");
    static_assert(!std::is_copy_assignable<QuarantineRegistry>::value,
                  "registry_must_be_noncopy_assignable");
    expect(true, "noncopyable_contract");

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}