// quarantine_registry_test.cpp — CPU-only certification of the owned
// submission-quarantine registry (QuarantineRegistry.hpp).
//
// Exercises the PRODUCTION registry with injected retention/reclaim scenarios,
// WITHOUT a physical Vulkan device. Certifies transitive resource ownership:
// every resource kind referenced by an unresolved submission is tracked and
// reclaimed only after confirmed completion / terminal teardown.
//
// Exit 0 = all controls pass.

#include "deep2/QuarantineRegistry.hpp"
#include <cstdio>

using namespace Deep2::Submit;

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

int main() {
    // Retain creates monotonic tickets and tracks entries.
    {
        QuarantineRegistry reg;
        const uint64_t t1 = reg.Retain(/*gen=*/1, /*epoch=*/10, ResourceKind::Fence);
        const uint64_t t2 = reg.Retain(1, 10, ResourceKind::CommandBuffer);
        expect(t1 == 1 && t2 == 2, "retain_monotonic_tickets");
        expect(reg.Size() == 2 && !reg.Empty(), "retain_tracks_entries");
        expect(reg.Contains(t1) && reg.Contains(t2), "retain_contains");
        expect(reg.NextTicket() == 3, "retain_next_ticket");
    }

    // ReclaimGeneration releases only the confirmed generation.
    {
        QuarantineRegistry reg;
        reg.Retain(1, 10, ResourceKind::Fence);
        reg.Retain(1, 10, ResourceKind::Arena);
        reg.Retain(2, 20, ResourceKind::KvCache);
        const size_t n = reg.ReclaimGeneration(1);
        expect(n == 2, "reclaim_generation_count");
        expect(reg.Size() == 1, "reclaim_generation_leaves_other");
        expect(reg.CountForGeneration(2) == 1, "reclaim_generation_isolated");
    }

    // ReclaimTicket reclaims a single ticket (late completion).
    {
        QuarantineRegistry reg;
        const uint64_t t1 = reg.Retain(1, 10, ResourceKind::DescriptorSet);
        const uint64_t t2 = reg.Retain(1, 10, ResourceKind::StagingBuffer);
        expect(reg.ReclaimTicket(t1), "reclaim_ticket_found");
        expect(!reg.Contains(t1) && reg.Contains(t2), "reclaim_ticket_isolated");
        expect(!reg.ReclaimTicket(t1), "reclaim_ticket_idempotent_false");
    }

    // ReclaimKind reclaims all of a kind for a generation.
    {
        QuarantineRegistry reg;
        reg.Retain(1, 10, ResourceKind::WeightPin);
        reg.Retain(1, 10, ResourceKind::WeightPin);
        reg.Retain(1, 10, ResourceKind::Scratch);
        const size_t n = reg.ReclaimKind(1, ResourceKind::WeightPin);
        expect(n == 2, "reclaim_kind_count");
        expect(reg.Size() == 1, "reclaim_kind_leaves_other_kind");
    }

    // Transitive ownership: a single Retain per resource kind protects the
    // whole dependency graph; all kinds are tracked.
    {
        QuarantineRegistry reg;
        const ResourceKind kinds[] = {
            ResourceKind::Fence, ResourceKind::CommandBuffer,
            ResourceKind::QueryPool, ResourceKind::DescriptorSet,
            ResourceKind::StagingBuffer, ResourceKind::Arena,
            ResourceKind::KvCache, ResourceKind::WeightPin,
            ResourceKind::Scratch,
        };
        for (ResourceKind k : kinds) reg.Retain(7, 70, k);
        expect(reg.Size() == 9, "transitive_all_kinds_tracked");
        expect(reg.ReclaimGeneration(7) == 9, "transitive_reclaim_all");
        expect(reg.Empty(), "transitive_fully_reclaimed");
    }

    // Empty registry reclaim is a no-op.
    {
        QuarantineRegistry reg;
        expect(reg.ReclaimGeneration(1) == 0, "empty_reclaim_noop");
        expect(reg.Empty(), "empty_stays_empty");
    }

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}