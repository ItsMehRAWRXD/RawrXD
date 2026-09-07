// FusedLiveController_Emit.cpp
#include "FusedLiveController.hpp"

namespace Deep2 {

void Fused_Emit(FILE* f) {
    if (!f) f = stdout;
    const auto& c = Fused_Counters();
    const auto& d = Fused_Last();
    fprintf(f, "FUSED_ENABLED=%u\n", Fused_Enabled() ? 1u : 0u);
    fprintf(f, "FUSED_DECISIONS=%u\n", c.decisions);
    fprintf(f, "FUSED_PREFETCH_DEPTH=%u\n", d.prefetchDepth);
    fprintf(f, "FUSED_REVERSE_DEPTH=%u\n", d.reverseDepth);
    fprintf(f, "FUSED_PREFETCH_DEPTH_MAX=%u\n", c.prefetchDepthMax);
    fprintf(f, "FUSED_REVERSE_DEPTH_MAX=%u\n", c.reverseDepthMax);
    fprintf(f, "FUSED_URGENT_ACQUIRES=%u\n", c.urgentAcquires);
    fprintf(f, "FUSED_SPECULATIVE_SUPPRESSED=%u\n", c.speculativeSuppressed);
    fprintf(f, "FUSED_EVICTIONS=%u\n", c.evictions);
    fprintf(f, "FUSED_WARMUP_ENABLES=%u\n", c.warmupEnables);
    fprintf(f, "FUSED_BRAKES=%u\n", c.brakes);
    fprintf(f, "FUSED_CONFLICTS_AVOIDED=%u\n", c.conflictsAvoided);
    fprintf(f, "FUSED_PREFETCH_REQUESTS_DROPPED=%u\n", c.prefetchRequestsDropped);
    fprintf(f, "FUSED_DUPLICATE_PREFETCHES=%u\n", c.duplicatePrefetches);
    fprintf(f, "FUSED_QUEUE_PEAK=%u\n", c.queuePeak);
    fprintf(f, "FUSED_FAST_BYPASS=%u\n", c.fastBypass);
    fprintf(f, "FUSED_SIGNAL_CHANGES=%u\n", c.signalChanges);
    fprintf(f, "FUSED_POLICY_CHANGES=%u\n", c.policyChanges);
    fprintf(f, "FUSED_DECISIONS_SKIPPED=%u\n", c.decisionsSkipped);
    fprintf(f, "FUSED_DECISION_US=%llu\n", (unsigned long long)c.decisionUs);
    fprintf(f, "FUSED_BRAKE_US=%llu\n", (unsigned long long)c.brakeUs);
    fprintf(f, "FUSED_SUPPRESSION_US=%llu\n", (unsigned long long)c.suppressionUs);
    fprintf(f, "FUSED_TOTAL_CONTROL_US=%llu\n", (unsigned long long)c.totalControlUs);
    fflush(f);
}

} // namespace Deep2
