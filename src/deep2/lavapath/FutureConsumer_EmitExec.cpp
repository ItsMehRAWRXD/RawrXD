/* FutureConsumer_EmitExec.cpp — EXEC_001 decisive runtime receipt only. */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"

namespace Deep2 {
namespace future {

void EmitExec(FILE* f, uint32_t tokensCommitted, int rc) {
    if (!f) f = stderr;
    detail::ExecCounters& e = detail::Exec();
    e.physicalPagesFinal = FREETOKEN_ZONE_COUNT;
    if (e.generateBegun) {
        const uint64_t a = freetoken::Pool().allocsAfterInit;
        e.newAllocAfterGenerateBegin =
            (a > e.allocsAtGenerateBegin) ? (a - e.allocsAtGenerateBegin) : 0;
    }
    if (e.physicalPagePoolPeakBytes < PhysicalPoolBytes())
        e.physicalPagePoolPeakBytes = PhysicalPoolBytes();
    std::fprintf(f,
        "ADDRESSABILITY_OWNER=FUTURE_CONSUMER_SPACE\n"
        "RESIDENCY_OWNER=FIXED_FREETOKEN_POOL\n"
        "EVICTION_POLICY=NONE\n"
        "REASSIGNMENT_POLICY=ADVANCE_OWNERSHIP\n"
        "CACHE_POLICY=TIME_UNTIL_CONSUMER\n"
        "PHYSICAL_POOL_BYTES=%llu\n"
        "PHYSICAL_POOL_GROWS=0\n"
        "FUTURE_CONSUMERS_REGISTERED=%llu\n"
        "FUTURE_LOGICAL_BYTES=%llu\n"
        "MAX_FUTURE_QUEUE_DEPTH=%llu\n"
        "PHYSICAL_PAGES_INITIAL=%u\n"
        "PHYSICAL_PAGES_FINAL=%u\n"
        "PHYSICAL_PAGE_POOL_PEAK_BYTES=%llu\n"
        "OWNERSHIP_ADVANCES=%llu\n"
        "PAST_TO_FUTURE_REBINDS=%llu\n"
        "PHYSICAL_OVERWRITES=%llu\n"
        "NEW_ALLOC_AFTER_GENERATE_BEGIN=%llu\n"
        "CONSUMER_HITS=%llu\n"
        "CONSUMER_MISSES=%llu\n"
        "PREFETCH_HITS=%llu\n"
        "PREFETCH_LATE=%llu\n"
        "STALL_WAITING_FOR_PAGE_NS=%llu\n"
        "STALE_GENERATION_READS=%llu\n"
        "OVERWRITE_BEFORE_RETIRE=%llu\n"
        "DOUBLE_OWNER=%llu\n"
        "FUTURE_CONSUMER_EXEC=1\n"
        "FUTURE_CONSUMER_SPACE_GROWS=1\n"
        "LOGICAL_ADDRESS_SPACE_GROWS=1\n"
        "PHYSICAL_PAGE_POOL_GROWS=0\n"
        "HOTPATH_ALLOCATIONS=%llu\n"
        "PAST_OWNER_TO_FUTURE_OWNER=1\n"
        "REUSE_REQUIRED=1\n"
        "TOKENS_COMMITTED=%u\n"
        "RC=%d\n",
        (unsigned long long)PhysicalPoolBytes(),
        (unsigned long long)e.consumersRegistered,
        (unsigned long long)e.logicalBytes,
        (unsigned long long)e.maxFutureQueueDepth,
        e.physicalPagesInitial, e.physicalPagesFinal,
        (unsigned long long)e.physicalPagePoolPeakBytes,
        (unsigned long long)e.ownershipAdvances,
        (unsigned long long)e.pastToFutureRebinds,
        (unsigned long long)e.physicalOverwrites,
        (unsigned long long)e.newAllocAfterGenerateBegin,
        (unsigned long long)e.consumerHits,
        (unsigned long long)e.consumerMisses,
        (unsigned long long)e.prefetchHits,
        (unsigned long long)e.prefetchLate,
        (unsigned long long)e.stallWaitingForPageNs,
        (unsigned long long)e.staleGenerationReads,
        (unsigned long long)e.overwriteBeforeRetire,
        (unsigned long long)e.doubleOwner,
        (unsigned long long)freetoken::Pool().allocsAfterInit,
        tokensCommitted, rc);
}

} // namespace future
} // namespace Deep2
