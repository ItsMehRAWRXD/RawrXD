#pragma once
/* Shared Space accessors for FutureConsumer TUs. */
#include "FutureConsumerSpace.hpp"
#include <mutex>

namespace Deep2 {
namespace future {
namespace detail {

struct ExecCounters {
    uint64_t consumersRegistered = 0;
    uint64_t logicalBytes = 0;
    uint64_t maxFutureQueueDepth = 0;
    uint32_t physicalPagesInitial = 0;
    uint32_t physicalPagesFinal = 0;
    uint64_t physicalPagePoolPeakBytes = 0;
    uint64_t ownershipAdvances = 0;
    uint64_t pastToFutureRebinds = 0;
    uint64_t physicalOverwrites = 0;
    uint64_t allocsAtGenerateBegin = 0;
    uint64_t newAllocAfterGenerateBegin = 0;
    uint64_t consumerHits = 0;
    uint64_t consumerMisses = 0;
    uint64_t prefetchHits = 0;
    uint64_t prefetchLate = 0;
    uint64_t stallWaitingForPageNs = 0;
    uint64_t staleGenerationReads = 0;
    uint64_t overwriteBeforeRetire = 0;
    uint64_t doubleOwner = 0;
    uint64_t queueDepthNow = 0;
    bool     generateBegun = false;
};

uint64_t& ConsumerN();
uint64_t& LogicalCursor();
uint64_t& OwnershipAdvances();
bool& Live();
PhysicalPage* Pages();
FutureConsumer* Consumers();
ExecCounters& Exec();
std::mutex& Mu();

} // namespace detail
} // namespace future
} // namespace Deep2
