/* FutureConsumer_Notes.cpp — EXEC_001 counter notes (no emit). */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"

namespace Deep2 {
namespace future {

void MarkGenerateBegin() {
    if (!detail::Live()) InitFromPhysicalPool();
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::ExecCounters& e = detail::Exec();
    e.generateBegun = true;
    e.physicalPagesInitial = FREETOKEN_ZONE_COUNT;
    e.physicalPagePoolPeakBytes = PhysicalPoolBytes();
    e.allocsAtGenerateBegin = freetoken::Pool().allocsAfterInit;
}

void NoteConsumerHit() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Exec().consumerHits++;
}
void NoteConsumerMiss() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Exec().consumerMisses++;
}
void NotePrefetchHit() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Exec().prefetchHits++;
}
void NotePrefetchLate() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Exec().prefetchLate++;
}
void NoteStallNs(uint64_t ns) {
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Exec().stallWaitingForPageNs += ns;
}
void NoteStaleGenerationRead() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Exec().staleGenerationReads++;
}

void NotePhysicalOverwrite(uint32_t pageIdx) {
    if (!detail::Live() || pageIdx >= FREETOKEN_ZONE_COUNT) return;
    std::lock_guard<std::mutex> lock(detail::Mu());
    (void)pageIdx;
    detail::Exec().physicalOverwrites++;
}

} // namespace future
} // namespace Deep2
