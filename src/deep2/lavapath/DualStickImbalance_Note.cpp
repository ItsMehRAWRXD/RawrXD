/* DualStickImbalance_Note.cpp — wall/n feed HARD OFF. ≤99. */
#include "DualStickImbalance.hpp"

namespace Deep2 {

void DualStickImbalanceNoteExperts(int layer, unsigned stick,
                                   const int32_t* experts, uint32_t n,
                                   uint64_t wallNs, uint64_t h2dNs,
                                   uint64_t queueNs) {
    /* ATTRIBUTABLE_SAMPLES_ONLY=1: never decompose stick wall into
       fake per-expert kernel samples. Stick-level V6 Observe only. */
    (void)layer;
    (void)stick;
    (void)experts;
    (void)n;
    (void)wallNs;
    (void)h2dNs;
    (void)queueNs;
}

} // namespace Deep2
