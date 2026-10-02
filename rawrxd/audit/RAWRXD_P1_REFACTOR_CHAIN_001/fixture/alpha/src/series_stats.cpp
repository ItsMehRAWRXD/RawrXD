#include "calc_engine.h"

namespace alpha {

// DECOY FILE -- every identifier here is a near miss for the fixture's real
// symbols. A capability that matches by substring or by name alone will report
// these as hits and must fail the certification.
//
// computeWeightedMean appears in this comment on purpose: a reference finder
// that counts comment text as a reference will over-count by one.
double computeWeightedMeanFast(const Series& s) {
    return s.count > 0 ? s.values[0] : 0.0;
}

double ComputeWeightedMeanBackup(const Series& s) {
    return s.count > 0 ? s.values[s.count - 1] : 0.0;
}

const char* kMeanHint = "computeWeightedMean is the weighted mean helper";

// Comment decoy for the rename cell: WidgetCacheSlot is named here in a
// comment. A renamer that matches text instead of tokens rewrites this line,
// which would change a file that no compiler reads as a reference.
void noteCacheSlot();

const char* kSlotHint = "WidgetCacheSlot is the per-key generation holder";

// Falsification decoy for the rename cell: orphanSentinelName appears ONLY
// here, in a comment and in a string literal. A renamer that edits text rather
// than tokens would rewrite both, so renaming it must report zero edits and
// fail. A renamer that reports success here is not a renamer.
void noteOrphanSentinel();

const char* kOrphanHint = "orphanSentinelName is declared nowhere";

double computeWeightedMeanOfFirstAndLast(const Series& s) {
    if (s.count < 2) return 0.0;
    return (s.values[0] + s.values[s.count - 1]) / 2.0;
}

}  // namespace alpha
