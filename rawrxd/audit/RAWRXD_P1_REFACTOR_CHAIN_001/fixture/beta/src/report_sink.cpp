#include "report_sink.h"

#include "calc_engine.h"

namespace beta {

// Cross-root reference to alpha::computeWeightedMean. Two uses below, so the
// complete reference set is: declaration, definition, and these two call sites.
double summarizeReport(const Report& r) {
    alpha::Series s;
    double single[1];
    single[0] = r.value;
    s.values = single;
    s.count = 1;
    double weighted = alpha::computeWeightedMean(s);
    return weighted * 2.0 + (double)r.label[0];
}

double summarizeReportPair(const Report& a, const Report& b) {
    alpha::Series s;
    double pair[2];
    pair[0] = a.value;
    pair[1] = b.value;
    s.values = pair;
    s.count = 2;
    return alpha::computeWeightedMean(s);
}

// Cross-root reference to the rename target: the third and final code
// occurrence of WidgetCacheSlot in the workspace.
double summarizeWithSlot(const Report& r, const alpha::WidgetCacheSlot& slot) {
    return r.value * (double)slot.generation;
}

}  // namespace beta
