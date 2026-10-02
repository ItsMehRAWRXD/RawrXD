#include "report_sink.h"

// Deliberately malformed source used by the diagnostics and code-action cells.
// Two defects are authored here on known lines:
//   DEFECT_MISSING_SEMICOLON  -- declaration with no terminating ';'
//   DEFECT_UNDECLARED         -- reference to a name that is never declared
// Both must be reported by the diagnostics engine, and the missing-semicolon
// must offer a code action that removes the diagnostic when applied.

namespace beta {

double brokenSummarize(const Report& r) {
    double accumulator = 0.0
    accumulator += r.value;
    return undeclaredHelper(r.value) + accumulator;
}

}  // namespace beta
