#include "calc_engine.h"

namespace alpha {

// Extract-function target for RAWRXD_P1_REFACTOR_CHAIN_001.
//
// The cell selects the contiguous statement block on lines 15-17 and requires:
//   * the block to become a function named weightedAccumulate,
//   * its two free variables (total, s) promoted to parameters with the types
//     the enclosing function declares for them,
//   * the block to be replaced by exactly one call statement,
//   * the whole fixture to still compile and still print identical output.
double combineScored(const Series& s) {
    double total = 0.0;
    for (int i = 0; i < s.count; ++i) {
        total += s.values[i] * (i + 1);
    }
    return total / 2.0;
}

}  // namespace alpha
