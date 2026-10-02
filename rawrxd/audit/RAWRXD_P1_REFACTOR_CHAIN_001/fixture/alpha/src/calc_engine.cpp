#include "calc_engine.h"

#include <cstdlib>

namespace alpha {

// Real code occurrence of the rename target. The type name occurs once here,
// once at its definition in calc_engine.h, and once as a parameter type in
// beta/src/report_sink.cpp. The decoy occurrences in series_stats.cpp are a
// comment and a string literal and must not be touched.
WidgetCacheSlot g_slot{0, 0};

double computeWeightedMean(const Series& s) {
    double total = 0.0;
    for (int i = 0; i < s.count; ++i) {
        total += s.values[i] * (i + 1);
    }
    return s.count > 0 ? total / (s.count * (s.count + 1) / 2.0) : 0.0;
}

double normalizeByMax(const Series& s) {
    double peak = 0.0;
    for (int i = 0; i < s.count; ++i) {
        if (s.values[i] > peak) peak = s.values[i];
    }
    if (peak == 0.0) return 0.0;
    double out = 0.0;
    for (int i = 0; i < s.count; ++i) {
        out += s.values[i] / peak;
    }
    return out / s.count;
}

double medianOf(const Series& s) {
    if (s.count == 0) return 0.0;
    double copy[64];
    int n = s.count < 64 ? s.count : 64;
    for (int i = 0; i < n; ++i) copy[i] = s.values[i];
    for (int i = 1; i < n; ++i) {
        double key = copy[i];
        int j = i - 1;
        while (j >= 0 && copy[j] > key) {
            copy[j + 1] = copy[j];
            --j;
        }
        copy[j + 1] = key;
    }
    if (n % 2 == 1) return copy[n / 2];
    return (copy[n / 2 - 1] + copy[n / 2]) / 2.0;
}

}  // namespace alpha
