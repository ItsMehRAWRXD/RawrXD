#pragma once

namespace alpha {

struct Series {
    const double* values;
    int count;
};

double computeWeightedMean(const Series& s);
double normalizeByMax(const Series& s);
double medianOf(const Series& s);

// Declared here so the fixture program can call them without the driver having to
// know which .cpp defines what.
double computeWeightedMeanFast(const Series& s);
double ComputeWeightedMeanBackup(const Series& s);
double computeWeightedMeanOfFirstAndLast(const Series& s);
double combineScored(const Series& s);

struct WidgetCacheSlot {
    int key;
    int generation;
};

void resetWidgetCacheSlot();

}  // namespace alpha
