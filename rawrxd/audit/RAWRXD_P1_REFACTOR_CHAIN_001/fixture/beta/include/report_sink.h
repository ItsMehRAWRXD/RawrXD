#pragma once

namespace beta {

struct Report {
    const char* label;
    double value;
};

double summarizeReport(const Report& r);
double summarizeReportPair(const Report& a, const Report& b);

double passthrough(const Report& r);
double second(const Report& r);

}  // namespace beta
