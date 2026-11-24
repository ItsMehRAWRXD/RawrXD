// =============================================================================
// coverage_report.h — T2 coverage parsing (TOP50 T2), dependency-free.
// =============================================================================
// Parses lcov .info traces and llvm-cov summary JSON into per-file line
// coverage percentages. The IDE bridge surfaces low-coverage files in the
// Problems panel; the CLI prints a report.
// =============================================================================
#pragma once
#include <string>
#include <vector>

namespace rawrxd::testing {

struct FileCoverage {
    std::string file;
    int lines_found = 0;
    int lines_hit = 0;
    double percent() const {
        return lines_found > 0 ? (100.0 * lines_hit / lines_found) : 0.0;
    }
};

class CoverageReport {
public:
    // Parse an lcov .info file. Returns false if the file is missing.
    bool LoadLcov(const std::string& path);

    // Parse an llvm-cov JSON export ({"data":[{"files":[{"filename":...,
    // "summary":{"lines":{"covered":N,"count":M}}}]}]}) — minimal reader.
    bool LoadLlvmJson(const std::string& path);

    const std::vector<FileCoverage>& Files() const { return files_; }
    double OverallPercent() const;

    static std::string ToJson(const std::vector<FileCoverage>& files);

private:
    std::vector<FileCoverage> files_;
};

}  // namespace rawrxd::testing