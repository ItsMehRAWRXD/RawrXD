#pragma once

// Calibration-ranked expert retention surface (Tip15/16 gates).
// Absent/invalid input => NOT_RUN (never invent calibrated ranks). PROMOTE=0.

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD::Reap {

struct PhysicalCalibResult {
    std::string status = "NOT_RUN";
    std::string reason;
    std::vector<uint32_t> ranks;
};

// Loads ranks only. Returns true iff file yields enough valid ids.
// Does NOT switch selection_policy to CALIBRATED (bank remap NEXT_GATE).
bool TryLoadCalibrationRanks(const std::string& path,
                             uint64_t expertsPerLayer,
                             uint64_t needRetained,
                             PhysicalCalibResult& out);

} // namespace RawrXD::Reap
