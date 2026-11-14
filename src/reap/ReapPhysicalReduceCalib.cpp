#include "reap/ReapPhysicalReduceCalib.hpp"

#include <fstream>
#include <sstream>

namespace RawrXD::Reap {

bool TryLoadCalibrationRanks(const std::string& path,
                             uint64_t expertsPerLayer,
                             uint64_t needRetained,
                             PhysicalCalibResult& out) {
    out = {};
    out.status = "NOT_RUN";
    if (path.empty()) {
        out.reason = "MISSING_INPUT:RAWR_REAP_CALIBRATION";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        out.reason = "MISSING_INPUT:CALIBRATION_FILE_UNREADABLE";
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#' || line[0] == '{') continue;
        std::istringstream iss(line);
        uint32_t id = 0;
        if (!(iss >> id)) continue;
        if (id >= expertsPerLayer) {
            out.ranks.clear();
            out.reason = "CALIBRATION_RANK_OOB";
            return false;
        }
        out.ranks.push_back(id);
    }
    if (out.ranks.size() < needRetained) {
        out.ranks.clear();
        out.reason = "MISSING_INPUT:CALIBRATION_RANKS_INSUFFICIENT";
        return false;
    }
    out.status = "SOURCE_WIRED_RANKS_LOADED";
    out.reason = "CALIBRATION_RANKS_LOADED_BANK_REMAP_PENDING";
    return true;
}

} // namespace RawrXD::Reap
