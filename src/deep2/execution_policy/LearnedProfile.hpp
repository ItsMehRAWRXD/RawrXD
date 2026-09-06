// ============================================================================
// LearnedProfile.hpp — fingerprint-bound machine+model execution memory
// Key: hardware fingerprint × model fingerprint (never filename alone)
// ============================================================================
#pragma once

#include "ExecutionPolicy.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

struct GpuTopo {
    int index = 0;
    std::string name;
    uint64_t vramBytes = 0;
};

struct HardwareSnapshot {
    std::string fingerprint; // stable digest of topology
    std::vector<GpuTopo> gpus;
    uint64_t ramBytes = 0;
    std::string topologyNote; // e.g. "pcie4x16+x8"
};

struct RunMetrics {
    double tps = 0.0;
    double ttftMs = 0.0;
    uint64_t peakVramBytes = 0;
    uint64_t peakRamBytes = 0;
    uint32_t runs = 0;
    uint32_t successes = 0;
    std::string lastIsoTime;
};

struct LearnedProfile {
    HardwareSnapshot hardware;
    std::string modelFingerprint; // sha256:...
    std::string modelName;
    std::string quant;            // disk/file quant tag
    RunMetrics metrics;
    ExecutionPolicy policy;       // last successful placement
    std::string policySha;
    bool valid = false;
};

// Build hw fingerprint: "g0:NAME:VRAM|g1:...|ram:N"
inline std::string MakeHardwareFingerprint(const HardwareSnapshot& hw) {
    std::string s;
    for (const auto& g : hw.gpus) {
        if (!s.empty()) s += "|";
        s += "g" + std::to_string(g.index) + ":" + g.name + ":" +
             std::to_string(g.vramBytes);
    }
    s += "|ram:" + std::to_string(hw.ramBytes);
    if (!hw.topologyNote.empty())
        s += "|topo:" + hw.topologyNote;
    return s;
}

inline std::string SanitizeFp(std::string name) {
    for (char& c : name) {
        if (c == ':' || c == '/' || c == '\\' || c == '|' || c == ' ')
            c = '_';
    }
    if (name.size() > 48) name = name.substr(0, 48);
    return name;
}

} // namespace Exec
} // namespace Deep2
