// ============================================================================
// LearnedProfileIo.hpp — minimal YAML for learned profiles (append to policy)
// ============================================================================
#pragma once

#include "LearnedProfile.hpp"
#include "ExecutionPolicyStore.hpp"
#include <cstdio>
#include <sstream>

namespace Deep2 {
namespace Exec {

inline std::string FormatBytesTag(uint64_t n) {
    if (n >= GB && (n % GB) == 0) return std::to_string(n / GB) + "GB";
    if (n >= MB && (n % MB) == 0) return std::to_string(n / MB) + "MB";
    return std::to_string(n) + "B";
}

inline std::string LearnedToYaml(const LearnedProfile& lp) {
    std::ostringstream o;
    o << "# Fingerprint-bound learned profile (hw × model)\n";
    o << "hardware:\n";
    o << "  fingerprint: \"" << lp.hardware.fingerprint << "\"\n";
    o << "  ram: " << FormatBytesTag(lp.hardware.ramBytes) << "\n";
    if (!lp.hardware.topologyNote.empty())
        o << "  topology: \"" << lp.hardware.topologyNote << "\"\n";
    for (const auto& g : lp.hardware.gpus) {
        o << "  gpu" << g.index << "_name: \"" << g.name << "\"\n";
        o << "  gpu" << g.index << "_vram: " << FormatBytesTag(g.vramBytes)
          << "\n";
    }
    o << "model:\n";
    o << "  fingerprint: \"" << lp.modelFingerprint << "\"\n";
    if (!lp.modelName.empty())
        o << "  name: \"" << lp.modelName << "\"\n";
    if (!lp.quant.empty())
        o << "  quant: \"" << lp.quant << "\"\n";
    o << "metrics:\n";
    o << "  tps: " << lp.metrics.tps << "\n";
    o << "  ttft_ms: " << lp.metrics.ttftMs << "\n";
    o << "  peak_vram: " << FormatBytesTag(lp.metrics.peakVramBytes) << "\n";
    o << "  peak_ram: " << FormatBytesTag(lp.metrics.peakRamBytes) << "\n";
    o << "  runs: " << lp.metrics.runs << "\n";
    o << "  successes: " << lp.metrics.successes << "\n";
    if (!lp.metrics.lastIsoTime.empty())
        o << "  last: \"" << lp.metrics.lastIsoTime << "\"\n";
    if (!lp.policySha.empty())
        o << "  policy_sha: \"" << lp.policySha << "\"\n";
    o << "\n";
    o << ExecutionPolicyStore::ToYaml(lp.policy);
    return o.str();
}

inline bool ParseBytesLoose(const std::string& raw, uint64_t& out) {
    Bytes b{};
    // Reuse store parser via tiny local copy of units.
    std::string s = raw;
    while (!s.empty() && (s.front() == ' ' || s.front() == '"')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '"')) s.pop_back();
    if (s.empty()) return false;
    char* end = nullptr;
    double v = std::strtod(s.c_str(), &end);
    if (end == s.c_str()) return false;
    std::string unit = end ? std::string(end) : "";
    for (auto& c : unit)
        c = (char)std::tolower((unsigned char)c);
    while (!unit.empty() && unit.front() == ' ') unit.erase(unit.begin());
    if (unit.empty() || unit == "b") out = (uint64_t)v;
    else if (unit == "kb" || unit == "kib") out = (uint64_t)(v * KB);
    else if (unit == "mb" || unit == "mib") out = (uint64_t)(v * MB);
    else if (unit == "gb" || unit == "gib") out = (uint64_t)(v * GB);
    else return false;
    return true;
}

} // namespace Exec
} // namespace Deep2
