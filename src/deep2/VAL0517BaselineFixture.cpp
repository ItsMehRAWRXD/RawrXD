// ============================================================================
// VAL0517BaselineFixture.cpp — Deterministic Baseline Manager
// ============================================================================

#include "VAL0517BaselineFixture.hpp"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace Deep2 {

// ============================================================================
// JSON Helpers (minimal, no external dependency)
// ============================================================================
static std::string EscapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

static std::string JsonField(const std::string& key, const std::string& value) {
    return "\"" + EscapeJson(key) + "\": \"" + EscapeJson(value) + "\"";
}

static std::string JsonField(const std::string& key, uint64_t value) {
    return "\"" + EscapeJson(key) + "\": " + std::to_string(value);
}

static std::string JsonField(const std::string& key, int value) {
    return "\"" + EscapeJson(key) + "\": " + std::to_string(value);
}

static std::string JsonField(const std::string& key, double value) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << value;
    return "\"" + EscapeJson(key) + "\": " + oss.str();
}

static std::string JsonField(const std::string& key, bool value) {
    return "\"" + EscapeJson(key) + "\": " + std::string(value ? "true" : "false");
}

static std::string JsonArray(const std::string& key, const std::vector<int>& arr) {
    std::string s = "\"" + EscapeJson(key) + "\": [";
    for (size_t i = 0; i < arr.size(); ++i) {
        if (i > 0) s += ", ";
        s += std::to_string(arr[i]);
    }
    s += "]";
    return s;
}

static std::string JsonArray(const std::string& key, const std::vector<std::string>& arr) {
    std::string s = "\"" + EscapeJson(key) + "\": [";
    for (size_t i = 0; i < arr.size(); ++i) {
        if (i > 0) s += ", ";
        s += "\"" + EscapeJson(arr[i]) + "\"";
    }
    s += "]";
    return s;
}

static std::string JsonArray(const std::string& key, const std::vector<size_t>& arr) {
    std::string s = "\"" + EscapeJson(key) + "\": [";
    for (size_t i = 0; i < arr.size(); ++i) {
        if (i > 0) s += ", ";
        s += std::to_string(arr[i]);
    }
    s += "]";
    return s;
}

// ============================================================================
// Save
// ============================================================================
bool BaselineManager::Save(const std::string& path, const BaselineSnapshot& snap) {
    std::ofstream f(path);
    if (!f.is_open()) return false;

    f << "{\n";
    f << "  " << JsonField("gitHead", snap.gitHead) << ",\n";
    f << "  " << JsonField("buildConfig", snap.buildConfig) << ",\n";
    f << "  " << JsonField("executableSha256", snap.executableSha256) << ",\n";
    f << "  " << JsonField("modelSha256", snap.modelSha256) << ",\n";
    f << "  " << JsonField("modelPath", snap.modelPath) << ",\n";
    f << "  " << JsonField("prompt", snap.prompt) << ",\n";
    f << "  " << JsonField("seed", (uint64_t)snap.seed) << ",\n";
    f << "  " << JsonField("timestamp", snap.timestamp) << ",\n";
    f << "  " << JsonField("runNumber", snap.runNumber) << ",\n";
    f << "  " << JsonField("exitCode", snap.exitCode) << ",\n";
    f << "  " << JsonArray("tokenIds", snap.tokenIds) << ",\n";
    f << "  " << JsonArray("tokenTexts", snap.tokenTexts) << ",\n";
    f << "  " << JsonField("tokensGenerated", (uint64_t)snap.tokensGenerated) << ",\n";
    f << "  " << JsonField("forwardCount", snap.forwardCount) << ",\n";
    f << "  " << JsonField("layerCount", snap.layerCount) << ",\n";
    f << "  " << JsonField("remapCount", snap.remapCount) << ",\n";
    f << "  " << JsonField("acquireCount", snap.acquireCount) << ",\n";
    f << "  " << JsonField("releaseCount", snap.releaseCount) << ",\n";
    f << "  " << JsonField("mapCount", snap.mapCount) << ",\n";
    f << "  " << JsonField("unmapCount", snap.unmapCount) << ",\n";
    f << "  " << JsonField("evictionCount", snap.evictionCount) << ",\n";
    f << "  " << JsonField("activeLeaseCount", snap.activeLeaseCount) << ",\n";
    f << "  " << JsonField("staleLeaseCount", snap.staleLeaseCount) << ",\n";
    f << "  " << JsonField("residencyErrors", snap.residencyErrors) << ",\n";
    f << "  " << JsonField("tensorAcquireFailures", snap.tensorAcquireFailures) << ",\n";
    f << "  " << JsonField("tensorReleaseFailures", snap.tensorReleaseFailures) << ",\n";
    f << "  " << JsonField("layerTransitions", snap.layerTransitions) << ",\n";
    f << "  " << JsonField("forwardTransitions", snap.forwardTransitions) << ",\n";
    f << "  " << JsonField("totalForwardMs", snap.totalForwardMs) << ",\n";
    f << "  " << JsonField("totalLayerMs", snap.totalLayerMs) << ",\n";
    f << "  " << JsonField("totalGenerationMs", snap.totalGenerationMs) << ",\n";
    f << "  " << JsonArray("positions", snap.positions) << ",\n";
    f << "  " << JsonField("positionMonotonic", snap.positionMonotonic) << ",\n";
    f << "  " << JsonField("hiddenStateFinite", snap.hiddenStateFinite) << ",\n";
    f << "  " << JsonField("logitsFinite", snap.logitsFinite) << ",\n";
    f << "  " << JsonField("nonFiniteCount", (uint64_t)snap.nonFiniteCount) << ",\n";
    f << "  " << JsonField("failureCategory", snap.failureCategory) << ",\n";
    f << "  " << JsonField("failureDetail", snap.failureDetail) << "\n";
    f << "}\n";
    return true;
}

// ============================================================================
// Load (stub — can be implemented with a JSON parser if needed)
// ============================================================================
bool BaselineManager::Load(const std::string& path, BaselineSnapshot& out) {
    // Minimal implementation: read file and extract key fields via string search
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    // TODO: proper JSON parse
    (void)content;
    (void)out;
    return false;
}

// ============================================================================
// Compare
// ============================================================================
bool BaselineManager::Compare(const BaselineSnapshot& a,
                               const BaselineSnapshot& b,
                               std::string& diffOut) {
    diffOut.clear();
    bool ok = true;

    if (!TokensEqual(a, b)) {
        diffOut += "[DIFF] Token sequences differ\n";
        ok = false;
    }
    if (!CountersEqual(a, b, diffOut)) {
        ok = false;
    }
    if (!PositionsEqual(a, b)) {
        diffOut += "[DIFF] Position sequences differ\n";
        ok = false;
    }
    if (a.hiddenStateFinite != b.hiddenStateFinite) {
        diffOut += "[DIFF] hiddenStateFinite differs\n";
        ok = false;
    }
    if (a.logitsFinite != b.logitsFinite) {
        diffOut += "[DIFF] logitsFinite differs\n";
        ok = false;
    }
    if (a.residencyErrors != b.residencyErrors) {
        diffOut += "[DIFF] residencyErrors differ\n";
        ok = false;
    }
    return ok;
}

bool BaselineManager::TokensEqual(const BaselineSnapshot& a,
                                    const BaselineSnapshot& b) {
    if (a.tokenIds.size() != b.tokenIds.size()) return false;
    for (size_t i = 0; i < a.tokenIds.size(); ++i) {
        if (a.tokenIds[i] != b.tokenIds[i]) return false;
    }
    return true;
}

bool BaselineManager::CountersEqual(const BaselineSnapshot& a,
                                     const BaselineSnapshot& b,
                                     std::string& diffOut) {
    bool ok = true;
    auto check = [&](const char* name, uint64_t av, uint64_t bv) {
        if (av != bv) {
            diffOut += std::string("[DIFF] ") + name + ": " +
                       std::to_string(av) + " vs " + std::to_string(bv) + "\n";
            return false;
        }
        return true;
    };
    ok &= check("forwardCount", a.forwardCount, b.forwardCount);
    ok &= check("layerCount", a.layerCount, b.layerCount);
    ok &= check("remapCount", a.remapCount, b.remapCount);
    ok &= check("acquireCount", a.acquireCount, b.acquireCount);
    ok &= check("releaseCount", a.releaseCount, b.releaseCount);
    ok &= check("mapCount", a.mapCount, b.mapCount);
    ok &= check("unmapCount", a.unmapCount, b.unmapCount);
    ok &= check("evictionCount", a.evictionCount, b.evictionCount);
    ok &= check("activeLeaseCount", a.activeLeaseCount, b.activeLeaseCount);
    ok &= check("staleLeaseCount", a.staleLeaseCount, b.staleLeaseCount);
    ok &= check("residencyErrors", a.residencyErrors, b.residencyErrors);
    ok &= check("tensorAcquireFailures", a.tensorAcquireFailures, b.tensorAcquireFailures);
    ok &= check("tensorReleaseFailures", a.tensorReleaseFailures, b.tensorReleaseFailures);
    ok &= check("layerTransitions", a.layerTransitions, b.layerTransitions);
    ok &= check("forwardTransitions", a.forwardTransitions, b.forwardTransitions);
    return ok;
}

bool BaselineManager::PositionsEqual(const BaselineSnapshot& a,
                                      const BaselineSnapshot& b) {
    if (a.positions.size() != b.positions.size()) return false;
    for (size_t i = 0; i < a.positions.size(); ++i) {
        if (a.positions[i] != b.positions[i]) return false;
    }
    return true;
}

// ============================================================================
// Report
// ============================================================================
std::string BaselineManager::Report(const BaselineSnapshot& snap) {
    std::string r;
    r += "VAL-051.7 Baseline Snapshot\n";
    r += "===========================\n";
    r += "Git HEAD: " + snap.gitHead + "\n";
    r += "Timestamp: " + snap.timestamp + "\n";
    r += "Run: " + std::to_string(snap.runNumber) + "\n";
    r += "Exit Code: " + std::to_string(snap.exitCode) + "\n";
    r += "Tokens Generated: " + std::to_string(snap.tokensGenerated) + "\n";
    r += "Token IDs: [";
    for (size_t i = 0; i < snap.tokenIds.size(); ++i) {
        if (i > 0) r += ", ";
        r += std::to_string(snap.tokenIds[i]);
    }
    r += "]\n";
    r += "Counters:\n";
    r += "  forwardCount=" + std::to_string(snap.forwardCount) + "\n";
    r += "  layerCount=" + std::to_string(snap.layerCount) + "\n";
    r += "  remapCount=" + std::to_string(snap.remapCount) + "\n";
    r += "  acquireCount=" + std::to_string(snap.acquireCount) + "\n";
    r += "  releaseCount=" + std::to_string(snap.releaseCount) + "\n";
    r += "  mapCount=" + std::to_string(snap.mapCount) + "\n";
    r += "  unmapCount=" + std::to_string(snap.unmapCount) + "\n";
    r += "  evictionCount=" + std::to_string(snap.evictionCount) + "\n";
    r += "  activeLeaseCount=" + std::to_string(snap.activeLeaseCount) + "\n";
    r += "  staleLeaseCount=" + std::to_string(snap.staleLeaseCount) + "\n";
    r += "  residencyErrors=" + std::to_string(snap.residencyErrors) + "\n";
    r += "  layerTransitions=" + std::to_string(snap.layerTransitions) + "\n";
    r += "  forwardTransitions=" + std::to_string(snap.forwardTransitions) + "\n";
    r += "Timing:\n";
    r += "  totalForwardMs=" + std::to_string(snap.totalForwardMs) + "\n";
    r += "  totalLayerMs=" + std::to_string(snap.totalLayerMs) + "\n";
    r += "  totalGenerationMs=" + std::to_string(snap.totalGenerationMs) + "\n";
    if (!snap.failureCategory.empty()) {
        r += "FAILURE: [" + snap.failureCategory + "] " + snap.failureDetail + "\n";
    } else {
        r += "STATUS: PASS\n";
    }
    return r;
}

std::string BaselineManager::DiffReport(const BaselineSnapshot& expected,
                                         const BaselineSnapshot& actual) {
    std::string diff;
    Compare(expected, actual, diff);
    return diff.empty() ? "EQUIVALENT\n" : diff;
}

} // namespace Deep2
