#pragma once
#include "execution_types.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::product {

struct TelemetryRecord {
    uint64_t gen = 0;
    const char* stage = "";
    uint32_t latencyMs = 0;
    int ok = 0;
};

inline std::string TelemetryDir() {
    return "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_LAYER_001";
}

inline void TelemetryEnsure() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(TelemetryDir().c_str(), nullptr);
#endif
}

inline bool TelemetryAppend(const TelemetryRecord& r) {
    TelemetryEnsure();
    std::ofstream out(TelemetryDir() + "\\trace.log", std::ios::app);
    if (!out) return false;
    out << "gen=" << r.gen << " stage=" << r.stage
        << " ms=" << r.latencyMs << " ok=" << r.ok << "\n";
    return true;
}

inline void TelemetryFromResult(const ExecutionResult& x, const char* stage) {
    TelemetryRecord r{};
    r.gen = x.gen;
    r.stage = stage;
    r.latencyMs = x.latencyMs;
    r.ok = x.ok;
    TelemetryAppend(r);
}

} // namespace rawr::product
