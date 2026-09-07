#pragma once
#include "../runtime/telemetry.hpp"
#include <ctime>
#include <fstream>
#include <string>
namespace rawr::product {

struct AuditRec {
    const char* tool = "";
    const char* path = "";
    int denied = 0;
    int ok = 0;
};

inline bool AuditWrite(const AuditRec& a) {
    TelemetryEnsure();
    std::ofstream out(TelemetryDir() + "\\audit.log", std::ios::app);
    if (!out) return false;
    out << "t=" << (unsigned long long)time(nullptr) << " tool=" << a.tool
        << " path=" << a.path << " denied=" << a.denied << " ok=" << a.ok
        << "\n";
    return true;
}

} // namespace rawr::product
