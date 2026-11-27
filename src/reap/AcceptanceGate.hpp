// AcceptanceGate.hpp — RAWRXD A02/A04 objective-derived acceptance (testable).
// Derives expected artifacts from the objective and verifies they were created
// this session. Rejects stale/pre-existing artifacts and wrong-objective outputs.
// Storage-independent; no RNG.
#pragma once
#include <string>
#include <set>
#include <vector>
#include <algorithm>

namespace RawrXD::Reap {

struct AcceptanceSpec { std::string src, exe; bool hasExe = false; };

inline AcceptanceSpec DeriveExpected(const std::string& objective) {
    AcceptanceSpec s;
    auto findExt = [&](const std::string& ext) -> std::string {
        size_t p = objective.find(ext);
        if (p == std::string::npos) return {};
        size_t b = objective.rfind(' ', p);
        b = (b == std::string::npos) ? 0 : b + 1;
        return objective.substr(b, p - b + ext.size());
    };
    s.src = findExt(".cpp");
    s.exe = findExt(".exe");
    s.hasExe = !s.exe.empty();
    return s;
}

inline bool CreatedThisSession(const std::string& name, const std::set<std::string>& startFiles) {
    return !name.empty() && startFiles.find(name) == startFiles.end();
}

// A04: verify objective-derived acceptance. `exists` = file exists now.
inline bool VerifyAcceptance(const AcceptanceSpec& spec, bool srcExists, bool exeExists,
                             bool srcCreated, bool exeCreated, bool srcHasApi, bool compiled) {
    if (spec.src.empty()) return false;                 // ambiguous objective
    if (!srcExists || !srcCreated) return false;        // missing or stale source
    if (!srcHasApi) return false;                        // wrong functionality
    if (spec.hasExe && (!exeExists || !exeCreated || !compiled)) return false;  // stale/failed exe
    return true;
}

} // namespace RawrXD::Reap