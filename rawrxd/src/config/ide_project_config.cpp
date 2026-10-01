// ide_project_config.cpp — RAWRXD_PER_PROJECT_CONFIG_001
//
// Replaces the one-line IDEConfig.cpp / three-line IDEConfig.h stub.

#include "ide_project_config.h"

#include <windows.h>

#include <fstream>
#include <algorithm>
#include <cstdio>

#include <nlohmann/json.hpp>

namespace RawrXD {

namespace {

// The project layer's schema. Deliberately small: these are the settings that
// genuinely differ per repository. Anything a developer sets globally belongs in
// the user layer, and duplicating it here is how two layers drift.
const char* const kKnown[] = {
    "project.name",
    "build.command",
    "build.args",
    "build.cwd",
    "test.command",
    "test.args",
    "run.command",
    "run.args",
    "run.cwd",
    "model.default",
    "model.contextTokens",
    "model.temperature",
    "tools.gitPolicy",
    "tools.network",
    "index.exclude",
};

} // namespace

const std::vector<std::string>& IDEProjectConfig::knownKeys() {
    static const std::vector<std::string> s = [] {
        std::vector<std::string> v;
        for (const char* k : kKnown) v.emplace_back(k);
        return v;
    }();
    return s;
}

ProjectConfigDiagnostics IDEProjectConfig::load(const std::string& workspaceRoot) {
    ProjectConfigDiagnostics d;
    d.loadCalled = true;
    d.projectPath = workspaceRoot + "\\.rawrxd\\project.json";
    values_.clear();
    name_.clear();

    std::ifstream file(d.projectPath);
    if (!file.is_open()) {
        d.lastError = "project config absent";
        return d;
    }
    d.fileExisted = true;

    nlohmann::json j;
    try {
        file >> j;
        d.parsed = true;
    } catch (const std::exception& ex) {
        d.refused = true;
        d.lastError = std::string("project config unparsable: ") + ex.what();
        return d;
    }

    try {
        if (j.contains("name") && j["name"].is_string()) name_ = j["name"].get<std::string>();
        d.projectName = name_;

        const nlohmann::json* p = nullptr;
        if (j.contains("settings") && j["settings"].is_object()) p = &j["settings"];
        else if (j.contains("project") && j["project"].is_object()) p = &j["project"];

        if (!p) {
            d.refused = true;
            d.lastError = "project config has no 'settings' object";
            return d;
        }

        const auto& known = knownKeys();
        for (auto it = p->begin(); it != p->end(); ++it) {
            const auto& v = it.value();
            if (v.is_object() || v.is_array()) {
                // Structured values (index.exclude is a list) are stored as JSON
                // text so a layered string API still works.
                values_[it.key()] = v.dump();
            } else if (v.is_string()) {
                values_[it.key()] = v.get<std::string>();
            } else if (v.is_boolean()) {
                values_[it.key()] = v.get<bool>() ? "1" : "0";
            } else if (v.is_number()) {
                values_[it.key()] = v.dump();
            } else {
                ++d.keysUnknown;
                continue;
            }
            if (std::find(known.begin(), known.end(), it.key()) == known.end()) {
                ++d.keysUnknown;
            }
        }
        d.keysProject = values_.size();
        return d;

    } catch (const std::exception& ex) {
        values_.clear();
        name_.clear();
        d.refused = true;
        d.lastError = std::string("project config schema error: ") + ex.what();
        return d;
    }
}

bool IDEProjectConfig::save(const std::string& workspaceRoot) const {
    const std::string dir = workspaceRoot + "\\.rawrxd";
    CreateDirectoryA(dir.c_str(), nullptr);

    const std::string path = dir + "\\project.json";

    nlohmann::json j;
    if (!name_.empty()) j["name"] = name_;
    j["settings"] = nlohmann::json::object();
    for (const auto& kv : values_) j["settings"][kv.first] = kv.second;

    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << j.dump(2);
        out.flush();
        if (!out.good()) { out.close(); DeleteFileA(tmp.c_str()); return false; }
    }
    if (!ReplaceFileA(path.c_str(), tmp.c_str(), nullptr, 0, nullptr, nullptr)) {
        if (!MoveFileExA(tmp.c_str(), path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileA(tmp.c_str());
            return false;
        }
    }
    return true;
}

bool IDEProjectConfig::hasProjectOverride(const std::string& key) const {
    return values_.find(key) != values_.end();
}

std::string IDEProjectConfig::resolve(const std::string& key,
                                     const std::string& userValue,
                                     const std::string& def) const {
    auto it = values_.find(key);
    if (it != values_.end()) return it->second;   // project wins
    if (!userValue.empty()) return userValue;    // then user
    return def;
}

} // namespace RawrXD
