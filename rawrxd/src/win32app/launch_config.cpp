// launch_config.cpp — RAWRXD_LAUNCH_CONFIGS_001
//
// Implementation notes:
//
// The refuse-don't-default rule for ${...} is the load-bearing decision. A
// launch configuration whose program expands to an empty string is the standard
// way a "run" appears to succeed while launching nothing, and that failure is
// indistinguishable from a working run until someone checks. So an unresolved
// variable fails the whole expansion, the configuration is dropped, and the
// reason is counted and reported.

#include "launch_config.h"

#include <windows.h>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>

#include <nlohmann/json.hpp>

namespace RawrXD::IDE {

namespace {

std::string dirNameOf(const std::string& path) {
    const std::size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return ".";
    if (slash == 0) return path.substr(0, 1);
    return path.substr(0, slash);
}

std::string baseNameOf(const std::string& path) {
    const std::size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string stripExtension(const std::string& name) {
    const std::size_t dot = name.find_last_of('.');
    return dot == std::string::npos || dot == 0 ? name : name.substr(0, dot);
}

// Extracts "${NAME}" starting at `pos` (which must point at the opening '$').
// Returns false when the text at `pos` is not a well-formed variable reference.
bool matchVariable(const std::string& s, std::size_t pos,
                   std::string& nameOut, std::size_t& afterOut) {
    if (pos + 1 >= s.size() || s[pos] != '$' || s[pos + 1] != '{') return false;
    const std::size_t close = s.find('}', pos + 2);
    if (close == std::string::npos) return false;
    nameOut = s.substr(pos + 2, close - (pos + 2));
    afterOut = close + 1;
    return true;
}

} // namespace

bool LaunchConfigAuthority::expandVariables(const std::string& in,
                                           const std::string& workspaceFolder,
                                           const std::string& currentFile,
                                           const std::map<std::string, std::string>& configValues,
                                           std::string& out,
                                           std::size_t& expanded,
                                           std::size_t& unresolved) {
    expanded = 0;
    unresolved = 0;
    std::string result;
    result.reserve(in.size() + 64);

    for (std::size_t i = 0; i < in.size();) {
        if (in[i] != '$') { result += in[i]; ++i; continue; }

        std::string name;
        std::size_t after = 0;
        if (!matchVariable(in, i, name, after)) {
            // A '$' that is not a variable reference is literal text.
            result += in[i];
            ++i;
            continue;
        }

        std::string value;
        bool ok = false;
        if (name == "workspaceFolder")            { value = workspaceFolder; ok = true; }
        else if (name == "cwd")                    { value = workspaceFolder; ok = true; }
        else if (name == "file")                   { value = currentFile;      ok = true; }
        else if (name == "fileDirname")            { value = dirNameOf(currentFile); ok = !currentFile.empty(); }
        else if (name == "fileBasename")           { value = baseNameOf(currentFile); ok = !currentFile.empty(); }
        else if (name == "fileBasenameNoExtension"){ value = stripExtension(baseNameOf(currentFile)); ok = !currentFile.empty(); }
        else if (name.rfind("env:", 0) == 0) {
            const char* v = std::getenv(name.c_str() + 4);
            if (v) { value = v; ok = true; }
        } else if (name.rfind("config:", 0) == 0) {
            const std::string key = name.substr(7);
            auto it = configValues.find(key);
            if (it != configValues.end()) { value = it->second; ok = true; }
        }

        if (!ok) {
            // Refuse the whole expansion. A partially expanded program path is
            // worse than a refused one.
            ++unresolved;
            return false;
        }
        result += value;
        ++expanded;
        i = after;
    }

    out = std::move(result);
    return true;
}

LaunchConfigDiagnostics LaunchConfigAuthority::load(const std::string& path) {
    LaunchConfigDiagnostics d;
    d.loadCalled = true;
    configs_.clear();

    std::ifstream file(path);
    if (!file.is_open()) {
        d.lastError = "launch config absent";
        return d;
    }
    d.fileExisted = true;

    nlohmann::json j;
    try {
        file >> j;
        d.parsed = true;
    } catch (const std::exception& ex) {
        d.lastError = std::string("launch config unparsable: ") + ex.what();
        d.refused = true;
        return d;
    }

    try {
        if (j.contains("version")) {
            d.version = j["version"].is_string() ? j["version"].get<std::string>() : j["version"].dump();
        }

        const nlohmann::json* arr = nullptr;
        if (j.contains("configurations") && j["configurations"].is_array()) {
            arr = &j["configurations"];
        } else if (j.is_array()) {
            arr = &j;   // bare array form
        }
        if (!arr) {
            d.lastError = "launch config has no 'configurations' array";
            d.refused = true;
            return d;
        }

        for (const auto& c : *arr) {
            ++d.entriesSeen;

            LaunchConfiguration lc;

            // Bare string form: just a program path.
            if (c.is_string()) {
                lc.program = c.get<std::string>();
                lc.name = baseNameOf(lc.program);
            } else if (c.is_object()) {
                if (c.contains("name") && c["name"].is_string()) lc.name = c["name"].get<std::string>();
                if (c.contains("type") && c["type"].is_string()) lc.type = c["type"].get<std::string>();
                if (c.contains("request") && c["request"].is_string()) {
                    lc.request = c["request"].get<std::string>() == "attach"
                                   ? LaunchRequest::Attach : LaunchRequest::Launch;
                }
                if (c.contains("program") && c["program"].is_string()) {
                    lc.program = c["program"].get<std::string>();
                }
                if (c.contains("args") && c["args"].is_array()) {
                    for (const auto& a : c["args"]) {
                        if (a.is_string()) lc.args.push_back(a.get<std::string>());
                    }
                    // "program" absent + args present: args[0] is the program,
                    // which is the compact form several tools write.
                    if (lc.program.empty() && !lc.args.empty()) {
                        lc.program = lc.args.front();
                        lc.args.erase(lc.args.begin());
                    }
                }
                if (c.contains("cwd") && c["cwd"].is_string()) lc.cwd = c["cwd"].get<std::string>();
                if (c.contains("console") && c["console"].is_string()) lc.console = c["console"].get<std::string>();
                if (c.contains("preLaunchTask") && c["preLaunchTask"].is_string())
                    lc.preLaunchTask = c["preLaunchTask"].get<std::string>();
                if (c.contains("stopAtEntry") && c["stopAtEntry"].is_boolean())
                    lc.stopAtEntry = c["stopAtEntry"].get<bool>();
                if (c.contains("noDebug") && c["noDebug"].is_boolean())
                    lc.noDebug = c["noDebug"].get<bool>();
                if (c.contains("env") && c["env"].is_object()) {
                    for (auto it = c["env"].begin(); it != c["env"].end(); ++it) {
                        const auto& v = it.value();
                        if      (v.is_string())  lc.env[it.key()] = v.get<std::string>();
                        else if (v.is_boolean()) lc.env[it.key()] = v.get<bool>() ? "1" : "0";
                        else if (v.is_number())  lc.env[it.key()] = v.dump();
                    }
                }
            } else {
                ++d.entriesRefused;
                continue;
            }

            if (lc.name.empty()) lc.name = baseNameOf(lc.program);
            if (lc.program.empty()) {
                // Refuse rather than adopt an entry that cannot launch anything.
                ++d.entriesRefused;
                if (d.lastError.empty())
                    d.lastError = "entry '" + lc.name + "' has no program";
                continue;
            }
            configs_.push_back(lc);
            ++d.entriesAdopted;
        }

        if (d.entriesAdopted == 0) {
            d.refused = true;
            if (d.lastError.empty()) d.lastError = "no usable launch configurations";
        }
        return d;

    } catch (const std::exception& ex) {
        configs_.clear();
        d.refused = true;
        d.lastError = std::string("launch config schema error: ") + ex.what();
        return d;
    }
}

void LaunchConfigAuthority::resolve(const std::string& workspaceFolder,
                                    const std::string& currentFile,
                                    const std::map<std::string, std::string>& configValues) {
    for (auto& lc : configs_) {
        std::size_t exp = 0, unres = 0;
        std::string out;

        // program: refusal here means the configuration is unusable.
        if (!expandVariables(lc.program, workspaceFolder, currentFile, configValues, out, exp, unres)) {
            lc.program.clear();
        } else {
            lc.program = out;
        }
        for (std::size_t i = 0; i < lc.args.size(); ++i) {
            if (!expandVariables(lc.args[i], workspaceFolder, currentFile, configValues, out, exp, unres)) {
                lc.args[i].clear();
            } else {
                lc.args[i] = out;
            }
        }
        if (!lc.cwd.empty() &&
            expandVariables(lc.cwd, workspaceFolder, currentFile, configValues, out, exp, unres)) {
            lc.cwd = out;
        }
        if (!lc.preLaunchTask.empty() &&
            expandVariables(lc.preLaunchTask, workspaceFolder, currentFile, configValues, out, exp, unres)) {
            lc.preLaunchTask = out;
        }
        for (auto& e : lc.env) {
            if (expandVariables(e.second, workspaceFolder, currentFile, configValues, out, exp, unres)) {
                e.second = out;
            }
        }
    }
}

std::size_t LaunchConfigAuthority::dropUnresolved(std::string* firstReason) {
    std::size_t dropped = 0;
    std::vector<LaunchConfiguration> kept;
    kept.reserve(configs_.size());
    for (auto& lc : configs_) {
        if (lc.program.empty()) {
            ++dropped;
            if (firstReason && firstReason->empty()) {
                *firstReason = "launch configuration '" + lc.name +
                               "' did not resolve to a program";
            }
            continue;
        }
        kept.push_back(lc);
    }
    configs_.swap(kept);
    return dropped;
}

bool LaunchConfigAuthority::has(const std::string& name) const {
    return find(name) != nullptr;
}

const LaunchConfiguration* LaunchConfigAuthority::find(const std::string& name) const {
    for (const auto& lc : configs_) {
        if (lc.name == name) return &lc;
    }
    return nullptr;
}

std::vector<std::string> LaunchConfigAuthority::names() const {
    std::vector<std::string> out;
    out.reserve(configs_.size());
    for (const auto& lc : configs_) out.push_back(lc.name);
    return out;
}

bool LaunchConfigAuthority::save(const std::string& path) const {
    nlohmann::json j;
    j["version"] = "0.2.0";
    j["configurations"] = nlohmann::json::array();

    for (const auto& lc : configs_) {
        nlohmann::json c;
        c["name"]    = lc.name;
        if (!lc.type.empty()) c["type"] = lc.type;
        c["request"] = lc.request == LaunchRequest::Attach ? "attach" : "launch";
        c["program"] = lc.program;
        if (!lc.args.empty())     c["args"] = lc.args;
        if (!lc.cwd.empty())      c["cwd"]  = lc.cwd;
        c["console"] = lc.console;
        if (!lc.preLaunchTask.empty()) c["preLaunchTask"] = lc.preLaunchTask;
        if (lc.stopAtEntry) c["stopAtEntry"] = true;
        if (lc.noDebug)     c["noDebug"] = true;
        if (!lc.env.empty()) {
            c["env"] = nlohmann::json::object();
            for (const auto& e : lc.env) c["env"][e.first] = e.second;
        }
        j["configurations"].push_back(c);
    }

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

} // namespace RawrXD::IDE
