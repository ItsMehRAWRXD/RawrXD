#include "rawrxd/config/ConfigStore.h"

#include <filesystem>
#include <fstream>
#include <regex>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif

namespace fs = std::filesystem;

namespace rawrxd::config {
namespace {

bool hasDriveLetter(const std::string& value) {
    return value.size() >= 3 &&
           ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
           value[1] == ':' && (value[2] == '\\' || value[2] == '/');
}

} // namespace

json ConfigStore::migrate(const json& input, int fromVersion) {
    json out = input;
    if (fromVersion < 2) {
        if (!out.contains("version")) out["version"] = 2;
        if (out.contains("modelServer") && out["modelServer"].is_object()) {
            auto& ms = out["modelServer"];
            for (const char* key : {"configPath"}) {
                if (ms.contains(key) && ms[key].is_string() && hasDriveLetter(ms[key].get<std::string>())) {
                    ms[key] = "ide/model-server/config.json";
                }
            }
            for (const char* key : {"tiinyAI", "gguf", "pyre"}) {
                if (ms.contains(key) && ms[key].is_object() && ms[key].contains("command")) {
                    auto& cmd = ms[key]["command"];
                    if (cmd.is_string() && hasDriveLetter(cmd.get<std::string>())) {
                        cmd = "bin/rawrxd-model-server.exe";
                    }
                }
            }
        }
        if (out.contains("features") && out["features"].is_object() &&
            !out["features"].contains("vulkanCompute")) {
            out["features"]["vulkanCompute"] = true;
        }
    }
    return out;
}

std::vector<std::string> ConfigStore::validate(const json& document) {
    std::vector<std::string> errors;
    if (!document.is_object()) {
        errors.push_back("configuration root must be a JSON object");
        return errors;
    }
    if (!document.contains("version") || !document["version"].is_number_integer()) {
        errors.push_back("missing integer field 'version'");
    } else if (document["version"].get<int>() > kCurrentVersion) {
        errors.push_back("configuration version " + std::to_string(document["version"].get<int>()) +
                         " is newer than supported version " + std::to_string(kCurrentVersion));
    }
    if (document.contains("inference")) {
        const auto& inf = document["inference"];
        if (!inf.is_object()) {
            errors.push_back("'inference' must be an object");
        } else {
            if (inf.contains("contextSize") && (!inf["contextSize"].is_number_integer() ||
                inf["contextSize"].get<int>() < 128 || inf["contextSize"].get<int>() > 1048576)) {
                errors.push_back("inference.contextSize must be an integer in [128, 1048576]");
            }
            if (inf.contains("threads") && (!inf["threads"].is_number_integer() || inf["threads"].get<int>() < 1)) {
                errors.push_back("inference.threads must be a positive integer");
            }
        }
    }
    if (document.contains("modelServer") && document["modelServer"].is_object()) {
        for (const auto& [key, value] : document["modelServer"].items()) {
            if (value.is_string() && hasDriveLetter(value.get<std::string>())) {
                errors.push_back("modelServer." + key +
                                 " must not contain a hardcoded drive letter; use a relative path");
            }
        }
    }
    if (document.contains("features") && !document["features"].is_object()) {
        errors.push_back("'features' must be an object");
    }
    return errors;
}

ConfigResult ConfigStore::load() const {
    ConfigResult result;
    std::ifstream in(path_, std::ios::binary);
    if (!in) {
        result.status = ConfigStatus::ValidationError;
        result.diagnostics.push_back("configuration file not found: " + path_);
        return result;
    }
    json doc;
    try {
        in >> doc;
    } catch (const std::exception& e) {
        result.status = ConfigStatus::ParseError;
        result.diagnostics.push_back(std::string("invalid JSON: ") + e.what());
        return result;
    }

    const int from = doc.contains("version") && doc["version"].is_number_integer() ? doc["version"].get<int>() : 1;
    if (from < kCurrentVersion) {
        doc = migrate(doc, from);
        result.status = ConfigStatus::MigrationApplied;
    }
    result.version = doc.contains("version") ? doc["version"].get<int>() : 0;
    result.document = std::move(doc);

    auto errors = validate(result.document);
    if (!errors.empty()) {
        result.status = ConfigStatus::ValidationError;
        result.diagnostics.insert(result.diagnostics.end(), errors.begin(), errors.end());
    }
    return result;
}

bool ConfigStore::saveAtomic(const json& document) const {
    std::error_code ec;
    fs::path target(path_);
    if (!target.parent_path().empty()) fs::create_directories(target.parent_path(), ec);
    fs::path temp = target;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << document.dump(2);
        out.flush();
        if (!out) return false;
    }
#if defined(_WIN32)
    if (!MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return false;
    }
#else
    if (std::rename(temp.string().c_str(), target.string().c_str()) != 0) return false;
#endif
    return true;
}

#if defined(_WIN32)
std::string ConfigStore::protectSecret(const std::string& plaintext) {
    DATA_BLOB in{static_cast<DWORD>(plaintext.size()), const_cast<BYTE*>(reinterpret_cast<const BYTE*>(plaintext.data()))};
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"RawrXD", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return {};
    }
    std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return result;
}

std::string ConfigStore::unprotectSecret(const std::string& protectedText) {
    DATA_BLOB in{static_cast<DWORD>(protectedText.size()), const_cast<BYTE*>(reinterpret_cast<const BYTE*>(protectedText.data()))};
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return {};
    }
    std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return result;
}
#else
std::string ConfigStore::protectSecret(const std::string&) { return {}; }
std::string ConfigStore::unprotectSecret(const std::string&) { return {}; }
#endif

} // namespace rawrxd::config