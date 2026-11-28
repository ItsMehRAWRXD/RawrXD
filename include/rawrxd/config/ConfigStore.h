#pragma once

#include <string>
#include <vector>

#include "nlohmann/json.hpp"

namespace rawrxd::config {

using nlohmann::json;

enum class ConfigStatus {
    Ok,
    ParseError,
    ValidationError,
    MigrationApplied
};

struct ConfigResult {
    ConfigStatus status = ConfigStatus::Ok;
    int version = 0;
    std::vector<std::string> diagnostics;
    json document;
};

// Versioned, validated, atomically persisted runtime configuration (M-CFG-03).
class ConfigStore {
public:
    static constexpr int kCurrentVersion = 2;

    explicit ConfigStore(std::string path) : path_(std::move(path)) {}

    ConfigResult load() const;
    bool saveAtomic(const json& document) const;

    static json migrate(const json& input, int fromVersion);
    static std::vector<std::string> validate(const json& document);
    static std::string protectSecret(const std::string& plaintext);
    static std::string unprotectSecret(const std::string& protectedText);

    const std::string& path() const { return path_; }

private:
    std::string path_;
};

} // namespace rawrxd::config