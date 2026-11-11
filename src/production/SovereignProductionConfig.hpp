#pragma once
/**
 * @file SovereignProductionConfig.hpp
 * @brief Centralised, dependency-free configuration for production hardening.
 *
 * Design rules for a source drop:
 *   - No configuration secret is ever read from a source file. Values resolve
 *     Default -> config file -> environment variable -> CLI override.
 *   - Every field is validated at load time; a bad or missing required field
 *     is reported by name rather than silently defaulted.
 *   - Environment variables are the supported deployment path so the same
 *     binary runs in dev/staging/prod unchanged.
 */

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace Sovereign::Production {

/// Strongly typed configuration value. std::chrono durations are first-class
/// because almost every production knob is a timeout.
using ConfigValue = std::variant<
    std::string,
    int64_t,
    double,
    bool,
    std::chrono::milliseconds
>;

enum class ConfigSource {
    Default = 0,
    ConfigFile = 1,
    EnvironmentVariable = 2,
    CommandLine = 3
};

struct ValidationResult {
    bool valid = true;
    std::string name;          // section.key of the offender
    std::string message;       // human readable reason
};

class ConfigManager;

/// Describes a single configuration field so the manager can validate and
/// document it, and so a misconfiguration has somewhere to live.
struct ConfigField {
    std::string section;
    std::string key;
    std::string description;
    bool required = false;
    std::string env_var;                      // e.g. RAWRXD_HTTP_TIMEOUT_MS
    ConfigValue default_value;
    std::optional<int64_t> min_int;
    std::optional<int64_t> max_int;
    std::optional<double> min_real;
    std::optional<double> max_real;
    std::optional<std::vector<std::string>> allowed;
};

/// Schema section: declare fields, and the manager owns the rest.
/// `field()` returns the schema so declarations chain fluently:
///   ConfigSchema("logging").field("level", "RAWRXD_LOG_LEVEL", "info",
///                               "minimum emitted log level")
///                           .field("max_files", "RAWRXD_LOG_MAX_FILES", 8,
///                                "rotated files to retain", false,
///                                ConfigSchema::limits().max(100));
class ConfigSchema {
public:
    /// Optional validation limits for a field. Default-constructed means
    /// "no constraint", so every field stays declarative.
    struct Limits {
        std::optional<int64_t> min_int;
        std::optional<int64_t> max_int;
        std::optional<double> min_real;
        std::optional<double> max_real;
        std::vector<std::string> allowed;

        /// Chainable builders so limits read as `limits().min_int64(1).max_int64(100)`.
        /// The numeric overloads are named by type because a single-letter
        /// overload set for min/max is ambiguous with integer literals.
        Limits& min_int64(int64_t v) {
            min_int = v;
            return *this;
        }
        Limits& max_int64(int64_t v) {
            max_int = v;
            return *this;
        }
        Limits& min_double(double v) {
            min_real = v;
            return *this;
        }
        Limits& max_double(double v) {
            max_real = v;
            return *this;
        }
        Limits& one_of(std::vector<std::string> values) {
            allowed = std::move(values);
            return *this;
        }
    };

    static Limits limits() { return Limits{}; }

    explicit ConfigSchema(std::string section) : section_(std::move(section)) {}

    /// Declares a field. `env` is the environment variable consulted for this
    /// field; pass "" to make it file/CLI only.
    ConfigSchema& field(std::string key, std::string env,
                    ConfigValue default_value, std::string description,
                    bool required = false, Limits limits = {});

    const std::string& name() const { return section_; }
    const std::vector<ConfigField>& fields() const { return fields_; }

private:
    std::string section_;
    std::vector<ConfigField> fields_;
};

/// Thrown when a required or invalid field is detected at startup. Failing here
/// is deliberate: a misspelled timeout must not silently become 0 ms.
class ConfigError : public std::runtime_error {
public:
    explicit ConfigError(const std::string& what)
        : std::runtime_error(what) {}
};

class ConfigManager {
public:
    static ConfigManager& instance() {
        static ConfigManager inst;
        return inst;
    }

    /// Registers the built-in RawrXD production schema.
    void install_default_schema();

    /// Adds (or merges) a schema. Called by subsystem initialisers.
    void add_schema(ConfigSchema schema);

    /// Loads a JSON file. Missing file is an error unless allow_missing.
    void load_file(const std::filesystem::path& path, bool allow_missing = false);

    /// Applies environment overrides to every field that declares an env var.
    void apply_environment(char* const* environ_var = nullptr);

    /// Applies "--section.key=value" CLI overrides.
    void apply_command_line(const std::vector<std::string>& args);

    /// Validates all fields, returning every problem found. All problems are
    /// collected (not just the first) so one run reports the whole config.
    std::vector<ValidationResult> validate() const;

    /// Same as validate(), but throws ConfigError on the first problem. Called
    /// from ProductionRuntime::init() so a broken deploy never starts serving.
    void validate_or_throw() const;

    template <typename T>
    std::optional<T> get(const std::string& section, const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return get_unlocked<T>(section, key);
    }

    template <typename T>
    T get_or(const std::string& section, const std::string& key, T fallback) const {
        if (auto v = get<T>(section, key)) return *v;
        return fallback;
    }

    std::string get_string(const std::string& section, const std::string& key) const {
        return get_or<std::string>(section, key, std::string{});
    }
    int64_t get_int(const std::string& section, const std::string& key) const {
        return get_or<int64_t>(section, key, 0);
    }
    double get_real(const std::string& section, const std::string& key) const {
        return get_or<double>(section, key, 0.0);
    }
    bool get_bool(const std::string& section, const std::string& key) const {
        return get_or<bool>(section, key, false);
    }
    std::chrono::milliseconds get_duration(const std::string& section,
                                           const std::string& key) const {
        return get_or<std::chrono::milliseconds>(section, key,
                                                 std::chrono::milliseconds{0});
    }

    /// True once a config file or env var supplied a value (i.e. the operator
    /// configured this subsystem rather than relying on defaults).
    bool was_explicitly_configured(const std::string& section,
                                   const std::string& key) const;

    /// Stable dump of effective config, for `--dump-config` and bug reports.
    /// Secret-like values (keys, tokens) are redacted by key name.
    std::string dump(bool redact = true) const;

    void set(const std::string& section, const std::string& key, ConfigValue value);

    /// Returns a short fingerprint of the effective configuration used in
    /// startup logs so two builds can be compared without diffing secrets.
    std::string config_fingerprint() const;

private:
    ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    template <typename T>
    std::optional<T> get_unlocked(const std::string& section,
                                  const std::string& key) const {
        auto s = values_.find(section);
        if (s == values_.end()) return std::nullopt;
        auto k = s->second.find(key);
        if (k == s->second.end()) return std::nullopt;
        if (auto* p = std::get_if<T>(&k->second.value)) return *p;
        return std::nullopt;
    }

    struct EffectiveValue {
        ConfigValue value;
        ConfigSource source = ConfigSource::Default;
    };

    // schema_ is append-only and only mutated during setup, but reads happen
    // on arbitrary threads, hence the shared mutex usage below.
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, ConfigField>>
        schema_;
    std::unordered_map<std::string, std::unordered_map<std::string, EffectiveValue>>
        values_;

    void apply_field_defaults_locked(const std::string& section,
                                      const ConfigField& f);
    static bool looks_secret(std::string_view key);
    static std::string to_string(const ConfigValue& v);
};

/// Loads a config file path from RAWRXD_CONFIG (or --config), if present.
std::filesystem::path ConfigManager_AutoDiscover();

} // namespace Sovereign::Production
