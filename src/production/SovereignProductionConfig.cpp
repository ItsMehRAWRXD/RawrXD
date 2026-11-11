#include "SovereignProductionConfig.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Schema declaration
// ---------------------------------------------------------------------------

ConfigSchema& ConfigSchema::field(std::string key, std::string env,
                                 ConfigValue default_value,
                                 std::string description, bool required,
                                 Limits limits) {
    ConfigField f;
    f.section = section_;
    f.key = std::move(key);
    f.env_var = std::move(env);
    f.default_value = std::move(default_value);
    f.description = std::move(description);
    f.required = required;
    f.min_int = limits.min_int;
    f.max_int = limits.max_int;
    f.min_real = limits.min_real;
    f.max_real = limits.max_real;
    // An engaged-but-empty whitelist would reject every value, so it is only
    // stored when the caller actually declared one. This is the difference
    // between "any value is fine" and "no value is fine".
    if (!limits.allowed.empty()) {
        f.allowed = std::move(limits.allowed);
    } else {
        f.allowed.reset();
    }
    fields_.push_back(std::move(f));
    return *this;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Parses a JSON scalar into ConfigValue. Any type mismatch becomes a plain
// int64/double/string rather than throwing, so partial config load still works.
ConfigValue coerce(const json& v) {
    if (v.is_boolean()) return ConfigValue{v.get<bool>()};
    if (v.is_number_integer() || v.is_number_unsigned())
        return ConfigValue{static_cast<int64_t>(v.get<int64_t>())};
    if (v.is_number_float()) return ConfigValue{v.get<double>()};
    if (v.is_string()) return ConfigValue{v.get<std::string>()};
    return ConfigValue{std::string{}};
}

bool parse_bool(std::string v) {
    v = lower(v);
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

} // namespace

// ---------------------------------------------------------------------------
// ConfigManager
// ---------------------------------------------------------------------------

void ConfigManager::install_default_schema() {
    add_schema(ConfigSchema("general")
        .field("service_name", "RAWRXD_SERVICE_NAME", std::string("rawrxd"),
               "Service name used in logs, metrics and audit records", true)
        .field("environment", "RAWRXD_ENVIRONMENT", std::string("development"),
               "Deployment environment: development | staging | production",
               true)
        .field("instance_id", "RAWRXD_INSTANCE_ID", std::string("local"),
               "Stable instance identifier for log/metric correlation")
        .field("shutdown_timeout_ms", "RAWRXD_SHUTDOWN_TIMEOUT_MS",
               std::chrono::milliseconds{15000},
               "Grace period for in-flight work before forced exit"));

    add_schema(ConfigSchema("logging")
        .field("level", "RAWRXD_LOG_LEVEL", std::string("info"),
               "Minimum emitted level: trace|debug|info|warn|error|critical", true,
               ConfigSchema::limits().one_of(
                   {"trace", "debug", "info", "warn", "error", "critical"}))
        .field("format", "RAWRXD_LOG_FORMAT", std::string("json"),
               "Log encoding: json | text", true,
               ConfigSchema::limits().one_of({"json", "text"}))
        .field("dir", "RAWRXD_LOG_DIR", std::string("%LOCALAPPDATA%\\RawrXD\\logs"),
               "Directory for structured log files")
        .field("max_file_bytes", "RAWRXD_LOG_MAX_FILE_BYTES",
               static_cast<int64_t>(64LL * 1024 * 1024),
               "Rotate a log file once it reaches this size", false,
               ConfigSchema::limits().min_int64(static_cast<int64_t>(4096)))
        .field("max_files", "RAWRXD_LOG_MAX_FILES", static_cast<int64_t>(8),
               "Rotated files to retain (oldest are deleted)", false,
               ConfigSchema::limits().min_int64(1).max_int64(64))
        .field("console_mirror", "RAWRXD_LOG_CONSOLE_MIRROR", true,
               "Mirror structured logs to stdout/stderr"));

    add_schema(ConfigSchema("observability")
        .field("metrics_enabled", "RAWRXD_METRICS_ENABLED", true,
               "Collect counters, gauges and histograms")
        .field("metrics_dir", "RAWRXD_METRICS_DIR",
               std::string("%LOCALAPPDATA%\\RawrXD\\metrics"),
               "Directory for periodic metric snapshots")
        .field("metrics_interval_ms", "RAWRXD_METRICS_INTERVAL_MS",
               std::chrono::milliseconds{5000},
               "Snapshot cadence for metric files")
        .field("tracing_enabled", "RAWRXD_TRACING_ENABLED", true,
               "Record trace spans for operation timelines")
        .field("trace_slow_operation_ms", "RAWRXD_TRACE_SLOW_OP_MS",
               std::chrono::milliseconds{1000},
               "Operations slower than this are always traced"));

    add_schema(ConfigSchema("reliability")
        .field("circuit_breaker_enabled", "RAWRXD_CB_ENABLED", true,
               "Enable circuit breakers on external calls")
        .field("cb_failure_threshold", "RAWRXD_CB_FAILURE_THRESHOLD",
               static_cast<int64_t>(5),
               "Consecutive failures that open a circuit", false,
               ConfigSchema::limits().min_int64(1).max_int64(1000))
        .field("cb_open_duration_ms", "RAWRXD_CB_OPEN_MS",
               std::chrono::milliseconds{30000},
               "Time a circuit stays open before a trial request", false,
               ConfigSchema::limits().min_int64(1))
        .field("cb_half_open_probes", "RAWRXD_CB_HALF_OPEN_PROBES",
               static_cast<int64_t>(3),
               "Trials allowed while half-open before deciding", false,
               ConfigSchema::limits().min_int64(1).max_int64(100))
        .field("retry_max_attempts", "RAWRXD_RETRY_MAX_ATTEMPTS",
               static_cast<int64_t>(4),
               "Attempts for retryable operations (1 = no retry)")
        .field("retry_initial_backoff_ms", "RAWRXD_RETRY_INITIAL_MS",
               std::chrono::milliseconds{100},
               "First retry delay")
        .field("retry_max_backoff_ms", "RAWRXD_RETRY_MAX_MS",
               std::chrono::milliseconds{8000},
               "Ceiling for exponential backoff")
        .field("retry_jitter", "RAWRXD_RETRY_JITTER", 0.2,
               "Randomised fraction added to each backoff (0-1)")
        .field("default_operation_timeout_ms", "RAWRXD_DEFAULT_TIMEOUT_MS",
               std::chrono::milliseconds{30000},
               "Timeout applied when an operation declares none"));

    add_schema(ConfigSchema("security")
        .field("encryption_enabled", "RAWRXD_SECURITY_ENCRYPTION", true,
               "Encrypt persisted state and audit records at rest")
        .field("key_file", "RAWRXD_SECURITY_KEY_FILE",
               std::string("%LOCALAPPDATA%\\RawrXD\\keys\\audit.key"),
               "Path to the 256-bit master key file (generated on first use; "
               "set empty to disable persistence, which also disables "
               "encryption of the audit log so it stays readable)")
        .field("audit_enabled", "RAWRXD_SECURITY_AUDIT", true,
               "Append-only audit trail of privileged operations")
        .field("audit_dir", "RAWRXD_SECURITY_AUDIT_DIR",
               std::string("%LOCALAPPDATA%\\RawrXD\\audit"),
               "Directory for the append-only audit log")
        .field("audit_retention_days", "RAWRXD_SECURITY_AUDIT_RETENTION_DAYS",
               static_cast<int64_t>(90),
               "Minimum audit retention period")
        .field("max_request_bytes", "RAWRXD_SECURITY_MAX_REQUEST_BYTES",
               static_cast<int64_t>(8LL * 1024 * 1024),
               "Reject untrusted input larger than this")
        .field("allowed_model_extensions", "RAWRXD_SECURITY_MODEL_EXTENSIONS",
               std::string(".gguf,.bin,.safetensors"),
               "Comma separated whitelist of loadable model extensions"));

    add_schema(ConfigSchema("production")
        .field("run_readiness_gates", "RAWRXD_RUN_READINESS_GATES", true,
               "Block startup on a failed readiness gate")
        .field("fail_fast_on_gate_failure", "RAWRXD_FAIL_FAST_GATES", true,
               "Abort startup instead of running degraded")
        .field("health_check_enabled", "RAWRXD_HEALTH_CHECK", true,
               "Answer liveness/readiness probes"));
}

void ConfigManager::apply_field_defaults_locked(const std::string& section,
                                                const ConfigField& f) {
    auto& slot = values_[section][f.key];
    slot.value = f.default_value;
    slot.source = ConfigSource::Default;
}

void ConfigManager::add_schema(ConfigSchema schema) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& dst = schema_[schema.name()];
    for (auto& f : schema.fields()) {
        // Last declaration wins, so a subsystem can re-declare a field with a
        // tighter default without the first declaration leaking through.
        dst[f.key] = f;
        if (!values_.count(schema.name()) || !values_[schema.name()].count(f.key)) {
            apply_field_defaults_locked(schema.name(), f);
        }
    }
}

void ConfigManager::load_file(const fs::path& path, bool allow_missing) {
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        if (allow_missing) return;
        throw ConfigError("config file not found: " + path.string());
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw ConfigError("config file unreadable: " + path.string());
    }
    json doc;
    try {
        in >> doc;
    } catch (const std::exception& e) {
        throw ConfigError("config file is not valid JSON (" + path.string() +
                          "): " + e.what());
    }
    if (!doc.is_object()) {
        throw ConfigError("config file root must be a JSON object: " + path.string());
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [section_name, section_val] : doc.items()) {
        if (!section_val.is_object()) continue;
        for (auto& [key, raw] : section_val.items()) {
            // Only declared fields are accepted: an unknown key is a typo and
            // must not be silently dropped, so it is recorded (and reported by
            // validate()) rather than ignored.
            auto sec = schema_.find(section_name);
            if (sec == schema_.end() || !sec->second.count(key)) {
                values_["_rejected_"][section_name + "." + key] =
                    EffectiveValue{coerce(raw), ConfigSource::ConfigFile};
                continue;
            }
            values_[section_name][key] = EffectiveValue{coerce(raw),
                                                        ConfigSource::ConfigFile};
        }
    }
}

void ConfigManager::apply_environment(char* const*) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [section_name, fields] : schema_) {
        for (auto& [key, field] : fields) {
            if (field.env_var.empty()) continue;
            const char* raw = std::getenv(field.env_var.c_str());
            if (!raw || !*raw) continue;

            // Environment values always arrive as strings. A value that parses
            // as JSON keeps its type; anything else stays a string, which is
            // what an unquoted enum like RAWRXD_LOG_LEVEL=info should become.
            json parsed = json::parse(raw, nullptr, false);
            const bool parsed_ok = !parsed.is_discarded();
            // "1", "true" and "null" are valid JSON but a bool/null is not a
            // useful config value here, so treat them as text instead.
            if (parsed_ok &&
                (parsed.is_primitive() && !parsed.is_boolean())) {
                values_[section_name][key] = EffectiveValue{
                    coerce(parsed), ConfigSource::EnvironmentVariable};
            } else {
                values_[section_name][key] = EffectiveValue{
                    ConfigValue{std::string(raw)},
                    ConfigSource::EnvironmentVariable};
            }
        }
    }
}

void ConfigManager::apply_command_line(const std::vector<std::string>& args) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& arg : args) {
        if (arg.rfind("--", 0) != 0) continue;
        auto body = arg.substr(2);
        auto eq = body.find('=');
        if (eq == std::string::npos) continue;
        std::string section_key = body.substr(0, eq);
        std::string raw = body.substr(eq + 1);
        auto dot = section_key.find('.');
        if (dot == std::string::npos) continue;
        auto section = section_key.substr(0, dot);
        auto key = section_key.substr(dot + 1);

        auto json_val = json::parse(raw, nullptr, false);
        ConfigValue parsed = json_val.is_discarded()
            ? ConfigValue{raw}
            : coerce(json_val);
        values_[section][key] = EffectiveValue{parsed, ConfigSource::CommandLine};
    }
}

std::vector<ValidationResult> ConfigManager::validate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ValidationResult> problems;

    for (const auto& [section, fields] : schema_) {
        for (const auto& [key, field] : fields) {
            const auto sec_it = values_.find(section);
            const bool present =
                sec_it != values_.end() && sec_it->second.count(key);
            const std::string name = section + "." + key;

            if (!present) {
                if (field.required) {
                    problems.push_back({false, name,
                                        "required field is not set"});
                }
                continue;
            }
            const ConfigValue& v = sec_it->second.at(key).value;

            if (field.required &&
                std::holds_alternative<std::string>(v) &&
                std::get<std::string>(v).empty()) {
                problems.push_back({false, name,
                                    "required field must not be empty"});
                continue;
            }
            if (field.min_int && std::holds_alternative<int64_t>(v)) {
                if (std::get<int64_t>(v) < *field.min_int) {
                    problems.push_back(
                        {false, name, "below the allowed minimum"});
                }
            }
            if (field.max_int && std::holds_alternative<int64_t>(v)) {
                if (std::get<int64_t>(v) > *field.max_int) {
                    problems.push_back(
                        {false, name, "above the allowed maximum"});
                }
            }
            if (field.min_real && std::holds_alternative<double>(v)) {
                if (std::get<double>(v) < *field.min_real) {
                    problems.push_back(
                        {false, name, "below the allowed minimum"});
                }
            }
            if (field.max_real && std::holds_alternative<double>(v)) {
                if (std::get<double>(v) > *field.max_real) {
                    problems.push_back(
                        {false, name, "above the allowed maximum"});
                }
            }
            if (field.allowed && std::holds_alternative<std::string>(v)) {
                const std::string& s = std::get<std::string>(v);
                if (std::find(field.allowed->begin(), field.allowed->end(),
                              s) == field.allowed->end()) {
                    problems.push_back({false, name,
                                        "value '" + s + "' is not permitted"});
                }
            }
        }
    }

    // Unknown keys from a config file: reported so operators can spot typos.
    auto rejected = values_.find("_rejected_");
    if (rejected != values_.end()) {
        for (const auto& [name, val] : rejected->second) {
            problems.push_back(
                {false, "_rejected_." + name,
                 "unknown configuration key '" + name + "' (value '" +
                     to_string(val.value) + "' ignored)"});
        }
    }
    return problems;
}

void ConfigManager::validate_or_throw() const {
    auto problems = validate();
    if (problems.empty()) return;
    std::ostringstream oss;
    oss << "invalid configuration (" << problems.size()
        << " problem(s)):";
    for (const auto& p : problems) {
        oss << "\n  - " << p.name << ": " << p.message;
    }
    throw ConfigError(oss.str());
}

bool ConfigManager::looks_secret(std::string_view key) {
    const std::string k = lower(std::string(key));
    return k.find("secret") != std::string::npos ||
           k.find("password") != std::string::npos ||
           k.find("token") != std::string::npos ||
           k.find("key_file") != std::string::npos ||
           k.find("api_key") != std::string::npos;
}

std::string ConfigManager::to_string(const ConfigValue& v) {
    if (auto* s = std::get_if<std::string>(&v)) return *s;
    if (auto* i = std::get_if<int64_t>(&v)) return std::to_string(*i);
    if (auto* d = std::get_if<double>(&v)) {
        std::ostringstream oss;
        oss << *d;
        return oss.str();
    }
    if (auto* b = std::get_if<bool>(&v)) return *b ? "true" : "false";
    if (auto* ms = std::get_if<std::chrono::milliseconds>(&v))
        return std::to_string(ms->count()) + "ms";
    return {};
}

bool ConfigManager::was_explicitly_configured(const std::string& section,
                                             const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto sec_it = values_.find(section);
    if (sec_it == values_.end()) return false;
    auto key_it = sec_it->second.find(key);
    if (key_it == sec_it->second.end()) return false;
    return key_it->second.source != ConfigSource::Default;
}

std::string ConfigManager::dump(bool redact) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    for (const auto& [section, fields] : values_) {
        if (section == "_rejected_") continue;
        for (const auto& [key, effective] : fields) {
            const std::string value =
                (redact && looks_secret(key)) ? "<redacted>"
                                              : to_string(effective.value);
            oss << section << "." << key << "=" << value << "\n";
        }
    }
    return oss.str();
}

void ConfigManager::set(const std::string& section, const std::string& key,
                       ConfigValue value) {
    std::lock_guard<std::mutex> lock(mutex_);
    values_[section][key] =
        EffectiveValue{std::move(value), ConfigSource::CommandLine};
}

std::string ConfigManager::config_fingerprint() const {
    // Order-independent hash of the effective configuration so a log line can
    // identify the configuration without printing secrets.
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> lines;
    for (const auto& [section, fields] : values_) {
        if (section == "_rejected_") continue;
        for (const auto& [key, effective] : fields) {
            const std::string value =
                looks_secret(key) ? "<redacted>" : to_string(effective.value);
            lines.push_back(section + "." + key + "=" + value);
        }
    }
    std::sort(lines.begin(), lines.end());
    std::string joined;
    for (const auto& l : lines) {
        joined += l;
        joined += '\n';
    }
    // FNV-1a: small, stable, no crypto dependency required for a fingerprint.
    uint64_t h = 1469598103934665603ULL;
    for (char c : joined) {
        h ^= static_cast<unsigned char>(c);
        h *= 1099511628211ULL;
    }
    char buf[17] = {0};
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
    return buf;
}

fs::path ConfigManager_AutoDiscover() {
    if (const char* p = std::getenv("RAWRXD_CONFIG"); p && *p) {
        return fs::path{p};
    }
    return {};
}

} // namespace Sovereign::Production
