#pragma once

/**
 * @file input_sanitizer.h
 * @brief Production-grade input validation and sanitization (dependency-free C++20)
 *
 * Security policy for RawrXD:
 *   - Every externally-controlled input (file paths, URLs, hostnames, model
 *     files, command arguments, JSON payloads, UI text) MUST be validated here
 *     before use. Nothing reaches disk, network, a subprocess, or a SQL
 *     statement without passing through this boundary.
 *   - Fail-closed: when validation fails, the caller gets `false` and must
 *     reject the operation. There are no "soft" validation passes.
 *   - No Qt, no exceptions in the API contract, no global state beyond a
 *     configurable singleton. Usable from native tools, the Qt shell, and
 *     unit tests alike.
 *
 * Threat model covered:
 *   - Path traversal / directory escape (e.g. "..\\..\\windows\\system32")
 *   - Command injection into QProcess / subprocess execution
 *   - SQL injection (defense-in-depth; parameterized queries remain mandatory)
 *   - XSS / HTML injection in rendered output
 *   - SSRF via URL/host/IP (scheme allowlist, private-IP blocking, null-byte)
 *   - Malformed / oversized JSON (DoS)
 *   - Corrupt or non-model files being treated as models
 *   - Integer overflow / range violations via unchecked numeric input
 *
 * This header is intentionally self-contained: it only uses the C++20 standard
 * library so that every target in this tree can depend on it.
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <array>
#include <algorithm>

namespace RawrXD {
namespace Security {

/**
 * @brief Outcome of a validation call.
 */
enum class ValidationResult {
    Ok = 0,             ///< Input accepted (possibly rewritten in `out`)
    Empty,              ///< Input was empty where a value was required
    TooLong,            ///< Input exceeded the configured length limit
    InvalidChars,       ///< Input contained characters outside the allow-list
    NullByte,           ///< Embedded NUL byte detected
    ControlChar,        ///< Suspicious control character (e.g. AX/BS for log forging)
    PathTraversal,      ///< Input attempted to escape the base directory
    NotAllowed,         ///< Path/resource outside an allow-list (base dir, root set)
    CommandInjection,   ///< Shell metacharacter sequence detected
    SqlInjection,       ///< SQL metacharacter/keyword sequence detected
    XssAttempt,         ///< HTML/script injection sequence detected
    InvalidUrl,         ///< URL failed structural or scheme validation
    InvalidHostname,    ///< Hostname violates RFC 1123
    InvalidPort,        ///< Port out of range
    InvalidIpAddress,   ///< Not a well-formed IPv4/IPv6 literal
    PrivateAddress,     ///< Private/loopback/link-local address (blocked for remote use)
    BadExtension,       ///< File extension not on the allow-list
    FileTooLarge,       ///< File exceeds the configured size cap
    JsonTooLarge,       ///< JSON payload exceeds the size cap
    InvalidJson,        ///< JSON is structurally invalid
    InvalidNumber,      ///< Not a well-formed number
    OutOfRange,         ///< Numeric value outside the permitted range
    InvalidModel,       ///< Model file header/magic invalid
    InvalidEncoding,    ///< Not valid UTF-8
    IoError,            ///< Filesystem read/open failure
};

/**
 * @brief Convert a result code to a stable, loggable identifier.
 */
constexpr std::string_view ToString(ValidationResult r) noexcept
{
    switch (r) {
        case ValidationResult::Ok:              return "Ok";
        case ValidationResult::Empty:          return "Empty";
        case ValidationResult::TooLong:        return "TooLong";
        case ValidationResult::InvalidChars:   return "InvalidChars";
        case ValidationResult::NullByte:        return "NullByte";
        case ValidationResult::ControlChar:    return "ControlChar";
        case ValidationResult::PathTraversal:  return "PathTraversal";
        case ValidationResult::NotAllowed:      return "NotAllowed";
        case ValidationResult::CommandInjection: return "CommandInjection";
        case ValidationResult::SqlInjection:   return "SqlInjection";
        case ValidationResult::XssAttempt:     return "XssAttempt";
        case ValidationResult::InvalidUrl:     return "InvalidUrl";
        case ValidationResult::InvalidHostname: return "InvalidHostname";
        case ValidationResult::InvalidPort:    return "InvalidPort";
        case ValidationResult::InvalidIpAddress: return "InvalidIpAddress";
        case ValidationResult::PrivateAddress: return "PrivateAddress";
        case ValidationResult::BadExtension:   return "BadExtension";
        case ValidationResult::FileTooLarge:   return "FileTooLarge";
        case ValidationResult::JsonTooLarge:   return "JsonTooLarge";
        case ValidationResult::InvalidJson:    return "InvalidJson";
        case ValidationResult::InvalidNumber:  return "InvalidNumber";
        case ValidationResult::OutOfRange:     return "OutOfRange";
        case ValidationResult::InvalidModel:    return "InvalidModel";
        case ValidationResult::InvalidEncoding:return "InvalidEncoding";
        case ValidationResult::IoError:        return "IoError";
    }
    return "Unknown";
}

    /**
     * @brief Tunable security policy. Tighten for higher-threat deployments.
 * Defaults reflect a production IDE: generous enough for real model files,
 * strict enough to reject abuse.
 */
struct SanitizerConfig {
    // ---- Length caps (DoS resistance) ----
    size_t maxPathLength        = 4096;
    size_t maxUrlLength         = 2048;
    size_t maxHostnameLength    = 253;    // RFC 1123
    size_t maxCommandArgLength  = 8192;
    size_t maxStringLength      = 65536;
    size_t maxJsonSize          = 16u * 1024u * 1024u;  // 16 MB
    uint64_t maxModelFileSize   = 64ull * 1024ull * 1024ull * 1024ull; // 64 GB
    uint64_t maxGenericFileSize = 8ull * 1024ull * 1024ull;            //  8 MB

    // ---- URL / network policy ----
    std::vector<std::string> allowedUrlSchemes = {"https", "http", "file"};
    bool blockPrivateIps   = true;   ///< Reject RFC1918/loopback/link-local for outbound
    bool allowLoopback     = true;   ///< Permitted for local-only features (model server)
    bool allowNonStandardPorts = true;
    uint16_t maxPort       = 65535;

    // ---- Model file policy ----
    std::vector<std::string> allowedModelExtensions = {".gguf", ".ggml", ".safetensors", ".bin"};
    ///< 4-byte magic values accepted as model headers ("GGUF", ...)
    std::vector<std::array<char, 4>> allowedModelMagics = {
        {'G', 'G', 'U', 'F'},   // GGUF
        {'G', 'G', 'M', 'L'},   // GGML (legacy)
    };

    // ---- Escape policy ----
    bool escapeOnOutput = true;   ///< Auto-escape in HighRiskText() helper
};

/**
 * @brief Central, single-threaded input validation boundary.
 *
 * Thread-safety: `instance()` is safe to call concurrently. Validation calls
 * that mutate state (`lastResult`) store the last call's outcome per-thread,
 * so concurrent validation on different threads does not corrupt each other.
 * Reconfigure only during startup, before request handling begins.
 */
class InputSanitizer
{
public:
    static InputSanitizer& instance();

    // ------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------
    void configure(const SanitizerConfig& cfg);
    const SanitizerConfig& config() const noexcept { return m_cfg; }

    /// Result of the most recent validation call on THIS thread.
    ValidationResult lastResult() const noexcept { return m_lastResult; }
    /// Human-readable explanation of the most recent failure.
    const std::string& lastError() const noexcept { return m_lastMessage; }

    // ------------------------------------------------------------
    // Paths
    // ------------------------------------------------------------
    /// Validate and normalize a filesystem path. When @p baseDir is non-empty,
    /// the resolved path MUST be inside it (no escape via .., symlinks via
    /// canonicalization when the file exists, or absolute redirection).
    bool resolvePath(const std::string& input,
                     const std::string& baseDir,
                     std::string& out,
                     bool allowRelative = false);

    /// Validate a model file path: resolvePath() extension allow-list + file
    /// existence check. Header/magic is checked only by verifyModelHeader().
    bool resolveModelPath(const std::string& input,
                          const std::string& baseDir,
                          std::string& out);

    /// True when @p path is equal to or inside @p root (both normalized).
    static bool isWithinRoot(const std::string& path, const std::string& root);

    /// True when @p path is inside at least one of @p roots.
    static bool isWithinAnyRoot(const std::string& path, const std::vector<std::string>& roots);

    // ------------------------------------------------------------
    // Network
    // ------------------------------------------------------------
    bool validateUrl(const std::string& input, std::string& out);       ///< returns canonical URL
    bool validateHostname(const std::string& input, std::string& out);
    bool validateIpAddress(const std::string& input, std::string& out);
    static bool isValidPort(uint16_t port) noexcept { return port != 0; }

    // ------------------------------------------------------------
    // Subprocess
    // ------------------------------------------------------------
    bool sanitizeCommandArg(const std::string& input, std::string& out);
    bool validateCommandLine(const std::string& program,
                             const std::vector<std::string>& args,
                             std::vector<std::string>& out);

    // ------------------------------------------------------------
    // SQL (defense-in-depth)
    // ------------------------------------------------------------
    bool sanitizeSqlLiteral(const std::string& input, std::string& out);  ///< quote-doubled literal
    bool validateSqlIdentifier(const std::string& input, std::string& out); ///< [a-zA-Z_][a-zA-Z0-9_]*

    // ------------------------------------------------------------
    // XSS / HTML
    // ------------------------------------------------------------
    std::string escapeHtml(const std::string& input) const;          ///< minimal escape (5 chars)
    std::string escapeHtmlAttr(const std::string& input) const;      ///< + quote escaping
    std::string escapeJavaScript(const std::string& input) const;
    bool sanitizeHtml(const std::string& input,
                      std::string& out,
                      const std::vector<std::string>& allowedTags = {});

    // ------------------------------------------------------------
    // JSON
    // ------------------------------------------------------------
    /// Size + UTF-8 gate only; structural parsing belongs to nlohmann/json.
    bool validateJsonBytes(const std::string& data, std::string& out);

    // ------------------------------------------------------------
    // Generic values
    // ------------------------------------------------------------
    bool validateString(const std::string& input,
                        const std::string& field,
                        std::string& out,
                        size_t maxLength = 0);          ///< 0 => config maxStringLength

    bool validateInt(const std::string& input, const std::string& field, std::string& out,
                     int64_t min, int64_t max);
    bool validateDouble(const std::string& input, const std::string& field, std::string& out,
                        double min, double max);

    // ------------------------------------------------------------
    // Encoding / model integrity
    // ------------------------------------------------------------
    static bool isValidUtf8(const std::string& s) noexcept;
    static bool containsNullBytes(const std::string& s) noexcept;
    static bool containsControlChars(const std::string& s) noexcept;  ///< excludes \t \r \n
    static void secureWipe(std::string& s) noexcept;                  ///< zeroize before free

    /// Verify the file's header magic matches an allowed model signature.
    bool verifyModelHeader(const std::string& path, std::string& out);

    /// Constant-time comparison (timing-attack resistant).
    static bool constantTimeEquals(const std::string& a, const std::string& b) noexcept;

    // ------------------------------------------------------------
    // Diagnostics
    // ------------------------------------------------------------
    static std::string_view describe(ValidationResult r) noexcept { return ToString(r); }

private:
    InputSanitizer() = default;

    /// Per-thread "last call" state. Thread-local so that concurrent
    /// validation on different threads cannot corrupt each other's
    /// diagnostics, with no locking on the validation hot path.
    thread_local static ValidationResult m_lastResult;
    thread_local static std::string m_lastMessage;

    void setResult(ValidationResult r, const std::string& msg);

    SanitizerConfig m_cfg;
};

// --------------------------------------------------------------------
// Convenience macros for consistent, terse call sites.
// These intentionally evaluate to `bool` so they compose with
// `if (!RAWRXD_VALIDATE_PATH(p, base, out)) { log; reject; }`.
// --------------------------------------------------------------------
#define RAWRXD_VALIDATE_PATH(input, baseDir, out) \
    ::RawrXD::Security::InputSanitizer::instance().resolvePath((input), (baseDir), (out))

#define RAWRXD_VALIDATE_MODEL_PATH(input, baseDir, out) \
    ::RawrXD::Security::InputSanitizer::instance().resolveModelPath((input), (baseDir), (out))

#define RAWRXD_VALIDATE_URL(input, out) \
    ::RawrXD::Security::InputSanitizer::instance().validateUrl((input), (out))

#define RAWRXD_VALIDATE_HOSTNAME(input, out) \
    ::RawrXD::Security::InputSanitizer::instance().validateHostname((input), (out))

#define RAWRXD_SANITIZE_CMD_ARG(input, out) \
    ::RawrXD::Security::InputSanitizer::instance().sanitizeCommandArg((input), (out))

#define RAWRXD_VALIDATE_CMD_LINE(program, args, out) \
    ::RawrXD::Security::InputSanitizer::instance().validateCommandLine((program), (args), (out))

#define RAWRXD_ESCAPE_HTML(str) \
    ::RawrXD::Security::InputSanitizer::instance().escapeHtml(str)

#define RAWRXD_ESCAPE_JS(str) \
    ::RawrXD::Security::InputSanitizer::instance().escapeJavaScript(str)

} // namespace Security
} // namespace RawrXD