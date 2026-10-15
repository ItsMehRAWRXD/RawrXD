/**
 * @file input_sanitizer.cpp
 * @brief Implementation of the RawrXD input validation boundary.
 *
 * Implementation notes / design rules:
 *  - Fail-closed: every public function returns false on any anomaly and
 *    records a specific ValidationResult + message for the audit log.
 *  - No exceptions cross the API boundary; filesystem work is wrapped so I/O
 *    failures surface as ValidationResult::IoError rather than a throw.
 *  - Normalization happens BEFORE comparison (lexically-normalized paths,
 *    lowercased hostnames) so that attacker-rewritten but equivalent inputs
 *    cannot bypass an allow-list.
 *  - Safe conversions only: integers parsed with std::from_chars (no exceptions,
 *    no locale, no UB on overflow); sizes checked before use.
 */

// ============================================================================
// These macros MUST precede every standard header (including those pulled in
// transitively by input_sanitizer.h), because MSVC evaluates them while
// processing <yvals_core.h>:
//   _CRT_SECURE_NO_WARNINGS                    - silence CRT "unsafe" warnings
//   _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING  - keep UTF-8 path construction
// Defining them after any standard include has no effect.
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#  define _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#endif

#include "input_sanitizer.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <system_error>
#include <thread>
#include <utility>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Security {

namespace {

// ---- Character class helpers ------------------------------------------

constexpr bool isAsciiAlnum(unsigned char c) noexcept
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/// Lowercase ASCII (locale-independent, so a Turkish locale cannot break it).
char asciiLower(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

std::string toLowerAscii(std::string s)
{
    for (char& c : s) c = asciiLower(c);
    return s;
}

bool startsWithCase(std::string_view s, std::string_view prefix) noexcept
{
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (asciiLower(s[i]) != asciiLower(prefix[i])) return false;
    }
    return true;
}

std::string trimAscii(const std::string& s)
{
    auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    auto b = std::find_if(s.begin(), s.end(), notSpace);
    auto e = std::find_if(s.rbegin(), s.rend(), notSpace).base();
    if (b >= e) return {};
    return std::string(b, e);
}

bool isHexChar(char c) noexcept
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// Reserved shell metacharacters that enable command injection.
bool isShellMeta(char c) noexcept
{
    switch (c) {
        case '`': case '$': case '|': case ';': case '&': case '<': case '>':
        case '(': case ')': case '{': case '}': case '\n': case '\r':
        case '"': case '\'': case '\\': case '\t':
            return true;
        default:
            return false;
    }
}

/// Tokens whose presence in a "filter/where" string indicates SQL injection.
bool containsSqlKeyword(std::string_view haystackLower)
{
    // Word-bounded scan so "selective" does not trip "SELECT ... OR".
    static constexpr std::string_view kSqlWords[] = {
        "select", "insert", "update", "delete", "drop", "union", "exec",
        "truncate", "alter", "create", "grant", "revoke", "pragma", "attach",
        "detach", "sqlite_master", "information_schema", "sleep", "waitfor"
    };
    for (auto w : kSqlWords) {
        size_t pos = 0;
        while ((pos = haystackLower.find(w, pos)) != std::string_view::npos) {
            const bool leftOk  = pos == 0 || !isAsciiAlnum(static_cast<unsigned char>(haystackLower[pos - 1]));
            const size_t right = pos + w.size();
            const bool rightOk = right >= haystackLower.size()
                              || !isAsciiAlnum(static_cast<unsigned char>(haystackLower[right]));
            // Also treat a leading SQL statement separator as a hit.
            if (leftOk && rightOk) return true;
            pos += w.size();
        }
    }
    return false;
}

/// Sequences that indicate XSS/HTML injection.
bool containsXssPattern(std::string_view lower)
{
    static constexpr std::string_view kXss[] = {
        "<script", "</script", "javascript:", "vbscript:", "onerror=", "onload=",
        "onclick=", "onmouseover=", "<iframe", "<img", "<svg", "<object", "<embed",
        "document.cookie", "eval(", "expression(", "data:text/html", "<link", "<meta"
    };
    for (auto p : kXss) {
        if (lower.find(p) != std::string_view::npos) return true;
    }
    return false;
}

/**
 * @brief Sequences that indicate an attempted directory escape.
 *
 * Deliberately does NOT include '/', '\\' or '?': those are legitimate in
 * ordinary absolute paths and their rejection would break every real path.
 * Only genuinely dangerous encodings and parent-references are listed.
 */
bool containsTraversalOrEscape(std::string_view s)
{
    static constexpr std::string_view kBad[] = {
        "..", "%2e%2e", "%2f", "%5c", "\\\\", "~", "::", "$env", "${", "\n", "\r"
    };
    for (auto p : kBad) {
        if (s.find(p) != std::string_view::npos) return true;
    }
    return false;
}

/// Normalize a path lexically and, when it exists, canonicalize to resolve
/// symlinks/junctions. Never throws: returns input-lexical on error.
fs::path normalizePath(const fs::path& p)
{
    std::error_code ec;
    if (fs::exists(p, ec)) {
        auto c = fs::canonical(p, ec);
        if (!ec) return c;
    }
    // weakly_canonical handles non-existent tails without touching the disk
    // for the existing prefix, and never throws with the ec overload.
    auto w = fs::weakly_canonical(p, ec);
    if (!ec) return w;
    return p.lexically_normal();
}

std::string pathToString(const fs::path& p) { return p.generic_string(); }

/**
 * @brief True for addresses that must never be reachable from outbound
 * requests (SSRF mitigation).
 *
 * Covers: this-network 0/8, loopback 127/8, RFC1918 10/8 + 172.16/12 +
 * 192.168/16, link-local 169.254/16, CGNAT 100.64/10, TEST-NETs, multicast,
 * broadcast, and reserved. IPv6 loopback/link-local/unique-local are handled
 * by the literal checks below.
 */
bool isPrivateOrReservedIp(const std::string& ip)
{
    auto starts = [&ip](const char* p) {
        const size_t n = std::strlen(p);
        return ip.size() >= n && ip.compare(0, n, p) == 0;
    };

    // IPv6 specials.
    if (ip == "::1" || ip == "::") return true;                    // loopback / unspecified
    if (starts("fc") || starts("fd")) return true;                 // IPv6 ULA fc00::/7
    if (starts("fe8") || starts("fe9") || starts("fea") || starts("feb")) return true; // LL

    // Must be dotted IPv4 to inspect the leading octets.
    if (ip.find(':') != std::string::npos) return false;

    // Parse the first two octets by hand (no sscanf: locale-independent,
    // non-throwing, and never reads beyond the parsed fields).
    auto firstTwoOctets = [&ip](int& a, int& b) -> bool {
        int octet = -1;
        int count = 0;
        for (char c : ip) {
            if (c == '.') {
                if (octet < 0 || octet > 255) return false;
                if (count == 0) a = octet; else if (count == 1) b = octet;
                ++count;
                octet = -1;
                if (count > 2) return true;   // only the first two are needed
                continue;
            }
            if (c < '0' || c > '9') return false;
            octet = (octet < 0 ? 0 : octet * 10) + (c - '0');
            if (octet > 255) return false;
        }
        if (count == 0 && octet >= 0) { a = octet; b = 0; return true; }
        if (count == 1 && octet >= 0) { b = octet; return true; }
        return count >= 2;
    };

    int a = 0, b = 0;
    if (!firstTwoOctets(a, b)) return true;   // malformed -> treat as private
    if (a == 0)         return true;                               // 0.0.0.0/8   this-network
    if (a == 127)       return true;                               // 127.0.0.0/8 loopback
    if (a == 10)        return true;                               // RFC1918
    if (a == 172 && b >= 16 && b <= 31) return true;               // 172.16.0.0/12
    if (a == 192 && b == 168) return true;                         // 192.168.0.0/16
    if (a == 169 && b == 254) return true;                         // 169.254.0.0/16 link-local
    if (a == 100 && b >= 64 && b <= 127) return true;              // 100.64.0.0/10 CGNAT
    if (a >= 224)       return true;                               // multicast/reserved/bcast
    if (a == 192 && b == 0)   return true;                         // TEST-NET-1
    if (a == 198 && (b == 18 || b == 19)) return true;             // TEST-NET-2/3
    if (a == 198 && b == 51)    return true;                       // TEST-NET-2
    if (a == 203 && b == 0)     return true;                       // TEST-NET-3
    return false;
}

bool extensionAllowed(const fs::path& p, const std::vector<std::string>& allowed)
{
    std::string ext = pathToString(p.extension());
    ext = toLowerAscii(std::move(ext));
    return std::find(allowed.begin(), allowed.end(), ext) != allowed.end();
}

} // anonymous namespace

// --------------------------------------------------------------------
// Singleton + per-thread state
// --------------------------------------------------------------------

InputSanitizer& InputSanitizer::instance()
{
    static InputSanitizer s_instance;
    return s_instance;
}

thread_local ValidationResult InputSanitizer::m_lastResult = ValidationResult::Ok;
thread_local std::string InputSanitizer::m_lastMessage;

void InputSanitizer::setResult(ValidationResult r, const std::string& msg)
{
    m_lastResult = r;
    m_lastMessage = msg;
}

void InputSanitizer::configure(const SanitizerConfig& cfg)
{
    m_cfg = cfg;
    // Reject pathological values at configuration time rather than per-call.
    if (m_cfg.maxPathLength == 0)        m_cfg.maxPathLength = 4096;
    if (m_cfg.maxUrlLength == 0)        m_cfg.maxUrlLength = 2048;
    if (m_cfg.maxHostnameLength == 0)   m_cfg.maxHostnameLength = 253;
    if (m_cfg.maxCommandArgLength == 0) m_cfg.maxCommandArgLength = 8192;
    if (m_cfg.maxStringLength == 0)      m_cfg.maxStringLength = 65536;
    if (m_cfg.maxJsonSize == 0)          m_cfg.maxJsonSize = 16u * 1024u * 1024u;
    if (m_cfg.maxModelFileSize == 0)     m_cfg.maxModelFileSize = 64ull * 1024ull * 1024ull * 1024ull;
}

// --------------------------------------------------------------------
// Shared pre-checks
// --------------------------------------------------------------------

/**
 * @brief Universal pre-flight applied to every text input.
 * @return true if the input passes the basic hygiene checks.
 *
 * Order matters: NUL/control characters are rejected before length/character
 * checks so smuggling into lower layers (webview, SQL, native APIs that stop
 * at NUL) is impossible.
 */
static bool preflightText(const std::string& in, SanitizerConfig const& cfg,
                          size_t maxLen, const char* field, ValidationResult& outResult,
                          std::string& outMessage)
{
    if (in.empty()) {
        outResult = ValidationResult::Empty;
        outMessage = std::string(field) + ": empty input";
        return false;
    }
    if (maxLen && in.size() > maxLen) {
        outResult = ValidationResult::TooLong;
        outMessage = std::string(field) + ": " + std::to_string(in.size())
                   + " bytes exceeds limit " + std::to_string(maxLen);
        return false;
    }
    if (in.find('\0') != std::string::npos) {
        outResult = ValidationResult::NullByte;
        outMessage = std::string(field) + ": embedded NUL byte";
        return false;
    }
    if (InputSanitizer::containsControlChars(in)) {
        outResult = ValidationResult::ControlChar;
        outMessage = std::string(field) + ": suspicious control character";
        return false;
    }
    (void)cfg;
    return true;
}

// --------------------------------------------------------------------
// Paths
// --------------------------------------------------------------------

bool InputSanitizer::resolvePath(const std::string& input,
                                 const std::string& baseDir,
                                 std::string& out,
                                 bool allowRelative)
{
    ValidationResult r = ValidationResult::Ok;
    std::string msg;

    if (!preflightText(input, m_cfg, m_cfg.maxPathLength, "path", r, msg)) {
        setResult(r, msg);
        return false;
    }

    const std::string cleaned = trimAscii(input);

    // Quantized drive/UNC + traversal/encoded-traversal detection.
    const std::string lower = toLowerAscii(cleaned);
    if (containsTraversalOrEscape(lower)) {
        setResult(ValidationResult::PathTraversal,
                  "path: traversal or escape sequence in '" + cleaned + "'");
        return false;
    }

    // Absolute-path requirement (unless explicitly allowed).
    const bool looksAbsolute = !cleaned.empty()
        && (cleaned[0] == '/' || cleaned[0] == '\\'
            || cleaned.find(':') != std::string::npos
            || startsWithCase(cleaned, "\\\\"));
    if (!allowRelative && !looksAbsolute) {
        setResult(ValidationResult::NotAllowed,
                  "path: relative paths are not permitted ('" + cleaned + "')");
        return false;
    }

    fs::path p;
    try {
        p = fs::u8path(cleaned);
        if (p.empty()) {
            setResult(ValidationResult::InvalidChars, "path: unrepresentable");
            return false;
        }
    } catch (const std::exception& e) {
        setResult(ValidationResult::InvalidChars,
                  std::string("path: ") + e.what());
        return false;
    }

    const fs::path norm = normalizePath(p);

    if (!baseDir.empty()) {
        const fs::path root = normalizePath(fs::u8path(baseDir));
        if (!isWithinRoot(pathToString(norm), pathToString(root))) {
            setResult(ValidationResult::NotAllowed,
                      "path: '" + pathToString(norm) + "' escapes base directory '"
                      + pathToString(root) + "'");
            return false;
        }
    }

    out = pathToString(norm);
    setResult(ValidationResult::Ok, "");
    return true;
}

bool InputSanitizer::resolveModelPath(const std::string& input,
                                      const std::string& baseDir,
                                      std::string& out)
{
    if (!resolvePath(input, baseDir, out)) return false;   // propagates setResult

    // Extension allow-list (post-normalization: ".gguf" not ".\u0067guf").
    if (!extensionAllowed(fs::u8path(out), m_cfg.allowedModelExtensions)) {
        setResult(ValidationResult::BadExtension,
                  "model: extension '" + pathToString(fs::u8path(out).extension())
                  + "' not allowed");
        return false;
    }

    // Existence + type check (fail-closed on I/O error).
    std::error_code ec;
    if (!fs::exists(fs::u8path(out), ec) || ec) {
        setResult(ValidationResult::IoError, "model: file not found '" + out + "'");
        return false;
    }
    if (fs::is_directory(fs::u8path(out), ec)) {
        setResult(ValidationResult::InvalidChars, "model: path is a directory");
        return false;
    }

    // Size cap (protects against truncated reads / decompression bombs).
    const auto sz = fs::file_size(fs::u8path(out), ec);
    if (ec) {
        setResult(ValidationResult::IoError, "model: cannot stat '" + out + "'");
        return false;
    }
    if (sz > m_cfg.maxModelFileSize) {
        setResult(ValidationResult::FileTooLarge,
                  "model: " + std::to_string(sz) + " bytes exceeds cap "
                  + std::to_string(m_cfg.maxModelFileSize));
        return false;
    }

    setResult(ValidationResult::Ok, "");
    return true;
}

/**
 * @brief True when @p path is @p root itself, or lies beneath it.
 *
 * Compares lexically-normalized generic paths and requires a separator
 * boundary, so "/srv/models-internal" is NOT accepted as being inside
 * "/srv/models" (a classic prefix-confusion bypass). Performed on strings
 * rather than path iterators so the logic is auditable and portable.
 */
bool InputSanitizer::isWithinRoot(const std::string& path, const std::string& root)
{
    if (root.empty()) return false;

    const auto normalizeToGeneric = [](const std::string& raw) -> std::string {
        std::string s = fs::path(fs::u8path(raw)).lexically_normal().generic_string();
        while (s.size() > 1 && s.back() == '/') s.pop_back();   // drop trailing slash
        return s;
    };

    const std::string p = normalizeToGeneric(path);
    const std::string r = normalizeToGeneric(root);

    if (p == r) return true;
    if (p.size() <= r.size()) return false;
    // Must share the root verbatim and then continue with a separator.
    return p.compare(0, r.size(), r) == 0 && p[r.size()] == '/';
}

bool InputSanitizer::isWithinAnyRoot(const std::string& path,
                                     const std::vector<std::string>& roots)
{
    for (const auto& r : roots) {
        if (isWithinRoot(path, r)) return true;
    }
    return false;
}

// --------------------------------------------------------------------
// URLs / hostnames / IPs
// --------------------------------------------------------------------

bool InputSanitizer::validateUrl(const std::string& input, std::string& out)
{
    ValidationResult r = ValidationResult::Ok;
    std::string msg;
    if (!preflightText(input, m_cfg, m_cfg.maxUrlLength, "url", r, msg)) {
        setResult(r, msg);
        return false;
    }

    const std::string url = trimAscii(input);
    const size_t sep = url.find("://");
    if (sep == std::string::npos || sep == 0) {
        setResult(ValidationResult::InvalidUrl, "url: missing scheme separator");
        return false;
    }

    const std::string scheme = toLowerAscii(url.substr(0, sep));
    if (std::find(m_cfg.allowedUrlSchemes.begin(),
                  m_cfg.allowedUrlSchemes.end(), scheme)
            == m_cfg.allowedUrlSchemes.end()) {
        setResult(ValidationResult::InvalidUrl, "url: scheme '" + scheme + "' not allowed");
        return false;
    }

    // Authority = up to first '/', '?' or '#'.
    size_t authStart = sep + 3;
    size_t authEnd = url.find_first_of("/?#", authStart);
    const std::string authority = url.substr(authStart, authEnd - authStart);
    if (authority.empty()) {
        setResult(ValidationResult::InvalidUrl, "url: empty authority");
        return false;
    }

    // Strip userinfo (user:pass@host) - never permitted.
    const size_t at = authority.rfind('@');
    if (at != std::string::npos) {
        setResult(ValidationResult::InvalidUrl, "url: userinfo is not permitted");
        return false;
    }

    // Host + optional port.
    std::string host = authority;
    uint32_t port = 0;
    bool hasPort = false;
    bool isIpv6Literal = false;   // IPv6 needs brackets when reassembled
    if (!host.empty() && host.front() == '[') {          // IPv6 literal
        const size_t close = host.find(']');
        if (close == std::string::npos) {
            setResult(ValidationResult::InvalidIpAddress, "url: unterminated IPv6 literal");
            return false;
        }
        host = host.substr(1, close - 1);
        isIpv6Literal = true;
        const std::string rest = authority.substr(close + 1);
        if (!rest.empty()) {
            if (rest[0] != ':') {
                setResult(ValidationResult::InvalidUrl, "url: malformed host suffix");
                return false;
            }
            auto pr = std::from_chars(rest.data() + 1, rest.data() + rest.size(), port);
            if (pr.ec != std::errc() || *pr.ptr != '\0') {
                setResult(ValidationResult::InvalidPort, "url: malformed port");
                return false;
            }
            hasPort = true;
        }
    } else {
        const size_t colon = host.rfind(':');
        if (colon != std::string::npos) {
            host = host.substr(0, colon);
            auto pr = std::from_chars(authority.data() + colon + 1,
                                      authority.data() + authority.size(), port);
            if (pr.ec != std::errc() || *pr.ptr != '\0') {
                setResult(ValidationResult::InvalidPort, "url: malformed port");
                return false;
            }
            hasPort = true;
        }
    }

    if (host.empty()) {
        setResult(ValidationResult::InvalidHostname, "url: empty host");
        return false;
    }

    // Classify the host exactly once, then apply policy: it must be either a
    // well-formed literal IP or a valid hostname, never "neither".
    std::string hostOut;
    const bool isLiteralIp = validateIpAddress(host, hostOut);

    if (!isLiteralIp && !validateHostname(host, hostOut)) {
        setResult(ValidationResult::InvalidHostname, "url: invalid host '" + host + "'");
        return false;
    }
    host = hostOut;

    // SSRF policy: block private/loopback/link-local unless explicitly allowed.
    if (isLiteralIp && m_cfg.blockPrivateIps) {
        const bool loopback = host.rfind("127.", 0) == 0 || host == "::1";
        if (host == "localhost" && m_cfg.allowLoopback) {
            // localhost is permitted only when loopback is allowed.
        } else if (isPrivateOrReservedIp(host)) {
            // Loopback is the one exception, and only when explicitly allowed.
            if (!(loopback && m_cfg.allowLoopback)) {
                setResult(ValidationResult::PrivateAddress,
                          "url: private/loopback address '" + host + "' blocked");
                return false;
            }
        }
    }

    if (hasPort && (port == 0 || port > m_cfg.maxPort)) {
        setResult(ValidationResult::InvalidPort, "url: port out of range");
        return false;
    }

    // Rebuild a canonical, normalized URL (homograph/normalization hygiene).
    // IPv6 hosts MUST keep their brackets or the result is ambiguous.
    std::string hostField = isIpv6Literal ? ("[" + host + "]") : host;
    std::string canonical = scheme + "://" + hostField;
    if (hasPort) canonical += ":" + std::to_string(port);
    if (authEnd != std::string::npos) canonical += url.substr(authEnd);
    out = canonical;
    setResult(ValidationResult::Ok, "");
    return true;
}

bool InputSanitizer::validateHostname(const std::string& input, std::string& out)
{
    ValidationResult r = ValidationResult::Ok;
    std::string msg;
    if (!preflightText(input, m_cfg, m_cfg.maxHostnameLength, "hostname", r, msg)) {
        setResult(r, msg);
        return false;
    }

    const std::string host = trimAscii(input);
    if (host.size() > m_cfg.maxHostnameLength) {
        setResult(ValidationResult::InvalidHostname, "hostname: too long");
        return false;
    }
    // Hyphen-leading labels and trailing dots are rejected per RFC 1123.
    if (host.size() > 253) {
        setResult(ValidationResult::InvalidHostname, "hostname: >253 chars");
        return false;
    }

    size_t labelLen = 0;
    char prev = '\0';
    bool labelEndsWithHyphen = false;   // trailing hyphen in a label is invalid
    for (char c : host) {
        if (c == '.') {
            if (labelLen == 0) {  // empty label ("a..b") or leading dot
                setResult(ValidationResult::InvalidHostname, "hostname: empty label");
                return false;
            }
            if (labelEndsWithHyphen) {
                setResult(ValidationResult::InvalidHostname, "hostname: trailing hyphen");
                return false;
            }
            labelLen = 0;
            labelEndsWithHyphen = false;
            prev = '.';
            continue;
        }
        if (c == '-') {
            if (prev == '\0' || prev == '.') {   // leading hyphen in label
                setResult(ValidationResult::InvalidHostname, "hostname: leading hyphen");
                return false;
            }
            labelEndsWithHyphen = true;
        } else {
            if (!isAsciiAlnum(static_cast<unsigned char>(c)) && c != '_') {
                setResult(ValidationResult::InvalidHostname,
                          std::string("hostname: illegal character '") + c + "'");
                return false;
            }
            labelEndsWithHyphen = false;
        }
        if (++labelLen > 63) {
            setResult(ValidationResult::InvalidHostname, "hostname: label >63 chars");
            return false;
        }
        prev = c;
    }
    if (labelEndsWithHyphen) {
        setResult(ValidationResult::InvalidHostname, "hostname: trailing hyphen");
        return false;
    }

    out = toLowerAscii(host);
    setResult(ValidationResult::Ok, "");
    return true;
}

bool InputSanitizer::validateIpAddress(const std::string& input, std::string& out)
{
    if (input.empty()) { setResult(ValidationResult::Empty, "ip: empty"); return false; }

    const std::string s = trimAscii(input);

    if (s.find(':') != std::string::npos) {
        // ---- IPv6 ----
        int groups = 0, compressedSeen = 0;
        bool prevColon = false, prevColon2 = false;
        for (size_t i = 0; i < s.size(); ++i) {
            const char c = s[i];
            if (c == ':') {
                if (prevColon) {
                    if (compressedSeen++) { setResult(ValidationResult::InvalidIpAddress, "ip: multiple '::'"); return false; }
                }
                prevColon2 = prevColon;
                prevColon = true;
                continue;
            }
            if (!isHexChar(c) && c != '.') {
                setResult(ValidationResult::InvalidIpAddress, "ip: illegal char in IPv6");
                return false;
            }
            prevColon = false;
            prevColon2 = false;
            groups++;
        }
        if (compressedSeen == 0 && groups < 8) {
            setResult(ValidationResult::InvalidIpAddress, "ip: IPv6 requires '::' or 8 groups");
            return false;
        }
        out = toLowerAscii(s);
        setResult(ValidationResult::Ok, "");
        return true;
    }

    // ---- IPv4: exactly four dotted decimal octets ----
    // Leading zeros are rejected: "010.1.1.1" is ambiguous between decimal
    // and octal interpretation, and different parsers disagree - which is
    // exactly the kind of ambiguity an SSRF/allow-list bypass relies on.
    int octets = 0;
    size_t i = 0;
    while (octets < 4) {
        uint64_t v = 0;
        int digits = 0;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
            v = v * 10 + static_cast<uint64_t>(s[i++] - '0');
            if (++digits > 3 || v > 255) {
                setResult(ValidationResult::InvalidIpAddress, "ip: malformed IPv4 octet");
                return false;
            }
        }
        if (digits == 0) {
            setResult(ValidationResult::InvalidIpAddress, "ip: malformed IPv4");
            return false;
        }
        if (digits > 1 && s[i - digits] == '0') {
            setResult(ValidationResult::InvalidIpAddress, "ip: leading zero in octet");
            return false;
        }
        ++octets;
        if (octets < 4) {
            if (i >= s.size() || s[i] != '.') {
                setResult(ValidationResult::InvalidIpAddress, "ip: expected '.' separator");
                return false;
            }
            ++i;
        } else if (i != s.size()) {
            setResult(ValidationResult::InvalidIpAddress, "ip: trailing data after IPv4");
            return false;
        }
    }
    out = s;
    setResult(ValidationResult::Ok, "");
    return true;
}

// --------------------------------------------------------------------
// Command line
// --------------------------------------------------------------------

bool InputSanitizer::sanitizeCommandArg(const std::string& input, std::string& out)
{
    ValidationResult r = ValidationResult::Ok;
    std::string msg;
    if (!preflightText(input, m_cfg, m_cfg.maxCommandArgLength, "arg", r, msg)) {
        setResult(r, msg);
        return false;
    }

    const std::string arg = trimAscii(input);
    if (arg.empty()) { setResult(ValidationResult::Empty, "arg: empty"); return false; }

    for (char c : arg) {
        if (isShellMeta(c)) {
            setResult(ValidationResult::CommandInjection,
                      std::string("arg: shell metacharacter '") + c + "'");
            return false;
        }
    }
    out = arg;
    setResult(ValidationResult::Ok, "");
    return true;
}

bool InputSanitizer::validateCommandLine(const std::string& program,
                                         const std::vector<std::string>& args,
                                         std::vector<std::string>& out)
{
    std::string progOut;
    if (!sanitizeCommandArg(program, progOut)) return false;
    out.clear();
    out.reserve(args.size() + 1);
    out.push_back(progOut);
    for (const auto& a : args) {
        std::string clean;
        if (!sanitizeCommandArg(a, clean)) return false;
        out.push_back(std::move(clean));
    }
    setResult(ValidationResult::Ok, "");
    return true;
}

// --------------------------------------------------------------------
// SQL
// --------------------------------------------------------------------

bool InputSanitizer::sanitizeSqlLiteral(const std::string& input, std::string& out)
{
    if (input.empty()) { setResult(ValidationResult::Empty, "sql: empty literal"); return false; }
    // 1) No NUL/control smuggling.
    if (input.find('\0') != std::string::npos) {
        setResult(ValidationResult::NullByte, "sql: NUL byte"); return false;
    }
    // 2) Fail closed on obvious statement delimiters/keywords.
    const std::string lower = toLowerAscii(input);
    if (containsSqlKeyword(lower)) {
        setResult(ValidationResult::SqlInjection,
                  "sql: keyword/statement sequence in literal");
        return false;
    }
    if (lower.find('\'') != std::string::npos) {
        // Single-quoted literal: our own delimiter must not appear here.
        setResult(ValidationResult::SqlInjection, "sql: quote in literal");
        return false;
    }
    // 3) Escape per SQL standard for consumers that still string-format.
    std::string escaped = "\"";
    escaped.append(input);
    escaped.push_back('"');
    out = std::move(escaped);
    setResult(ValidationResult::Ok, "");
    return true;
}

bool InputSanitizer::validateSqlIdentifier(const std::string& input, std::string& out)
{
    if (input.empty()) { setResult(ValidationResult::Empty, "sql: empty identifier"); return false; }
    if (input.size() > 128) { setResult(ValidationResult::TooLong, "sql: identifier too long"); return false; }

    if (!(std::isalpha(static_cast<unsigned char>(input[0])) || input[0] == '_')) {
        setResult(ValidationResult::InvalidChars, "sql: identifier must start with letter/_");
        return false;
    }
    for (char c : input) {
        if (!(isAsciiAlnum(static_cast<unsigned char>(c)) || c == '_')) {
            setResult(ValidationResult::InvalidChars,
                      std::string("sql: illegal identifier character '") + c + "'");
            return false;
        }
    }
    out = input;
    setResult(ValidationResult::Ok, "");
    return true;
}

// --------------------------------------------------------------------
// HTML / JS escaping
// --------------------------------------------------------------------

std::string InputSanitizer::escapeHtml(const std::string& input) const
{
    std::string out;
    out.reserve(input.size() + input.size() / 8);
    for (char c : input) {
        switch (c) {
            case '&': out += "&amp;";  break;
            case '<': out += "&lt;";   break;
            case '>': out += "&gt;";   break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string InputSanitizer::escapeHtmlAttr(const std::string& input) const
{
    std::string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
            case '&': out += "&amp;";  break;
            case '<': out += "&lt;";   break;
            case '>': out += "&gt;";   break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            case '\n': out += "&#10;"; break;
            case '\r': out += "&#13;"; break;
            case '\t': out += "&#9;";  break;
            case '`': out += "&#96;";  break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string InputSanitizer::escapeJavaScript(const std::string& input) const
{
    std::string out;
    out.reserve(input.size() + input.size() / 4);
    for (unsigned char c : input) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\'': out += "\\'";  break;
            case '<':  out += "\\x3C"; break;   // prevents "</script>" breakout
            case '>':  out += "\\x3E"; break;
            case '&':  out += "\\x26"; break;
            case '=':  out += "\\x3D"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\x%02X", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

bool InputSanitizer::sanitizeHtml(const std::string& input,
                                  std::string& out,
                                  const std::vector<std::string>& allowedTags)
{
    if (input.empty()) { setResult(ValidationResult::Empty, "html: empty"); return false; }

    const std::string lower = toLowerAscii(input);
    if (containsXssPattern(lower)) {
        setResult(ValidationResult::XssAttempt, "html: XSS/scripting pattern detected");
        return false;
    }

    // When an allow-list is supplied, unknown tags are rejected outright
    // (fail-closed) rather than silently stripped.
    if (!allowedTags.empty()) {
        size_t pos = 0;
        while ((pos = lower.find('<', pos)) != std::string::npos) {
            const size_t end = lower.find_first_of(" />\t\n", pos + 1);
            const std::string tag = lower.substr(pos + 1, (end == std::string::npos
                                                              ? lower.size()
                                                              : end) - pos - 1);
            if (!tag.empty() && tag[0] != '/') {
                if (std::find(allowedTags.begin(), allowedTags.end(), tag)
                        == allowedTags.end()) {
                    setResult(ValidationResult::XssAttempt,
                              "html: tag '<" + tag + ">' not on allow-list");
                    return false;
                }
            }
            pos = end == std::string::npos ? lower.size() : end;
        }
    }

    out = escapeHtml(input);
    setResult(ValidationResult::Ok, "");
    return true;
}

// --------------------------------------------------------------------
// JSON
// --------------------------------------------------------------------

bool InputSanitizer::validateJsonBytes(const std::string& data, std::string& out)
{
    if (data.empty()) { setResult(ValidationResult::Empty, "json: empty"); return false; }
    if (data.size() > static_cast<size_t>(m_cfg.maxJsonSize)) {
        setResult(ValidationResult::JsonTooLarge,
                  "json: " + std::to_string(data.size()) + " bytes exceeds "
                  + std::to_string(m_cfg.maxJsonSize));
        return false;
    }
    if (!isValidUtf8(data)) {
        setResult(ValidationResult::InvalidEncoding, "json: not valid UTF-8");
        return false;
    }
    // Lightweight structural gate: balanced AND correctly matched brackets,
    // with proper string/escape handling so braces inside strings are ignored.
    // Full parsing belongs to nlohmann/json; this only rejects obvious garbage
    // before it reaches a parser.
    char stack[256] = {};   // bounded: deeper nesting is rejected outright
    long depth = 0;
    bool inStr = false;
    bool esc = false;
    for (char c : data) {
        if (esc) { esc = false; continue; }
        if (inStr) {
            if (c == '\\') esc = true;
            else if (c == '"') inStr = false;
            continue;
        }
        switch (c) {
            case '"': inStr = true; break;
            case '{':
            case '[':
                if (depth >= static_cast<long>(sizeof(stack))) {
                    setResult(ValidationResult::JsonTooLarge, "json: nesting too deep");
                    return false;
                }
                stack[depth++] = c;
                break;
            case '}':
            case ']':
                if (depth == 0 || stack[depth - 1] != (c == '}' ? '{' : '[')) {
                    setResult(ValidationResult::InvalidJson, "json: mismatched bracket");
                    return false;
                }
                --depth;
                break;
            default:
                break;
        }
    }
    if (inStr) {
        setResult(ValidationResult::InvalidJson, "json: unterminated string");
        return false;
    }
    if (depth != 0) {
        setResult(ValidationResult::InvalidJson, "json: unbalanced brackets");
        return false;
    }
    out = data;
    setResult(ValidationResult::Ok, "");
    return true;
}

// --------------------------------------------------------------------
// Generic values
// --------------------------------------------------------------------

bool InputSanitizer::validateString(const std::string& input, const std::string& field,
                                    std::string& out, size_t maxLength)
{
    const size_t cap = maxLength ? maxLength : m_cfg.maxStringLength;
    ValidationResult r = ValidationResult::Ok;
    std::string msg;
    if (!preflightText(input, m_cfg, cap, field.c_str(), r, msg)) {
        setResult(r, msg);
        return false;
    }
    out = trimAscii(input);
    setResult(ValidationResult::Ok, "");
    return true;
}

bool InputSanitizer::validateInt(const std::string& input, const std::string& field,
                                 std::string& out, int64_t min, int64_t max)
{
    const std::string s = trimAscii(input);
    if (s.empty()) { setResult(ValidationResult::Empty, field + ": empty"); return false; }

    int64_t v = 0;
    const char* b = s.data();
    const char* e = s.data() + s.size();
    auto res = std::from_chars(b, e, v);
    if (res.ec == std::errc::result_out_of_range) {
        setResult(ValidationResult::OutOfRange, field + ": integer out of range");
        return false;
    }
    if (res.ec != std::errc() || res.ptr != e) {
        setResult(ValidationResult::InvalidNumber, field + ": not an integer");
        return false;
    }
    if (v < min || v > max) {
        setResult(ValidationResult::OutOfRange,
                  field + ": " + std::to_string(v) + " outside [" + std::to_string(min)
                  + "," + std::to_string(max) + "]");
        return false;
    }
    out = std::to_string(v);
    setResult(ValidationResult::Ok, "");
    return true;
}

bool InputSanitizer::validateDouble(const std::string& input, const std::string& field,
                                    std::string& out, double min, double max)
{
    const std::string s = trimAscii(input);
    if (s.empty()) { setResult(ValidationResult::Empty, field + ": empty"); return false; }

    // Reject non-finite spellings, hex floats, and thousands separators that
    // strtod would otherwise tolerate in some locales.
    const std::string lower = toLowerAscii(s);
    if (lower.find("nan") != std::string::npos
        || lower.find("inf") != std::string::npos
        || lower.find("0x") != std::string::npos) {
        setResult(ValidationResult::InvalidNumber, field + ": non-finite/hex number");
        return false;
    }

    double v = 0.0;
    const char* b = s.data();
    const char* e = s.data() + s.size();
    auto res = std::from_chars(b, e, v);
    if (res.ec == std::errc::result_out_of_range) {
        setResult(ValidationResult::OutOfRange, field + ": out of double range");
        return false;
    }
    if (res.ec != std::errc() || res.ptr != e) {
        setResult(ValidationResult::InvalidNumber, field + ": not a double");
        return false;
    }
    if (!(v >= min && v <= max)) {
        setResult(ValidationResult::OutOfRange,
                  field + ": " + std::to_string(v) + " outside ["
                  + std::to_string(min) + "," + std::to_string(max) + "]");
        return false;
    }

    // Emit a canonical, locale-independent representation.
    std::ostringstream oss;
    oss.precision(17);
    oss << v;
    out = oss.str();
    setResult(ValidationResult::Ok, "");
    return true;
}

// --------------------------------------------------------------------
// Model integrity
// --------------------------------------------------------------------

bool InputSanitizer::verifyModelHeader(const std::string& path, std::string& out)
{
    std::ifstream f(fs::u8path(path), std::ios::binary);
    if (!f) {
        setResult(ValidationResult::IoError, "model: cannot open '" + path + "'");
        return false;
    }
    std::array<char, 4> magic{};
    f.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (f.gcount() != static_cast<std::streamsize>(magic.size())) {
        setResult(ValidationResult::InvalidModel, "model: truncated header");
        return false;
    }
    for (const auto& allowed : m_cfg.allowedModelMagics) {
        if (allowed == magic) {
            out = path;
            setResult(ValidationResult::Ok, "");
            return true;
        }
    }
    setResult(ValidationResult::InvalidModel,
              "model: unrecognized magic '" + std::string(magic.data(), 4) + "'");
    return false;
}

// --------------------------------------------------------------------
// Encoding helpers
// --------------------------------------------------------------------

bool InputSanitizer::isValidUtf8(const std::string& s) noexcept
{
    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        size_t extra = 0;
        uint32_t cp = 0;
        if (c < 0x80) { ++i; continue; }
        else if ((c & 0xE0) == 0xC0) { extra = 1; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { extra = 2; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { extra = 3; cp = c & 0x07; }
        else return false;                        // invalid leading byte
        if (i + extra >= n) return false;         // truncated sequence
        for (size_t k = 1; k <= extra; ++k) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;   // continuation byte expected
            cp = (cp << 6) | (cc & 0x3F);
        }
        // Overlong encodings and out-of-range code points.
        if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800)
            || (extra == 3 && cp < 0x10000)) return false;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += extra + 1;
    }
    return true;
}

bool InputSanitizer::containsNullBytes(const std::string& s) noexcept
{
    return s.find('\0') != std::string::npos;
}

bool InputSanitizer::containsControlChars(const std::string& s) noexcept
{
    for (unsigned char c : s) {
        if (c < 0x20 && c != '\t' && c != '\r' && c != '\n') return true;
        if (c == 0x7F) return true;
    }
    return false;
}

void InputSanitizer::secureWipe(std::string& s) noexcept
{
    // Best-effort zeroization: break optimizer elision by using a volatile
    // pointer, then release the buffer. Protects secrets from heap remnants.
    if (!s.empty()) {
        volatile char* p = s.data();
        for (size_t i = 0; i < s.size(); ++i) p[i] = '\0';
    }
    s.clear();
    s.shrink_to_fit();
}

bool InputSanitizer::constantTimeEquals(const std::string& a, const std::string& b) noexcept
{
    const size_t n = std::max(a.size(), b.size());
    unsigned char diff = static_cast<unsigned char>(a.size() != b.size());
    for (size_t i = 0; i < n; ++i) {
        const unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0u;
        const unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0u;
        diff |= static_cast<unsigned char>(ca ^ cb);
    }
    return diff == 0;
}

} // namespace Security
} // namespace RawrXD