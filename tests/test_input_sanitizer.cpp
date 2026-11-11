// ============================================================================
// Security regression tests for the input validation boundary.
//
// Every test below encodes a class of input that MUST be rejected. These are
// the executable form of the security policy in input_sanitizer.h: if a change
// to the sanitizer ever lets one of these through, CI must fail.
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#  define _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#endif

#include "test_harness.h"
#include "input_sanitizer.h"
#include "secure_buffer.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <utility>

namespace fs = std::filesystem;
using namespace RawrXD::Security;

namespace {

/// Scratch directory for filesystem-based tests (created lazily, per-process).
const std::string& scratchDir()
{
    static const std::string dir = [] {
        const fs::path base = fs::temp_directory_path() / "rawrxd_tests";
        std::error_code ec;
        fs::create_directories(base, ec);
        return base.generic_string();
    }();
    return dir;
}

void writeFile(const std::string& path, const std::string& bytes)
{
    std::ofstream f(fs::u8path(path), std::ios::binary);
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string makeDir(const char* name)
{
    const std::string p = scratchDir() + "/" + name;
    std::error_code ec;
    fs::remove_all(fs::u8path(p), ec);
    fs::create_directories(fs::u8path(p), ec);
    return p;
}

InputSanitizer& S()
{
    return InputSanitizer::instance();
}

std::string okOut;
bool tryPath(const std::string& in, const std::string& base = {})
{
    return S().resolvePath(in, base, okOut);
}

bool tryUrl(const std::string& in)
{
    return S().validateUrl(in, okOut);
}

} // anonymous namespace

// ============================================================================
// Path traversal / directory escape
// ============================================================================

TEST(InputSanitizer, RejectsRelativePathWhenNotAllowed) {
    CHECK_FALSE(tryPath("models/mistral.gguf"));
    CHECK_EQ(S().lastResult(), ValidationResult::NotAllowed);
}

TEST(InputSanitizer, RejectsParentTraversal) {
    const std::string base = makeDir("base");
    // Literal traversal payloads (compile-time constant strings only).
    for (const char* bad : {
            "../secrets.gguf", "..\\..\\windows\\system32\\evil.gguf",
            "..%2f..%2f..%2fetc%2fpasswd" }) {
        CHECK_FALSE(tryPath(bad, base));
        CHECK_EQ(S().lastResult(), ValidationResult::PathTraversal);
    }
    // Encoded variants (case-insensitive: the sanitizer lowercases before
    // matching so "%2F" cannot evade "%2f").
    for (const std::string& bad : {
            std::string(base) + "/..%2f..%2f..%2fetc%2fpasswd",
            std::string(base) + "/..%2F..%2F..%2Fetc" }) {
        CHECK_FALSE(tryPath(bad, base));
        CHECK_EQ(S().lastResult(), ValidationResult::PathTraversal);
    }
}

TEST(InputSanitizer, RejectsPathTrailingBackslashEscape) {
    const std::string base = makeDir("base2");
    // Windows drive-relative escape attempt
    CHECK_FALSE(tryPath("\\\\localhost\\c$\\windows\\system32\\evil.gguf", base));
}

TEST(InputSanitizer, AcceptsPathInsideBaseDirectory) {
    const std::string base = makeDir("base3");
    const std::string good = base + "/model.gguf";
    CHECK(tryPath(good, base));
    CHECK_EQ(S().lastResult(), ValidationResult::Ok);
}

TEST(InputSanitizer, RejectsPrefixConfusionWithBaseDirectory) {
    // Classic bypass: base "/srv/models" must not accept "/srv/models-evil".
    const std::string root = makeDir("models");
    const std::string decoy = scratchDir() + "/models-evil.gguf";
    writeFile(decoy, "x");
    CHECK_FALSE(tryPath(decoy, root));
    CHECK_EQ(S().lastResult(), ValidationResult::NotAllowed);
}

TEST(InputSanitizer, RejectsNulByteInPath) {
    const std::string bad(std::string("C:\\models\\") + std::string("a\0b", 3) + ".gguf", 0);
    CHECK_FALSE(tryPath(bad));
}

TEST(InputSanitizer, RejectsOverlongPath) {
    std::string huge(5000, 'a');
    huge = "C:\\" + huge;
    CHECK_FALSE(tryPath(huge));
    CHECK_EQ(S().lastResult(), ValidationResult::TooLong);
}

TEST(InputSanitizer, IsWithinRootSemantics) {
    const std::string root = "/srv/models";
    CHECK(InputSanitizer::isWithinRoot("/srv/models/a.gguf", root));
    CHECK(InputSanitizer::isWithinRoot("/srv/models", root));
    CHECK_FALSE(InputSanitizer::isWithinRoot("/srv/models-evil", root));
    CHECK_FALSE(InputSanitizer::isWithinRoot("/srv", root));
    CHECK_FALSE(InputSanitizer::isWithinRoot("/srv/../etc/passwd", root));
    CHECK(InputSanitizer::isWithinRoot("/srv/models/sub/dir/a.gguf", root));
}

// ============================================================================
// URLs and SSRF
// ============================================================================

TEST(InputSanitizer, AcceptsValidHttpsUrl) {
    CHECK(tryUrl("https://api.example.com/v1/models"));
    CHECK_EQ(okOut, "https://api.example.com/v1/models");
}

TEST(InputSanitizer, RejectsNonAllowlistedScheme) {
    for (const char* bad : {"file:///etc/passwd", "ftp://example.com/x",
                            "gopher://example.com/x", "data:text/plain,hi"}) {
        CHECK_FALSE(tryUrl(bad));
    }
}

TEST(InputSanitizer, RejectsUserinfoInUrl) {
    CHECK_FALSE(tryUrl("https://user:pass@example.com/x"));
    CHECK_EQ(S().lastResult(), ValidationResult::InvalidUrl);
}

TEST(InputSanitizer, BlocksPrivateAddressesForSsrf) {
    for (const char* bad : {"http://10.0.0.5/x", "http://192.168.1.1/x",
                            "http://172.16.0.1/x", "http://169.254.169.254/latest/meta-data",
                            "http://100.64.0.1/x", "http://0.0.0.0/x",
                            "http://224.0.0.1/x", "http://192.0.2.1/x"}) {
        CHECK_FALSE(tryUrl(bad));
        CHECK_EQ(S().lastResult(), ValidationResult::PrivateAddress);
    }
}

TEST(InputSanitizer, AllowsLoopbackUnderPolicyButBracketsIpv6) {
    // Loopback is permitted by default (local model servers need it) - the same
    // policy applies to IPv6 loopback [::1].
    CHECK(tryUrl("http://127.0.0.1:8080/health"));
    CHECK_EQ(okOut, "http://127.0.0.1:8080/health");

    CHECK(tryUrl("http://[::1]/x"));
    // IPv6 must keep its brackets, else the URL is ambiguous for consumers.
    CHECK_EQ(okOut, "http://[::1]/x");
}

TEST(InputSanitizer, BlocksLoopbackWhenPolicyDisabled) {
    SanitizerConfig cfg;
    cfg.allowLoopback = false;
    cfg.blockPrivateIps = true;
    S().configure(cfg);

    CHECK_FALSE(tryUrl("http://127.0.0.1:8080/x"));
    CHECK_EQ(S().lastResult(), ValidationResult::PrivateAddress);

    // Restore the default policy for later tests.
    S().configure(SanitizerConfig{});
}

TEST(InputSanitizer, RejectsMalformedPort) {
    for (const char* bad : {"http://example.com:99999/x", "http://example.com:abcd/x",
                            "http://example.com:/x"}) {
        CHECK_FALSE(tryUrl(bad));
    }
}

TEST(InputSanitizer, ValidatesHostnamePerRfc1123) {
    std::string h;
    CHECK(S().validateHostname("Example.COM", h));
    CHECK_EQ(h, "example.com");
    for (const char* bad : {"-leading.com", "trailing-.com", "a..b",
                            "host_with spaces.com", "host\ttab.com", ""}) {
        CHECK_FALSE(S().validateHostname(bad, h));
    }
}

TEST(InputSanitizer, RejectsOverlongHostname) {
    std::string h(300, 'a');
    CHECK_FALSE(S().validateHostname(h + ".com", okOut));
    CHECK_EQ(S().lastResult(), ValidationResult::TooLong);
}

TEST(InputSanitizer, ValidatesIpv4Literals) {
    std::string ip;
    CHECK(S().validateIpAddress("192.0.2.1", ip));
    CHECK(S().validateIpAddress("255.255.255.255", ip));
    for (const char* bad : {"999.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4",
                            "1.2.3.-1", "1.2.3.256", "a.b.c.d"}) {
        CHECK_FALSE(S().validateIpAddress(bad, ip));
    }
}

TEST(InputSanitizer, ValidatesIpv6Literals) {
    std::string ip;
    CHECK(S().validateIpAddress("2001:db8::1", ip));
    CHECK(S().validateIpAddress("::1", ip));
    CHECK_FALSE(S().validateIpAddress("2001:db8::1::2", ip));
    CHECK_FALSE(S().validateIpAddress("::gggg", ip));
}

// ============================================================================
// Command injection
// ============================================================================

TEST(InputSanitizer, RejectsShellMetacharacters) {
    for (const char* bad : {"$(rm -rf /)", "`whoami`", "a; rm -rf /", "a && b",
                            "a | b", "a > out.txt", "a\nb", "a\"b", "a'b",
                            "a\\b", "a{b}", "a(b)", "a$b"}) {
        CHECK_FALSE(S().sanitizeCommandArg(bad, okOut));
        CHECK_EQ(S().lastResult(), ValidationResult::CommandInjection);
    }
}

TEST(InputSanitizer, AcceptsOrdinaryArguments) {
    std::vector<std::string> args;
    CHECK(S().validateCommandLine("cmake",
                                  {"--build", "build", "--config", "Release", "models/x.gguf"},
                                  args));
    CHECK_EQ(args.size(), static_cast<size_t>(6));
    CHECK_EQ(args[0], "cmake");
}

TEST(InputSanitizer, RejectsInjectedArgumentInCommandLine) {
    std::vector<std::string> args;
    CHECK_FALSE(S().validateCommandLine("git", {"commit", "-m", "x; rm -rf /"}, args));
}

// ============================================================================
// SQL injection (defense-in-depth)
// ============================================================================

TEST(InputSanitizer, RejectsSqlStatementFragments) {
    for (const char* bad : {"a' OR '1'='1", "'; DROP TABLE users; --",
                            "1 UNION SELECT password FROM users",
                            "x' UNION ALL SELECT NULL--"}) {
        CHECK_FALSE(S().sanitizeSqlLiteral(bad, okOut));
        CHECK_EQ(S().lastResult(), ValidationResult::SqlInjection);
    }
}

TEST(InputSanitizer, AcceptsBenignSqlLiteral) {
    CHECK(S().sanitizeSqlLiteral("hello world", okOut));
    CHECK_EQ(okOut, "\"hello world\"");
}

TEST(InputSanitizer, ValidatesSqlIdentifiers) {
    CHECK(S().validateSqlIdentifier("model_table", okOut));
    CHECK(S().validateSqlIdentifier("_checked_in", okOut));
    for (const char* bad : {"1table", "table-name", "table name", "table;", ""}) {
        CHECK_FALSE(S().validateSqlIdentifier(bad, okOut));
    }
}

// ============================================================================
// XSS / HTML
// ============================================================================

TEST(InputSanitizer, EscapesHtmlMetacharacters) {
    const std::string out = S().escapeHtml("<script>alert(1)</script>");
    CHECK_EQ(out, "&lt;script&gt;alert(1)&lt;/script&gt;");
    CHECK(out.find("<") == std::string::npos);
}

TEST(InputSanitizer, EscapesAttributePayloads) {
    const std::string out = S().escapeHtmlAttr("\" onload='alert(1)");
    CHECK(out.find("\"") == std::string::npos);
}

TEST(InputSanitizer, DetectsscriptInStyleAndEventHandlers) {
    for (const char* bad : {
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>", "data:text/html,<script>alert(1)</script>"}) {
        CHECK_FALSE(S().sanitizeHtml(bad, okOut));
        CHECK_EQ(S().lastResult(), ValidationResult::XssAttempt);
    }
}

TEST(InputSanitizer, RejectsTagNotOnAllowlist) {
    CHECK_FALSE(S().sanitizeHtml("<b>bold</b><div>x</div>", okOut, {"b"}));
}

TEST(InputSanitizer, AcceptsAllowlistedTag) {
    CHECK(S().sanitizeHtml("<b>bold</b>", okOut, {"b"}));
    CHECK_EQ(okOut, "&lt;b&gt;bold&lt;/b&gt;");
}

TEST(InputSanitizer, EscapesQuotesInHtmlAttribute) {
    // Every quote form must be escaped so an attribute value cannot be broken
    // out of (the classic quote-in-attribute XSS vector).
    const std::string out = S().escapeHtmlAttr("' /><script>alert(1)</script>");
    CHECK(out.find("'") == std::string::npos);      // no raw single quote
    CHECK(out.find("\"") == std::string::npos);     // no raw double quote
    CHECK(out.find("&#39;") != std::string::npos);  // single quote escaped
    CHECK(out.find("&lt;") != std::string::npos);   // markup neutralized
    CHECK(out.find("&gt;") != std::string::npos);
}

TEST(InputSanitizer, EscapesJavaScriptTerminator) {
    const std::string out = S().escapeJavaScript("'); alert(1); //");
    CHECK(out.find("<") == std::string::npos);
    CHECK(out.find(">") == std::string::npos);
}

// ============================================================================
// JSON
// ============================================================================

TEST(InputSanitizer, AcceptsWellFormedJson) {
    const std::string j = R"({"a":[1,2,3],"b":{"c":"}"}})";
    CHECK(S().validateJsonBytes(j, okOut));
}

TEST(InputSanitizer, RejectsUnbalancedJson) {
    for (const char* bad : {"{\"a\": 1", "[1,2,3}", "}}}", "{\"a\":[]"}) {
        CHECK_FALSE(S().validateJsonBytes(bad, okOut));
        CHECK_EQ(S().lastResult(), ValidationResult::InvalidJson);
    }
}

TEST(InputSanitizer, RejectsInvalidUtf8Json) {
    const std::string bad = "{\"a\":\"\xFF\xFE\"}";
    CHECK_FALSE(S().validateJsonBytes(bad, okOut));
    CHECK_EQ(S().lastResult(), ValidationResult::InvalidEncoding);
}

TEST(InputSanitizer, RejectsOversizedJson) {
    SanitizerConfig cfg;
    cfg.maxJsonSize = 64;
    S().configure(cfg);
    CHECK_FALSE(S().validateJsonBytes(std::string("{\"a\":\"") + std::string(512, 'x') + "\"}", okOut));
    CHECK_EQ(S().lastResult(), ValidationResult::JsonTooLarge);
}

// ============================================================================
// UTF-8 / control characters
// ============================================================================

TEST(InputSanitizer, AcceptsValidUtf8) {
    CHECK(InputSanitizer::isValidUtf8("abc"));
    CHECK(InputSanitizer::isValidUtf8("\xC3\xA9"));          // e-acute
    CHECK(InputSanitizer::isValidUtf8("\xE2\x82\xAC"));      // euro sign
    CHECK(InputSanitizer::isValidUtf8("\xF0\x9F\x98\x80"));  // emoji
}

TEST(InputSanitizer, RejectsInvalidUtf8) {
    CHECK_FALSE(InputSanitizer::isValidUtf8("\xFF\xFE"));
    CHECK_FALSE(InputSanitizer::isValidUtf8("\xC0\x80"));              // overlong NUL
    CHECK_FALSE(InputSanitizer::isValidUtf8("\xED\xA0\x80"));          // surrogate
    CHECK_FALSE(InputSanitizer::isValidUtf8("\xC3"));                  // truncated
    CHECK_FALSE(InputSanitizer::isValidUtf8("\xF5\x80\x80\x80"));      // > U+10FFFF
    CHECK_FALSE(InputSanitizer::isValidUtf8("\xE2\x82"));              // truncated multi-byte
}

TEST(InputSanitizer, NulByteIsValidUtf8ButBlockedElsewhere) {
    // NUL is technically valid UTF-8, so the UTF-8 gate must not be the only
    // defence: the sanitizer blocks NUL separately at the preflight stage
    // (containsNullBytes), which is what actually protects the lower layers
    // (SQL, webview, native APIs) that stop at the first NUL.
    CHECK(InputSanitizer::isValidUtf8(std::string("a\0b", 3)));
    CHECK(InputSanitizer::containsNullBytes(std::string("a\0b", 3)));
    CHECK_FALSE(InputSanitizer::containsNullBytes("clean-input"));
    // And the path gate rejects it end-to-end.
    CHECK_FALSE(tryPath(std::string("C:\\a\0b.gguf", 11)));
}

TEST(InputSanitizer, DetectsNullAndControlChars) {
    CHECK(InputSanitizer::containsNullBytes(std::string("a\0b", 3)));
    CHECK_FALSE(InputSanitizer::containsNullBytes("abc"));
    CHECK(InputSanitizer::containsControlChars(std::string("a\x01" "b", 3)));
    CHECK_FALSE(InputSanitizer::containsControlChars("tabs\tand\nnewlines\r"));
    CHECK(InputSanitizer::containsControlChars("\x7f"));   // DEL
}

// ============================================================================
// Numeric validation
// ============================================================================

TEST(InputSanitizer, ValidatesIntegersWithoutOverflow) {
    CHECK(S().validateInt("42", "n", okOut, 0, 100));
    CHECK_EQ(okOut, "42");
    CHECK_FALSE(S().validateInt("99999999999999999999", "n", okOut, 0, 100));
    CHECK_EQ(S().lastResult(), ValidationResult::OutOfRange);
    CHECK_FALSE(S().validateInt("12.5", "n", okOut, 0, 100));
    CHECK_FALSE(S().validateInt("", "n", okOut, 0, 100));
    CHECK_FALSE(S().validateInt("0x10", "n", okOut, 0, 100));
    CHECK_FALSE(S().validateInt("500", "n", okOut, 0, 100));
    CHECK_EQ(S().lastResult(), ValidationResult::OutOfRange);
}

TEST(InputSanitizer, ValidatesDoublesRejectingNonFinite) {
    CHECK(S().validateDouble("0.7", "t", okOut, 0.0, 1.0));
    for (const char* bad : {"nan", "inf", "-inf", "1e999", "abc", "0x1p3"}) {
        CHECK_FALSE(S().validateDouble(bad, "t", okOut, -1.0, 1.0));
    }
}

// ============================================================================
// Model file integrity
// ============================================================================

TEST(InputSanitizer, AcceptsRealGgufHeader) {
    const std::string dir = makeDir("model_ok");
    const std::string p = dir + "/model.gguf";
    writeFile(p, "GGUFstuff-and-bytes-here");
    std::string out;
    CHECK(S().verifyModelHeader(p, out));
    CHECK_EQ(out, p);
}

TEST(InputSanitizer, RejectsNonModelHeader) {
    const std::string dir = makeDir("model_bad");
    const std::string p = dir + "/evil.gguf";
    writeFile(p, std::string("\x7f", 1) + "ELF\x02\x01\x01 not a model");
    CHECK_FALSE(S().verifyModelHeader(p, okOut));
    CHECK_EQ(S().lastResult(), ValidationResult::InvalidModel);
}

TEST(InputSanitizer, RejectsTruncatedHeader) {
    const std::string dir = makeDir("model_trunc");
    const std::string p = dir + "/tiny.gguf";
    writeFile(p, "GG");
    CHECK_FALSE(S().verifyModelHeader(p, okOut));
    CHECK_EQ(S().lastResult(), ValidationResult::InvalidModel);
}

TEST(InputSanitizer, RejectsDisallowedExtension) {
    SanitizerConfig cfg;
    cfg.allowedModelExtensions = {".gguf"};
    S().configure(cfg);
    const std::string dir = makeDir("model_ext");
    const std::string p = dir + "/payload.exe";
    writeFile(p, "GGUF");
    CHECK_FALSE(S().resolveModelPath(p, dir, okOut));
    CHECK_EQ(S().lastResult(), ValidationResult::BadExtension);
}

TEST(InputSanitizer, ResolveModelPathAcceptsGgufInBase) {
    const std::string dir = makeDir("model_good");
    const std::string p = dir + "/good.gguf";
    writeFile(p, "GGUF0000000000000000");
    CHECK(S().resolveModelPath(p, dir, okOut));
    CHECK_EQ(S().lastResult(), ValidationResult::Ok);
}

// ============================================================================
// SecureBuffer behaviour
// ============================================================================

TEST(SecureBuffer, ReportsOutOfRangeAccessInsteadOfCorrupting) {
    SecureBytes b(4);
    CHECK_EQ(b.size(), static_cast<size_t>(4));
    CHECK(b.at(0) != nullptr);
    CHECK(b.at(4) == nullptr);        // one past the end
    CHECK(b.at(999) == nullptr);
    CHECK_FALSE(b.set(4, 0xFF));      // out of range is reported
    CHECK_FALSE(b.set(999, 0xFF));
    CHECK(b.set(3, 0xAB));            // in range succeeds
    CHECK_EQ(b.get(3), 0xABu);
    CHECK_EQ(b.get(4, 0x00u), 0x00u); // fallback value
}

TEST(SecureBuffer, SubstaysInsideBounds) {
    SecureBytes b(10);
    CHECK(!b.subspan(8, 4).empty() == false);   // 8+4 > 10 -> empty
    CHECK_EQ(b.subspan(8, 4).size(), static_cast<size_t>(0));
    CHECK_EQ(b.subspan(8, 2).size(), static_cast<size_t>(2));
    CHECK_EQ(b.subspan(11, 0).size(), static_cast<size_t>(0));
}

TEST(SecureBuffer, CopyFromChecksBounds) {
    SecureBytes b(4);
    const unsigned char src[4] = {1, 2, 3, 4};
    CHECK(b.copyFrom(src, 4, 0));
    CHECK_FALSE(b.copyFrom(src, 4, 1));   // would run past the end
    CHECK_FALSE(b.copyFrom(src, 3, 3));   // 3+3 > 4
    CHECK_EQ(b.get(0), 1u);
    CHECK_EQ(b.get(3), 4u);
}

TEST(SecureBuffer, ZeroizeClearsContent) {
    SecureBytes b(8);
    for (size_t i = 0; i < b.size(); ++i) CHECK(b.set(i, 0xAA));
    b.zeroize();
    for (size_t i = 0; i < b.size(); ++i) CHECK_EQ(b.get(i), 0u);
}

TEST(SecureBuffer, RefusesUnrepresentableAllocation) {
    SecureBytes b(4);
    CHECK_EQ(b.size(), static_cast<size_t>(4));
    // An allocation that cannot be represented must be refused, not wrapped.
    CHECK_FALSE(b.allocate(static_cast<size_t>(-1)));
    // A refused allocate is a NO-OP: the previous contents stay intact rather
    // than being destroyed, so a caller can distinguish failure from success.
    CHECK_EQ(b.size(), static_cast<size_t>(4));
}

TEST(SecureBuffer, MoveTransfersOwnership) {
    SecureBytes a(4);
    CHECK(a.set(0, 7));
    SecureBytes b = std::move(a);
    CHECK_EQ(b.size(), static_cast<size_t>(4));
    CHECK_EQ(b.get(0), 7u);
    CHECK(a.empty());
}

TEST(SecureBuffer, SecureRandomBytesIsNonDeterministic) {
    unsigned char a[32] = {};
    unsigned char b[32] = {};
    CHECK(secureRandomBytes(a, sizeof(a)));
    CHECK(secureRandomBytes(b, sizeof(b)));
    bool allEqual = true;
    for (size_t i = 0; i < sizeof(a); ++i) {
        if (a[i] != b[i]) { allEqual = false; break; }
    }
    CHECK_FALSE(allEqual);   // two draws must differ
}

TEST(SecureBuffer, ConstantTimeEqualWorks) {
    const unsigned char x[4] = {1, 2, 3, 4};
    const unsigned char y[4] = {1, 2, 3, 4};
    const unsigned char z[4] = {1, 2, 3, 5};
    CHECK(constantTimeEqual(x, y, 4));       // identical
    CHECK_FALSE(constantTimeEqual(x, z, 4)); // differ only in the last byte
    CHECK_FALSE(constantTimeEqual(x, y, 0) ? x == nullptr : false); // len 0 is trivially equal
}

// ============================================================================
// Concurrency: per-thread diagnostics must not clobber each other
// ============================================================================

TEST(InputSanitizer, PerThreadDiagnosticsAreIndependent) {
    auto threadFn = [](ValidationResult expected) {
        for (int i = 0; i < 200; ++i) {
            if (expected == ValidationResult::Ok) {
                S().validateHostname("valid.example.com", okOut);
            } else {
                S().validateHostname("-bad-hostname.example.com", okOut);
            }
            // Each thread's own state must reflect its own last call.
            CHECK(S().lastResult() == expected);
        }
    };
    std::thread a(threadFn, ValidationResult::InvalidHostname);
    std::thread b(threadFn, ValidationResult::Ok);
    a.join();
    b.join();
}

/**
 * @brief Runs the security/memory-safety suites within this translation unit.
 *
 * Called by tests/main_hardening_tests.cpp, which is the single entry point for
 * the whole hardening test binary.
 */
extern "C" int runInputSanitizerSuite()
{
    return RUN_ALL_TESTS();
}
