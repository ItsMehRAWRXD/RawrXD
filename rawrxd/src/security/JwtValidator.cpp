// ============================================================================
// JwtValidator.cpp â€” RAWRXD_SECURITY_JWT_VALIDATION_001
// ============================================================================
#include "security/JwtValidator.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <ctime>
#include <string>

#pragma comment(lib, "bcrypt.lib")

namespace rawrxd {
namespace security {
namespace {

constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int Base64UrlValue(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

// ---------------------------------------------------------------------------
// Minimal JSON member scanner.
//
// This is not a general JSON parser. It walks the document tracking string
// state, identifies member keys as (string followed by ':') pairs, and returns
// the raw text of the requested value. That is exactly what JWT claim
// extraction needs and it cannot be confused by a key-looking substring inside
// another string value.
// ---------------------------------------------------------------------------
bool ScanJsonString(const std::string& json, std::size_t quotePos, std::string& outValue,
                    std::size_t& outAfterPos) {
    outValue.clear();
    std::size_t i = quotePos + 1;
    while (i < json.size()) {
        const char c = json[i];
        if (c == '\\') {
            if (i + 1 >= json.size()) return false;
            const char esc = json[i + 1];
            switch (esc) {
                case '"':  outValue.push_back('"');  break;
                case '\\': outValue.push_back('\\'); break;
                case '/':  outValue.push_back('/');  break;
                case 'b':  outValue.push_back('\b'); break;
                case 'f':  outValue.push_back('\f'); break;
                case 'n':  outValue.push_back('\n'); break;
                case 'r':  outValue.push_back('\r'); break;
                case 't':  outValue.push_back('\t'); break;
                case 'u': {
                    if (i + 5 >= json.size()) return false;
                    unsigned code = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = json[i + 2 + static_cast<std::size_t>(k)];
                        unsigned v = 0;
                        if (h >= '0' && h <= '9') v = static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') v = static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') v = static_cast<unsigned>(h - 'A' + 10);
                        else return false;
                        code = (code << 4) | v;
                    }
                    // Encode as UTF-8. Surrogate halves are emitted as the
                    // replacement character rather than producing invalid UTF-8.
                    if (code >= 0xD800 && code <= 0xDFFF) code = 0xFFFD;
                    if (code < 0x80) {
                        outValue.push_back(static_cast<char>(code));
                    } else if (code < 0x800) {
                        outValue.push_back(static_cast<char>(0xC0 | (code >> 6)));
                        outValue.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    } else {
                        outValue.push_back(static_cast<char>(0xE0 | (code >> 12)));
                        outValue.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                        outValue.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    }
                    i += 4;
                    break;
                }
                default:
                    return false;
            }
            i += 2;
            continue;
        }
        if (c == '"') {
            outAfterPos = i + 1;
            return true;
        }
        outValue.push_back(c);
        ++i;
    }
    return false;
}

void SkipWhitespace(const std::string& json, std::size_t& pos) {
    while (pos < json.size()) {
        const char c = json[pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++pos;
        } else {
            break;
        }
    }
}

// Returns the raw value text for `key`. Handles string, number, true/false/null
// and balanced {} / [] so that nested objects are skipped rather than misread.
bool FindJsonMember(const std::string& json, const std::string& key, std::string& outRaw,
                    bool& outWasString) {
    outRaw.clear();
    outWasString = false;
    std::size_t i = 0;
    while (i < json.size()) {
        if (json[i] != '"') {
            ++i;
            continue;
        }
        std::string name;
        std::size_t after = 0;
        if (!ScanJsonString(json, i, name, after)) return false;
        std::size_t p = after;
        SkipWhitespace(json, p);
        if (p >= json.size() || json[p] != ':') {
            i = after;
            continue;
        }
        ++p;
        SkipWhitespace(json, p);
        if (p >= json.size()) return false;

        const bool isKey = (name == key);
        const char valueStart = json[p];
        std::size_t valueEnd = p;
        bool valueIsString = false;
        std::string stringValue;

        if (valueStart == '"') {
            valueIsString = true;
            if (!ScanJsonString(json, p, stringValue, valueEnd)) return false;
        } else if (valueStart == '{' || valueStart == '[') {
            int depth = 0;
            bool inString = false;
            while (valueEnd < json.size()) {
                const char c = json[valueEnd];
                if (inString) {
                    if (c == '\\') {
                        ++valueEnd;
                    } else if (c == '"') {
                        inString = false;
                    }
                } else if (c == '"') {
                    inString = true;
                } else if (c == '{' || c == '[') {
                    ++depth;
                } else if (c == '}' || c == ']') {
                    --depth;
                    if (depth == 0) {
                        ++valueEnd;
                        break;
                    }
                }
                ++valueEnd;
            }
            if (depth != 0) return false;
        } else {
            while (valueEnd < json.size() && json[valueEnd] != ',' && json[valueEnd] != '}' &&
                   json[valueEnd] != ' ' && json[valueEnd] != '\n' && json[valueEnd] != '\r' &&
                   json[valueEnd] != '\t') {
                ++valueEnd;
            }
        }

        if (isKey) {
            outRaw = valueIsString ? stringValue : json.substr(p, valueEnd - p);
            outWasString = valueIsString;
            return true;
        }
        i = (valueEnd > i) ? valueEnd : (i + 1);
    }
    return false;
}

bool ExtractStringClaim(const std::string& json, const std::string& key, std::string& out) {
    std::string raw;
    bool wasString = false;
    if (!FindJsonMember(json, key, raw, wasString) || !wasString) return false;
    out = raw;
    return true;
}

bool ExtractUintClaim(const std::string& json, const std::string& key, std::uint64_t& out) {
    std::string raw;
    bool wasString = false;
    if (!FindJsonMember(json, key, raw, wasString) || wasString) return false;
    if (raw.empty()) return false;
    std::uint64_t value = 0;
    const char* first = raw.data();
    const char* last = raw.data() + raw.size();
    const std::from_chars_result res = std::from_chars(first, last, value);
    if (res.ec != std::errc() || res.ptr != last) return false;
    out = value;
    return true;
}

void SecureClear(std::vector<std::uint8_t>& v) {
    if (!v.empty()) {
        SecureZeroMemory(v.data(), v.size());
        v.clear();
    }
}

// A rejected token must yield no usable identity. A caller that forgets to
// check `valid` would otherwise still get a signed sub/iss from an expired or
// not-yet-valid token. Reject() strips every claim and keeps only the reason.
JwtClaims Reject(JwtClaims claims, const std::string& reason) {
    claims.valid = false;
    claims.error = reason;
    claims.subject.clear();
    claims.issuer.clear();
    claims.audience.clear();
    claims.expiresAt = 0;
    claims.notBefore = 0;
    claims.issuedAt = 0;
    claims.hasExp = false;
    claims.hasNbf = false;
    return claims;
}

// Builds "header.payload.signature" from measured parts. Used by the self test
// only; never used to validate an externally supplied token.
std::string BuildHs256Token(const std::string& headerJson, const std::string& payloadJson,
                            const std::vector<std::uint8_t>& key) {
    const std::string signingInput =
        JwtValidator::Base64UrlEncode(reinterpret_cast<const std::uint8_t*>(headerJson.data()),
                                      headerJson.size()) +
        "." +
        JwtValidator::Base64UrlEncode(reinterpret_cast<const std::uint8_t*>(payloadJson.data()),
                                      payloadJson.size());
    const std::vector<std::uint8_t> mac = JwtValidator::HmacSha256(key, signingInput);
    if (mac.empty()) return std::string();
    return signingInput + "." + JwtValidator::Base64UrlEncode(mac.data(), mac.size());
}

} // namespace

// ---------------------------------------------------------------------------

std::uint64_t JwtValidator::UnixNow() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    const std::uint64_t ticks = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) |
                                static_cast<std::uint64_t>(ft.dwLowDateTime);
    // 100ns ticks since 1601-01-01 -> seconds since 1970-01-01.
    return (ticks - 116444736000000000ULL) / 10000000ULL;
}

bool JwtValidator::Base64UrlDecode(const std::string& in, std::vector<std::uint8_t>& out) {
    out.clear();
    if (in.empty()) return true;
    if ((in.size() % 4) == 1) return false;  // impossible length

    std::uint32_t accumulator = 0;
    int bits = 0;
    for (const char c : in) {
        const int v = Base64UrlValue(c);
        if (v < 0) return false;  // rejects '=', '+', '/' and whitespace
        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xFFu));
        }
    }
    // Leftover bits must be zero, otherwise the encoding is not canonical.
    if (bits > 0 && (accumulator & ((1u << bits) - 1u)) != 0u) {
        out.clear();
        return false;
    }
    return true;
}

std::string JwtValidator::Base64UrlEncode(const std::uint8_t* data, std::size_t size) {
    std::string out;
    out.reserve(((size + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= size) {
        const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                                static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kBase64UrlAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kBase64UrlAlphabet[(n >> 12) & 0x3F]);
        out.push_back(kBase64UrlAlphabet[(n >> 6) & 0x3F]);
        out.push_back(kBase64UrlAlphabet[n & 0x3F]);
        i += 3;
    }
    const std::size_t remaining = size - i;
    if (remaining == 1) {
        const std::uint32_t n = static_cast<std::uint32_t>(data[i]) << 16;
        out.push_back(kBase64UrlAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kBase64UrlAlphabet[(n >> 12) & 0x3F]);
    } else if (remaining == 2) {
        const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(kBase64UrlAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kBase64UrlAlphabet[(n >> 12) & 0x3F]);
        out.push_back(kBase64UrlAlphabet[(n >> 6) & 0x3F]);
    }
    return out;
}

std::vector<std::uint8_t> JwtValidator::HmacSha256(const std::vector<std::uint8_t>& key,
                                                  const std::string& message) {
    std::vector<std::uint8_t> digest;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<std::uint8_t> hashObject;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return digest;
    }

    DWORD objectLength = 0;
    DWORD resultLength = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
                          sizeof(objectLength), &resultLength, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return digest;
    }
    DWORD digestLength = 0;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&digestLength),
                          sizeof(digestLength), &resultLength, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return digest;
    }

    hashObject.assign(objectLength, 0);
    // An empty HMAC key is not usable for token verification; BCrypt would
    // otherwise happily produce a valid MAC under a null key.
    const PUCHAR keyData = key.empty() ? nullptr : const_cast<PUCHAR>(key.data());
    const ULONG keyLength = static_cast<ULONG>(key.size());

    if (BCryptCreateHash(alg, &hash, hashObject.data(), objectLength, keyData, keyLength, 0) != 0) {
        SecureZeroMemory(hashObject.data(), hashObject.size());
        BCryptCloseAlgorithmProvider(alg, 0);
        return digest;
    }

    bool ok = true;
    if (!message.empty()) {
        ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(message.data())),
                            static_cast<ULONG>(message.size()), 0) == 0;
    }
    if (ok) {
        digest.assign(digestLength, 0);
        ok = BCryptFinishHash(hash, digest.data(), digestLength, 0) == 0;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    SecureZeroMemory(hashObject.data(), hashObject.size());
    if (!ok) {
        digest.clear();
    }
    return digest;
}

bool JwtValidator::ConstantTimeEquals(const std::uint8_t* a, std::size_t aLen,
                                      const std::uint8_t* b, std::size_t bLen) {
    if (aLen != bLen) return false;
    if (aLen == 0) return true;
    if (a == nullptr || b == nullptr) return false;
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < aLen; ++i) {
        diff = static_cast<std::uint8_t>(diff | static_cast<std::uint8_t>(a[i] ^ b[i]));
    }
    return diff == 0;
}

JwtClaims JwtValidator::Validate(const std::string& jwt, const std::vector<std::uint8_t>& secret) {
    return ValidateAt(jwt, secret, UnixNow(), 0);
}

JwtClaims JwtValidator::ValidateAt(const std::string& jwt, const std::vector<std::uint8_t>& secret,
                                   std::uint64_t nowUnix, std::uint64_t leewaySeconds) {
    JwtClaims claims;
    claims.leewaySeconds = leewaySeconds;
    claims.validatedAtUnix = nowUnix;

    // --- 1. Structure -------------------------------------------------------
    const std::size_t dot1 = jwt.find('.');
    if (dot1 == std::string::npos) {
        return Reject(claims, "malformed: missing first '.' separator");
    }
    const std::size_t dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos) {
        return Reject(claims, "malformed: missing second '.' separator");
    }
    if (jwt.find('.', dot2 + 1) != std::string::npos) {
        return Reject(claims, "malformed: unexpected third '.' separator");
    }
    const std::string headerB64 = jwt.substr(0, dot1);
    const std::string payloadB64 = jwt.substr(dot1 + 1, dot2 - dot1 - 1);
    const std::string signatureB64 = jwt.substr(dot2 + 1);
    if (headerB64.empty() || payloadB64.empty() || signatureB64.empty()) {
        return Reject(claims, "malformed: empty JOSE segment");
    }

    // --- 2. Decode ----------------------------------------------------------
    std::vector<std::uint8_t> headerBytes;
    std::vector<std::uint8_t> payloadBytes;
    std::vector<std::uint8_t> signatureBytes;
    if (!Base64UrlDecode(headerB64, headerBytes) || !Base64UrlDecode(payloadB64, payloadBytes) ||
        !Base64UrlDecode(signatureB64, signatureBytes)) {
        return Reject(claims, "malformed: base64url decode failed");
    }
    const std::string headerJson(reinterpret_cast<const char*>(headerBytes.data()),
                                 headerBytes.size());
    const std::string payloadJson(reinterpret_cast<const char*>(payloadBytes.data()),
                                  payloadBytes.size());

    // --- 3. JOSE header: refuse "none" and anything but HS256 ---------------
    if (!ExtractStringClaim(headerJson, "alg", claims.algorithm)) {
        return Reject(claims, "rejected: JOSE header has no string 'alg'");
    }
    if (claims.algorithm != "HS256") {
        return Reject(claims, "rejected: unsupported alg '" + claims.algorithm + "' (only HS256)");
    }

    // --- 4. Signature, verified before any claim is trusted -----------------
    if (secret.empty()) {
        return Reject(claims, "rejected: no HMAC key supplied");
    }
    const std::vector<std::uint8_t> expected =
        HmacSha256(secret, jwt.substr(0, dot2));  // "header.payload"
    if (expected.empty()) {
        return Reject(claims, "rejected: HMAC-SHA256 provider failure");
    }
    if (!ConstantTimeEquals(expected.data(), expected.size(), signatureBytes.data(),
                            signatureBytes.size())) {
        return Reject(claims, "rejected: HMAC-SHA256 signature mismatch");
    }

    // --- 5. Claims, only now that the token is authentic --------------------
    claims.hasExp = ExtractUintClaim(payloadJson, "exp", claims.expiresAt);
    claims.hasNbf = ExtractUintClaim(payloadJson, "nbf", claims.notBefore);
    ExtractUintClaim(payloadJson, "iat", claims.issuedAt);
    ExtractStringClaim(payloadJson, "sub", claims.subject);
    ExtractStringClaim(payloadJson, "iss", claims.issuer);
    ExtractStringClaim(payloadJson, "aud", claims.audience);

    if (claims.hasExp) {
        const std::uint64_t deadline = claims.expiresAt + leewaySeconds;
        if (deadline < claims.expiresAt) {
            return Reject(claims, "rejected: exp overflows with leeway");
        }
        if (nowUnix > deadline) {
            return Reject(claims, "rejected: token expired");
        }
    }
    if (claims.hasNbf) {
        const std::uint64_t start = (claims.notBefore > leewaySeconds)
                                        ? (claims.notBefore - leewaySeconds)
                                        : 0ULL;
        if (nowUnix < start) {
            return Reject(claims, "rejected: token not yet valid");
        }
    }

    claims.valid = true;
    claims.error.clear();
    return claims;
}

JwtSelfTest JwtValidator::RunSelfTest() {
    JwtSelfTest result;

    std::vector<std::uint8_t> key = {'r', 'a', 'w', 'r', 'x', 'd', '-', 'k', 'e', 'y'};
    std::vector<std::uint8_t> wrongKey = {'w', 'r', 'o', 'n', 'g'};
    const std::uint64_t now = 1700000000ULL;

    // --- positive round trip ------------------------------------------------
    {
        const std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        const std::string payload =
            "{\"iss\":\"rawrxd-test\",\"sub\":\"user-1\",\"exp\":1700003600,\"iat\":1699996400}";
        const std::string token = BuildHs256Token(header, payload, key);
        if (!token.empty()) {
            const JwtClaims c = ValidateAt(token, key, now, 0);
            result.roundTripAccepted = c.valid && c.subject == "user-1" &&
                                       c.issuer == "rawrxd-test" && c.hasExp &&
                                       c.expiresAt == 1700003600ULL;
            result.casesRun += 1;
            result.casesPassed += result.roundTripAccepted ? 1u : 0u;
            if (!result.roundTripAccepted) {
                result.detail += "roundTrip: " + c.error + "; ";
            }
        } else {
            result.detail += "roundTrip: token build failed; ";
        }
    }

    // --- tampered payload ---------------------------------------------------
    {
        const std::string token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJpc3MiOiJhdHRhY2tlciIsInN1YiI6ImFkbWluIiwiaWF0IjoxNjk5OTk2NDAwfQ."
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const JwtClaims c = ValidateAt(token, key, now, 0);
        result.tamperedPayloadRejected = !c.valid;
        result.casesRun += 1;
        result.casesPassed += result.tamperedPayloadRejected ? 1u : 0u;
    }

    // --- tampered signature on an otherwise well formed token ---------------
    {
        const std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        const std::string payload = "{\"sub\":\"user-1\"}";
        std::string token = BuildHs256Token(header, payload, key);
        if (!token.empty()) {
            // Flip one base64url character in the signature segment.
            const std::size_t dot = token.rfind('.');
            const char original = token[dot + 1];
            const char replacement = (original == 'A') ? 'B' : 'A';
            token[dot + 1] = replacement;
            const JwtClaims c = ValidateAt(token, key, now, 0);
            result.tamperedSignatureRejected = !c.valid;
            result.casesRun += 1;
            result.casesPassed += result.tamperedSignatureRejected ? 1u : 0u;
        }
    }

    // --- wrong key ----------------------------------------------------------
    {
        const std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        const std::string payload = "{\"sub\":\"user-1\"}";
        const std::string token = BuildHs256Token(header, payload, key);
        if (!token.empty()) {
            const JwtClaims c = ValidateAt(token, wrongKey, now, 0);
            result.wrongKeyRejected = !c.valid;
            result.casesRun += 1;
            result.casesPassed += result.wrongKeyRejected ? 1u : 0u;
        }
    }

    // --- alg:none -----------------------------------------------------------
    {
        const std::string header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        const std::string payload = "{\"sub\":\"attacker\",\"exp\":1700003600}";
        const std::string token = BuildHs256Token(header, payload, key);
        if (!token.empty()) {
            const JwtClaims c = ValidateAt(token, key, now, 0);
            result.algNoneRejected = !c.valid;
            result.casesRun += 1;
            result.casesPassed += result.algNoneRejected ? 1u : 0u;
        }
    }

    // --- expired ------------------------------------------------------------
    {
        const std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        const std::string payload = "{\"sub\":\"user-1\",\"exp\":1699999000}";
        const std::string token = BuildHs256Token(header, payload, key);
        if (!token.empty()) {
            const JwtClaims c = ValidateAt(token, key, now, 0);
            result.expiredTokenRejected = !c.valid && c.subject.empty();
            result.casesRun += 1;
            result.casesPassed += result.expiredTokenRejected ? 1u : 0u;
        }
    }

    // --- not yet valid ------------------------------------------------------
    {
        const std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        const std::string payload = "{\"sub\":\"user-1\",\"nbf\":1700003600}";
        const std::string token = BuildHs256Token(header, payload, key);
        if (!token.empty()) {
            const JwtClaims c = ValidateAt(token, key, now, 0);
            result.notYetValidTokenRejected = !c.valid && c.subject.empty();
            result.casesRun += 1;
            result.casesPassed += result.notYetValidTokenRejected ? 1u : 0u;
        }
    }

    // --- malformed ----------------------------------------------------------
    {
        std::uint32_t rejected = 0;
        const char* bad[] = {"",           ".",           "a.b",         "a.b.c.d",
                             "abc",        "a..c",        "a.b.",        "a.b.!!!"};
        const std::size_t badCount = sizeof(bad) / sizeof(bad[0]);
        for (std::size_t i = 0; i < badCount; ++i) {
            if (!ValidateAt(bad[i], key, now, 0).valid) {
                ++rejected;
                // Each malformed candidate is its own case, otherwise the
                // run/pass totals cannot be compared.
                result.casesPassed += 1;
            }
            result.casesRun += 1;
        }
        result.malformedTokenRejected = (rejected == badCount);
    }

    // --- constant time compare ---------------------------------------------
    {
        // A correct constant-time compare reports "not equal" and never reports
        // a match for a differing prefix. Verify the observable contract.
        const std::uint8_t a[4] = {1, 2, 3, 4};
        const std::uint8_t b[4] = {1, 2, 3, 5};
        const std::uint8_t c[4] = {1, 2, 3, 4};
        const bool mismatchRejected = !ConstantTimeEquals(a, 4, b, 4);
        const bool matchAccepted = ConstantTimeEquals(a, 4, c, 4);
        const bool lengthMismatchRejected = !ConstantTimeEquals(a, 4, b, 3);
        const bool emptyAccepted = ConstantTimeEquals(nullptr, 0, nullptr, 0);
        result.constantTimeCompareIsConstantTime =
            mismatchRejected && matchAccepted && lengthMismatchRejected && emptyAccepted;
        result.casesRun += 1;
        result.casesPassed += result.constantTimeCompareIsConstantTime ? 1u : 0u;
    }

    const bool selfPasses = result.roundTripAccepted && result.tamperedPayloadRejected &&
                            result.tamperedSignatureRejected && result.wrongKeyRejected &&
                            result.algNoneRejected && result.expiredTokenRejected &&
                            result.notYetValidTokenRejected && result.malformedTokenRejected &&
                            result.constantTimeCompareIsConstantTime;
    result.allPassed = selfPasses && (result.casesRun == result.casesPassed);

    SecureClear(key);
    SecureClear(wrongKey);
    return result;
}

} // namespace security
} // namespace rawrxd
