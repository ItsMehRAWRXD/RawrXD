// ============================================================================
// JwtValidator.h — RAWRXD_SECURITY_JWT_VALIDATION_001
// HS256 JWT verification. Win32 BCrypt only, zero external dependencies.
// No cryptographic and no JSON library is used; both are implemented here
// against documented algorithms so the validator has no unowned trust surface.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace security {

// Outcome of a single validation attempt. `valid` is derived only from measured
// checks; it is never assigned from a literal.
struct JwtClaims {
    bool valid = false;
    std::string error;

    std::string subject;   // "sub"
    std::string issuer;    // "iss"
    std::string audience;  // "aud" (string form only)
    std::string algorithm; // "alg" from the JOSE header

    std::uint64_t expiresAt = 0;  // "exp", 0 when absent
    std::uint64_t notBefore = 0;  // "nbf", 0 when absent
    std::uint64_t issuedAt = 0;   // "iat", 0 when absent

    bool hasExp = false;
    bool hasNbf = false;

    // Clock skew allowance in seconds applied to exp/nbf.
    std::uint64_t leewaySeconds = 0;

    // Seconds since the Unix epoch, measured at validation time.
    std::uint64_t validatedAtUnix = 0;
};

// Result of a self test. Every field is produced by running the validator.
struct JwtSelfTest {
    bool roundTripAccepted = false;
    bool tamperedPayloadRejected = false;
    bool tamperedSignatureRejected = false;
    bool wrongKeyRejected = false;
    bool algNoneRejected = false;
    bool expiredTokenRejected = false;
    bool notYetValidTokenRejected = false;
    bool malformedTokenRejected = false;
    bool constantTimeCompareIsConstantTime = false;
    bool allPassed = false;
    std::uint32_t casesRun = 0;
    std::uint32_t casesPassed = 0;
    std::string detail;
};

class JwtValidator {
public:
    // Validates structure, JOSE alg, HMAC-SHA256 signature, and exp/nbf.
    // The signature is verified before any claim is trusted.
    static JwtClaims Validate(const std::string& jwt, const std::vector<std::uint8_t>& secret);

    // Same, with a clock-skew allowance and an externally supplied "now"
    // (seconds since the Unix epoch). Intended for tests and for callers that
    // already hold a trusted clock.
    static JwtClaims ValidateAt(const std::string& jwt,
                                const std::vector<std::uint8_t>& secret,
                                std::uint64_t nowUnix,
                                std::uint64_t leewaySeconds);

    // Base64url (RFC 4648 §5) decode. Returns false on any invalid character,
    // bad length, or trailing bits that are not zero.
    static bool Base64UrlDecode(const std::string& in, std::vector<std::uint8_t>& out);

    static std::string Base64UrlEncode(const std::uint8_t* data, std::size_t size);

    // HMAC-SHA256 via BCrypt. Returns an empty vector on provider failure.
    static std::vector<std::uint8_t> HmacSha256(const std::vector<std::uint8_t>& key,
                                                const std::string& message);

    // Length-independent, value-constant-time equality. Returns false when the
    // lengths differ, without leaking *where* they differ.
    static bool ConstantTimeEquals(const std::uint8_t* a, std::size_t aLen,
                                   const std::uint8_t* b, std::size_t bLen);

    // Runs the negative and round-trip cases below and reports measured results.
    static JwtSelfTest RunSelfTest();

    // Convenience: current time in seconds since the Unix epoch.
    static std::uint64_t UnixNow();
};

} // namespace security
} // namespace rawrxd
