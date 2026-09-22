#pragma once
#include <cstdint>
#include <cstddef>
#include "enterprise_license.h"

namespace RawrXD::License::AntiTampering {

using RawrXD::License::LicenseKeyV2;
using RawrXD::License::LicenseResult;

constexpr uint32_t CRC32_POLYNOMIAL = 0xEDB88320;
constexpr uint32_t MAX_LICENSE_AGE_SECONDS = 31557600; // ~1 year

enum class TamperingPatterns : uint32_t {
    INVALID_MAGIC        = 1u << 0,
    INVALID_VERSION      = 1u << 1,
    CORRUPT_SIGNATURE    = 1u << 2,
    INVALID_TIER         = 1u << 3,
    FUTURE_ISSUE_DATE    = 1u << 4,
    PAST_EXPIRY          = 1u << 5,
    EXCESSIVE_AGE        = 1u << 6,
    INVALID_FEATURE_MASK = 1u << 7,
    INVALID_HWID         = 1u << 8,
    INVALID_LIMITS       = 1u << 9
};

inline uint32_t operator|(uint32_t lhs, TamperingPatterns rhs) { return lhs | static_cast<uint32_t>(rhs); }
inline uint32_t operator&(uint32_t lhs, TamperingPatterns rhs) { return lhs & static_cast<uint32_t>(rhs); }
inline uint32_t& operator|=(uint32_t& lhs, TamperingPatterns rhs) { lhs |= static_cast<uint32_t>(rhs); return lhs; }

uint32_t computeCRC32(const uint8_t* data, size_t size);
void sha256(const uint8_t* data, size_t size, uint8_t hash[32]);
bool computeHMAC_SHA256(const uint8_t* data, size_t dataSize,
                        const uint8_t* key, size_t keySize,
                        uint8_t outSignature[32]);
bool verifyHMAC_SHA256(const uint8_t* data, size_t dataSize,
                       const uint8_t* key, size_t keySize,
                       const uint8_t signature[32]);
bool verifyLicenseKeyIntegrity(const LicenseKeyV2& key,
                               const uint8_t* publicKey, size_t keySize,
                               uint64_t boundHWID);
uint32_t detectTampering(const LicenseKeyV2& key);
const char* getTamperingDescription(uint32_t tamperingBits);

LicenseResult reconstructKeyWithSignature(const LicenseKeyV2& inKey,
                                          const uint8_t* publicKey, size_t keySize,
                                          LicenseKeyV2& outKey);
bool encryptLicenseForStorage(const LicenseKeyV2& inKey,
                              const char* password,
                              uint8_t* outData, size_t* outSize);
bool decryptLicenseFromStorage(const uint8_t* encData, size_t encSize,
                               const char* password,
                               LicenseKeyV2& outKey);

} // namespace RawrXD::License::AntiTampering

