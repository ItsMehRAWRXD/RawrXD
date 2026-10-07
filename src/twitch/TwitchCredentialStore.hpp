#pragma once
/* TwitchCredentialStore.hpp — DPAPI-protected token storage.
 * Windows-only. No client secret in source. */
#include <string>
#include <vector>
#include <cstdint>

namespace RawrXD {
namespace Twitch {

struct StoredCredentials {
    std::string accessToken;
    std::string refreshToken;
    uint64_t    expiresAtUnix = 0;
    std::string botUserId;
    std::string botLogin;
};

class TwitchCredentialStore {
public:
    /* Load credentials from DPAPI-encrypted file. */
    bool Load(const std::string& path, StoredCredentials& out) noexcept;

    /* Save credentials to DPAPI-encrypted file. */
    bool Save(const std::string& path, const StoredCredentials& in) noexcept;

    /* Securely wipe memory. */
    static void SecureErase(void* ptr, size_t len) noexcept;

    /* Verify token is not expired (with 60s margin). */
    static bool IsTokenValid(const StoredCredentials& creds, uint64_t nowUnix) noexcept;

private:
    static bool ProtectData(const std::vector<uint8_t>& plain,
                            std::vector<uint8_t>& cipher) noexcept;
    static bool UnprotectData(const std::vector<uint8_t>& cipher,
                              std::vector<uint8_t>& plain) noexcept;
};

} // namespace Twitch
} // namespace RawrXD
