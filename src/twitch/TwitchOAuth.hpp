#pragma once
/* TwitchOAuth.hpp — Device Code Grant flow.
 * No client secret embedded. Windows-native HTTPS via WinHTTP. */
#include <string>
#include <functional>
#include <cstdint>

namespace RawrXD {
namespace Twitch {

struct OAuthDeviceCode {
    std::string deviceCode;
    std::string userCode;
    std::string verificationUri;
    uint32_t    expiresIn = 0;
    uint32_t    interval = 0;
};

struct OAuthTokenResponse {
    std::string accessToken;
    std::string refreshToken;
    std::string tokenType;
    uint32_t    expiresIn = 0;
    std::string scope;
};

class TwitchOAuth {
public:
    using LogFn = std::function<void(const char*)>;

    explicit TwitchOAuth(const std::string& clientId, LogFn log = nullptr);

    /* Step 1: Request device code. Returns user-facing URL. */
    bool RequestDeviceCode(OAuthDeviceCode& out) noexcept;

    /* Step 2: Poll for token (blocking with sleep). */
    bool PollForToken(const OAuthDeviceCode& device,
                      OAuthTokenResponse& out,
                      uint32_t maxTotalSeconds = 600) noexcept;

    /* Refresh existing token. */
    bool RefreshToken(const std::string& refreshToken,
                      OAuthTokenResponse& out) noexcept;

    /* Revoke token. */
    bool RevokeToken(const std::string& token) noexcept;

private:
    std::string clientId_;
    LogFn       log_;

    bool HttpPost(const std::string& url,
                  const std::string& body,
                  std::string& outResponse,
                  const std::string& authHeader = {}) noexcept;
    bool ParseJsonToken(const std::string& json, OAuthTokenResponse& out) noexcept;
    bool ParseJsonDevice(const std::string& json, OAuthDeviceCode& out) noexcept;
};

} // namespace Twitch
} // namespace RawrXD
