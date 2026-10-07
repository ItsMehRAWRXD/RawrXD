#pragma once
/* TwitchHttpClient.hpp — minimal WinHTTP GET/POST wrapper.
 * No external dependencies. */
#include <string>
#include <vector>
#include <cstdint>

namespace RawrXD {
namespace Twitch {

class TwitchHttpClient {
public:
    explicit TwitchHttpClient(const std::string& accessToken);

    bool Get(const std::string& url, std::string& outResponse) noexcept;
    bool Post(const std::string& url,
              const std::string& contentType,
              const std::string& body,
              std::string& outResponse) noexcept;
    bool Delete(const std::string& url, std::string& outResponse) noexcept;

    void SetAccessToken(const std::string& token) noexcept;

    static bool UrlEncode(const std::string& in, std::string& out) noexcept;

private:
    std::string token_;
    bool        request(const std::string& url,
                        const std::string& method,
                        const std::string& contentType,
                        const std::string& body,
                        std::string& outResponse) noexcept;
};

} // namespace Twitch
} // namespace RawrXD
