/* TwitchConfig.cpp — configuration validation and migration */
#include "TwitchConfig.hpp"
#include <algorithm>
#include <cctype>

namespace RawrXD {
namespace Twitch {

bool TwitchConfig::Validate(std::string& outError) const noexcept {
    if (schemaVersion != CONFIG_SCHEMA_VERSION) {
        outError = "Config schema version mismatch";
        return false;
    }
    if (deep2Port == 0 || deep2Port > 65535) {
        outError = "Invalid Deep2 port";
        return false;
    }
    if (twitchClientId.empty()) {
        outError = "Twitch client ID not configured";
        return false;
    }
    if (channelName.empty()) {
        outError = "Channel name not configured";
        return false;
    }
    if (allowedModels.empty()) {
        outError = "No allowed models configured";
        return false;
    }
    for (const auto& m : allowedModels) {
        if (m.empty()) {
            outError = "Empty model ID in allowedModels";
            return false;
        }
    }
    if (maxConcurrent == 0 || maxConcurrent > 8) {
        outError = "Invalid maxConcurrent (must be 1-8)";
        return false;
    }
    if (userCooldownSeconds > 3600) {
        outError = "userCooldownSeconds exceeds 1 hour";
        return false;
    }
    if (maxQueueSize == 0 || maxQueueSize > 256) {
        outError = "Invalid maxQueueSize (must be 1-256)";
        return false;
    }
    if (maxReplyChars == 0 || maxReplyChars > 1000) {
        outError = "Invalid maxReplyChars";
        return false;
    }
    if (deep2RequestTimeoutMs == 0 || deep2RequestTimeoutMs > 300000) {
        outError = "Invalid deep2RequestTimeoutMs";
        return false;
    }
    if (maxRetries > 5) {
        outError = "maxRetries exceeds 5";
        return false;
    }
    return true;
}

bool TwitchConfig::MigrateFrom(uint32_t oldVersion, std::string& outError) noexcept {
    (void)oldVersion;
    schemaVersion = CONFIG_SCHEMA_VERSION;
    outError.clear();
    return true;
}

} // namespace Twitch
} // namespace RawrXD
