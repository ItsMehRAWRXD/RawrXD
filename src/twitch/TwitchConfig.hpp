#pragma once
/* TwitchConfig.hpp — versioned configuration schema for RawrXD Twitch bridge.
 * Windows-native, zero third-party dependencies. */
#include <string>
#include <vector>
#include <cstdint>

namespace RawrXD {
namespace Twitch {

constexpr uint32_t CONFIG_SCHEMA_VERSION = 1;

enum class ConfigField : uint32_t {
    Safe   = 0, /* cooldowns, reply length, allowed models, command enables, logging */
    Unsafe = 1  /* OAuth identity, bot user ID, Deep2 topology */
};

struct TwitchConfig {
    uint32_t schemaVersion = CONFIG_SCHEMA_VERSION;

    // Deep2 endpoint
    std::string deep2Host = "127.0.0.1";
    uint16_t    deep2Port = 11436;
    std::string deep2ProtocolVersion = "1.0";

    // Twitch bot identity (Unsafe: requires reconnect)
    std::string twitchClientId;
    std::string botUserId;
    std::string botLogin;

    // Channel
    std::string channelName = "itsmehrawrxd";
    std::string broadcasterId;

    // Allowed models
    std::vector<std::string> allowedModels = {"deep2-local"};

    // Commands
    bool cmdDeep2Enabled  = true;
    bool cmdAskEnabled    = true;
    bool cmdAiEnabled     = true;
    bool cmdHelpEnabled   = true;
    bool cmdStatusEnabled = true;
    bool cmdModelEnabled  = true;
    bool cmdNewEnabled    = true;
    bool cmdResetEnabled  = true;

    // Permissions
    bool allowViewer       = true;
    bool allowModerator    = true;
    bool allowBroadcaster  = true;

    // Rate limits
    uint32_t maxConcurrent = 1;
    uint32_t userCooldownSeconds = 5;
    uint32_t maxQueueSize = 16;
    uint32_t maxRetries = 3;

    // Timeouts
    uint32_t deep2RequestTimeoutMs = 30000;
    uint32_t twitchSendTimeoutMs = 10000;
    uint32_t eventSubReconnectSec = 30;

    // Reply limits
    uint32_t maxReplyChars = 450;
    uint32_t maxReplyParts = 3;

    // CPU fallback policy
    bool allowCpuFallback = false;

    // Logging
    uint32_t logLevel = 2; /* 0=none, 1=error, 2=info, 3=debug */

    // Validation
    bool Validate(std::string& outError) const noexcept;
    bool MigrateFrom(uint32_t oldVersion, std::string& outError) noexcept;
};

} // namespace Twitch
} // namespace RawrXD
