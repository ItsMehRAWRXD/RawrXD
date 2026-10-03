#pragma once
#include <cstdint>
#include <string>

namespace rawrxd { namespace plugin {

struct PluginSignature {
    uint8_t hash[32];
    uint32_t version;
    bool verify(const uint8_t* data, size_t len) const;
};

bool VerifyPlugin(const std::string& path, const PluginSignature& expected);

}} // namespace rawrxd::plugin
