// RAWRXD_GRAPH_RESTORED_001 — Minimal stub for plugin_signature.h
#pragma once
#include <string>

namespace RawrXD {

// Plugin signature verification stub
struct PluginSignatureResult {
    bool valid = false;
    char message[256] = {};
};

PluginSignatureResult VerifyPluginSignature(const std::string& path);

} // namespace RawrXD
