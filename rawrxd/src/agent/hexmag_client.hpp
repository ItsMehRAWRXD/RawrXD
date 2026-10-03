#pragma once
#include <cstdint>
#include <string>

namespace rawrxd { namespace agent {

struct HexMagClient {
    uint32_t sessionId = 0;
    bool connected = false;
    bool connect(const char* endpoint) { (void)endpoint; connected = true; return true; }
    void disconnect() { connected = false; }
    bool send(const uint8_t* data, size_t len) { (void)data; (void)len; return connected; }
};

}} // namespace rawrxd::agent
