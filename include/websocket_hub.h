#pragma once
#include <cstdint>

class WebSocketHub {
public:
    WebSocketHub() = default;
    ~WebSocketHub() = default;
    bool startServer(uint16_t /*port*/) { return true; }
    void stopServer() {}
};
