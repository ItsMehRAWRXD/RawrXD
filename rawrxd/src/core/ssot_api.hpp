#pragma once
#include <cstdint>
#include <string>

namespace rawrxd { namespace ssot {

struct SSOTRequest {
    uint32_t id = 0;
    std::string topic;
    std::string payload;
};

struct SSOTResponse {
    bool ok = false;
    std::string data;
    uint32_t status = 0;
};

SSOTResponse HandleRequest(const SSOTRequest& req);
bool PublishEvent(const std::string& topic, const std::string& payload);

}} // namespace rawrxd::ssot
