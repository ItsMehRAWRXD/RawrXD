#pragma once
#include <cstdint>
#include <string>
namespace rawr::product {

struct ExecutionRequest {
    uint32_t abi = 1;
    uint64_t gen = 0;
    std::string sessionId;
    std::string workspace;
    std::string prompt;
    uint32_t maxTokens = 256;
    uint32_t timeoutMs = 500;
    bool stream = true;
    bool tools = false;
};

struct ExecutionResult {
    uint32_t abi = 1;
    uint64_t gen = 0;
    int ok = 0;
    int cancelled = 0;
    int stale = 0;
    uint32_t tokensOut = 0;
    uint32_t latencyMs = 0;
    std::string text;
    std::string err;
};

} // namespace rawr::product
