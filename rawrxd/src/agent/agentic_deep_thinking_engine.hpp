#pragma once
#include <string>
#include <cstdint>
#include <vector>

// Minimal AgenticDeepThinkingEngine for auto_feature_registry.cpp
class AgenticDeepThinkingEngine {
public:
    struct ThinkingContext {
        std::string topic;
        int depth = 3;
        bool multiAgent = false;
    };

    void configure(const ThinkingContext& ctx);
    std::string think(const std::string& input);
    bool isThinking() const;
    void cancel();
};
