#pragma once
#include <string>
#include <cstdint>
#include <vector>

// Minimal LocalReasoningEngine for auto_feature_registry.cpp
class LocalReasoningEngine {
public:
    struct AnalysisContext {
        std::string code;
        std::string language;
        bool deep = false;
    };

    std::string analyze(const AnalysisContext& ctx);
    std::string getStats() const;
};
