#pragma once
#include "local_reasoning_engine.hpp"

// Minimal LocalReasoningIntegration for auto_feature_registry.cpp
class LocalReasoningIntegration {
public:
    static LocalReasoningEngine& instance();
};
