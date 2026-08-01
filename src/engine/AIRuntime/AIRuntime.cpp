#include "AIRuntime.hpp"
#include "RealGGUFInference.hpp"
#include <iostream>
#include <chrono>
#include <random>
#include <thread>

// ============================================================================
// Factory — returns RealGGUFInference when a model path is configured,
// falls back to StubAIRuntime for demo/testing without a model file.
// ============================================================================

IAIRuntime* CreateAIRuntime() {
    return new RealGGUFInference();
}
