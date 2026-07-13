#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>

namespace Cosmic {

class CosmicWebLoop {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();
    static void Shutdown();
    
    static nlohmann::json GetLoopState();
    static nlohmann::json GetLoopMetrics();
    
private:
    static bool s_initialized;
    static int64_t s_tickCount;
    static float s_webCoherence;
    static float s_webStability;
};

} // namespace Cosmic
