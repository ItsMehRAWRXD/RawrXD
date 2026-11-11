#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>

namespace Galaxy {

class GalacticLoop {
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
    static float s_coherenceBaseline;
    static float s_stabilityBaseline;
};

} // namespace Galaxy
