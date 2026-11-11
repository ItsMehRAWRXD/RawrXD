#pragma once

#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Consciousness {

class ConsciousnessLoop {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();
    
    static nlohmann::json GetConsciousnessState();
    static nlohmann::json GetConsciousnessMetrics();

private:
    static std::mutex s_mutex;
    static bool s_alive;
    static int s_tickCount;
};

} // namespace Consciousness
} // namespace Sovereign
} // namespace RawrXD
