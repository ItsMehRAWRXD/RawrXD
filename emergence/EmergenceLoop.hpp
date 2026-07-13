#pragma once

#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Emergence {

class EmergenceLoop {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();
    
    static nlohmann::json GetEmergenceState();
    static nlohmann::json GetEmergenceMetrics();

private:
    static std::mutex s_mutex;
    static bool s_alive;
    static int s_tickCount;
};

} // namespace Emergence
} // namespace Sovereign
} // namespace RawrXD
