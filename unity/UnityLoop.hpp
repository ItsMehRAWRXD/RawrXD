#pragma once

#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Unity {

class UnityLoop {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();
    
    static nlohmann::json GetUnityState();
    static nlohmann::json GetUnityMetrics();

private:
    static std::mutex s_mutex;
    static bool s_alive;
    static int s_tickCount;
};

} // namespace Unity
} // namespace Sovereign
} // namespace RawrXD
