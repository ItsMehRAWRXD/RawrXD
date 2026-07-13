#pragma once

#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Society {

class SocietyLoop {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();
    
    static nlohmann::json GetSocietyState();
    static nlohmann::json GetSocietyMetrics();

private:
    static std::mutex s_mutex;
    static bool s_alive;
    static int s_tickCount;
};

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
