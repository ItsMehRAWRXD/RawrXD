#pragma once

#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Spirituality {

class SpiritualityLoop {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();
    
    static nlohmann::json GetSpiritualityState();
    static nlohmann::json GetSpiritualityMetrics();

private:
    static std::mutex s_mutex;
    static bool s_alive;
    static int s_tickCount;
};

} // namespace Spirituality
} // namespace Sovereign
} // namespace RawrXD
