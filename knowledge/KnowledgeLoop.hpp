#pragma once

#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Knowledge {

class KnowledgeLoop {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();
    
    static nlohmann::json GetKnowledgeState();
    static nlohmann::json GetKnowledgeMetrics();

private:
    static std::mutex s_mutex;
    static bool s_alive;
    static int s_tickCount;
};

} // namespace Knowledge
} // namespace Sovereign
} // namespace RawrXD
