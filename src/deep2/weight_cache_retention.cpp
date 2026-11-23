// Shared device-level retention policy. Kept independent of the Deep2
// dispatcher so standalone Vulkan tests do not need to link its full graph.
#include <atomic>

namespace RawrXD { namespace Deep2 { namespace QuantDot {
namespace {
std::atomic<bool> g_weight_cache_retention{false};
}
void SetWeightCacheRetention(bool enabled) {
    g_weight_cache_retention.store(enabled, std::memory_order_relaxed);
}
bool WeightCacheRetention() {
    return g_weight_cache_retention.load(std::memory_order_relaxed);
}
} } }
