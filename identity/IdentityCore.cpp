#include "identity/IdentityCore.hpp"
#include <mutex>

static nlohmann::json identity;
static std::mutex s_mutex;
static bool s_initialized = false;

void IdentityCore::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        identity = {
            {"version", "sovereign-1.0"},
            {"core_values", {"coherence", "stability", "autonomy", "legibility"}},
            {"long_term_goals", nlohmann::json::array()},
            {"continuity_score", 1.0}
        };
        s_initialized = true;
    }
}

nlohmann::json IdentityCore::Get() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return identity;
}

void IdentityCore::Update(const nlohmann::json& delta) {
    std::lock_guard<std::mutex> lock(s_mutex);
    for (auto& [k, v] : delta.items()) {
        identity[k] = v;
    }
}
