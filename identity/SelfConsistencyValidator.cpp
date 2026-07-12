#include "identity/SelfConsistencyValidator.hpp"
#include "identity/IdentityCore.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void SelfConsistencyValidator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
}

bool SelfConsistencyValidator::Validate() {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto id = IdentityCore::Get();
    
    // Check if identity has required fields
    if (!id.contains("version") || !id.contains("core_values")) {
        return false;
    }
    
    // Check continuity score is in valid range
    if (id.contains("continuity_score")) {
        double score = id["continuity_score"];
        if (score < 0.0 || score > 1.0) {
            return false;
        }
    }
    
    return true;
}
