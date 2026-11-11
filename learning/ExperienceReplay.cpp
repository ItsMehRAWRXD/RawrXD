#include "learning/ExperienceReplay.hpp"
#include <mutex>
#include <random>
#include <algorithm>

static std::vector<nlohmann::json> experienceBuffer;
static std::mutex s_mutex;
static bool s_initialized = false;
static const size_t MAX_BUFFER_SIZE = 10000;

void ExperienceReplay::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        experienceBuffer.clear();
        s_initialized = true;
    }
}

void ExperienceReplay::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic buffer maintenance
}

bool ExperienceReplay::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void ExperienceReplay::StoreExperience(const nlohmann::json& experience) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Add timestamp if not present
    nlohmann::json exp = experience;
    if (!exp.contains("timestamp")) {
        exp["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    
    experienceBuffer.push_back(exp);
    
    // Remove oldest if buffer full
    if (experienceBuffer.size() > MAX_BUFFER_SIZE) {
        experienceBuffer.erase(experienceBuffer.begin());
    }
}

std::vector<nlohmann::json> ExperienceReplay::SampleExperiences(size_t count) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized || experienceBuffer.empty()) {
        return {};
    }
    
    std::vector<nlohmann::json> sampled;
    std::random_device rd;
    std::mt19937 gen(rd());
    
    size_t sampleSize = std::min(count, experienceBuffer.size());
    std::sample(experienceBuffer.begin(), experienceBuffer.end(), 
                std::back_inserter(sampled), sampleSize, gen);
    
    return sampled;
}

nlohmann::json ExperienceReplay::GetExperienceStats() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"buffer_size", experienceBuffer.size()},
        {"max_size", MAX_BUFFER_SIZE},
        {"utilization", (double)experienceBuffer.size() / MAX_BUFFER_SIZE}
    };
}

void ExperienceReplay::ClearExperiences() {
    std::lock_guard<std::mutex> lock(s_mutex);
    experienceBuffer.clear();
}
