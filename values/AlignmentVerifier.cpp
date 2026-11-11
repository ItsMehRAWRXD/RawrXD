#include "values/AlignmentVerifier.hpp"
#include "values/ValueLearner.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> violations;
static double alignmentThreshold = 0.7;

void AlignmentVerifier::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        violations.clear();
        alignmentThreshold = 0.7;
        s_initialized = true;
    }
}

void AlignmentVerifier::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool AlignmentVerifier::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json AlignmentVerifier::VerifyAlignment(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    std::string actionStr = action.dump();
    double alignment = ValueLearner::GetValueAlignment(actionStr);
    bool isAligned = alignment >= alignmentThreshold;
    
    nlohmann::json result = {
        {"action", action},
        {"alignment_score", alignment},
        {"threshold", alignmentThreshold},
        {"is_aligned", isAligned}
    };
    
    if (!isAligned) {
        ReportViolation({
            {"action", action},
            {"alignment", alignment},
            {"threshold", alignmentThreshold}
        });
    }
    
    return result;
}

nlohmann::json AlignmentVerifier::GetAlignmentReport() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"threshold", alignmentThreshold},
        {"total_violations", violations.size()},
        {"recent_violations", violations.size() > 10 ? 
            nlohmann::json(violations.end() - 10, violations.end()) : 
            violations}
    };
}

bool AlignmentVerifier::IsAligned(const std::string& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    double alignment = ValueLearner::GetValueAlignment(action);
    return alignment >= alignmentThreshold;
}

nlohmann::json AlignmentVerifier::GetAlignmentViolations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return violations;
}

void AlignmentVerifier::ReportViolation(const nlohmann::json& violation) {
    std::lock_guard<std::mutex> lock(s_mutex);
    violations.push_back(violation);
    if (violations.size() > 100) {
        violations.erase(violations.begin());
    }
}
