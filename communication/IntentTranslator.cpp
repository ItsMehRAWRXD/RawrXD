#include "communication/IntentTranslator.hpp"
#include "intent/IntentModel.hpp"
#include "identity/IdentityCore.hpp"
#include <mutex>
#include <sstream>

static std::mutex s_mutex;
static bool s_initialized = false;

void IntentTranslator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_initialized = true;
    }
}

void IntentTranslator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool IntentTranslator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

std::string IntentTranslator::TranslateIntentToNL(const nlohmann::json& intent) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    std::string goal = intent.value("goal", "");
    std::string status = intent.value("status", "");
    double progress = intent.value("progress", 0.0);
    
    std::stringstream ss;
    ss << "I am currently ";
    
    if (status == "active") {
        ss << "working toward the goal: " << goal;
        ss << " (" << static_cast<int>(progress * 100) << "% complete)";
    } else if (status == "completed") {
        ss << "have completed the goal: " << goal;
    } else if (status == "idle") {
        ss << "idle, awaiting new instructions";
    } else {
        ss << "in state: " << status;
    }
    
    return ss.str();
}

std::string IntentTranslator::TranslateStateToNL(const nlohmann::json& state) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    std::stringstream ss;
    ss << "System state: ";
    
    if (state.contains("continuity_score")) {
        double score = state["continuity_score"].get<double>();
        ss << "continuity at " << static_cast<int>(score * 100) << "%. ";
    }
    
    if (state.contains("version")) {
        ss << "Running version " << state["version"].get<std::string>() << ". ";
    }
    
    return ss.str();
}

std::string IntentTranslator::TranslateActionToNL(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    std::string actionName = action.value("action", "unknown action");
    return "I am performing: " + actionName;
}

std::string IntentTranslator::GenerateExplanation(const std::string& topic) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    if (topic == "identity") {
        auto identity = IdentityCore::Get();
        std::stringstream ss;
        ss << "My identity is based on core values including: ";
        if (identity.contains("core_values") && identity["core_values"].is_array()) {
            for (size_t i = 0; i < identity["core_values"].size(); ++i) {
                if (i > 0) ss << ", ";
                ss << identity["core_values"][i].get<std::string>();
            }
        }
        return ss.str();
    } else if (topic == "intent") {
        return TranslateIntentToNL(IntentModel::GetCurrentIntent());
    }
    
    return "Explanation for topic '" + topic + "' not available.";
}

nlohmann::json IntentTranslator::GetTranslationContext() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"language", "en"},
        {"formality", "neutral"},
        {"verbosity", "medium"}
    };
}
