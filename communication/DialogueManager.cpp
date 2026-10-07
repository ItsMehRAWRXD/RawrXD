#include "communication/DialogueManager.hpp"
#include "communication/IntentTranslator.hpp"
#include "communication/ExplanationGenerator.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> conversationHistory;
static nlohmann::json currentContext;

void DialogueManager::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        conversationHistory.clear();
        currentContext = {
            {"turn", 0},
            {"topic", "general"},
            {"user_intent", "unknown"}
        };
        s_initialized = true;
    }
}

void DialogueManager::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool DialogueManager::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json DialogueManager::ProcessInput(const std::string& input) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Simple intent detection
    std::string detectedIntent = "general";
    if (input.find("explain") != std::string::npos) {
        detectedIntent = "explanation_request";
    } else if (input.find("status") != std::string::npos || input.find("state") != std::string::npos) {
        detectedIntent = "status_request";
    } else if (input.find("why") != std::string::npos) {
        detectedIntent = "reasoning_request";
    }
    
    currentContext["user_intent"] = detectedIntent;
    currentContext["last_input"] = input;
    
    nlohmann::json result = {
        {"intent", detectedIntent},
        {"input", input},
        {"context", currentContext}
    };
    
    return result;
}

std::string DialogueManager::GenerateResponse(const nlohmann::json& context) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return "";
    
    std::string intent = context.value("intent", "general");
    std::string response;
    
    if (intent == "explanation_request") {
        response = ExplanationGenerator::GenerateContextualExplanation(context);
    } else if (intent == "status_request") {
        response = IntentTranslator::TranslateIntentToNL(nlohmann::json{});
    } else if (intent == "reasoning_request") {
        response = "I make decisions based on my current intent, predicted outcomes, and value alignment.";
    } else {
        response = "I understand. How can I assist you further?";
    }
    
    // Store in history
    conversationHistory.push_back({
        {"turn", currentContext["turn"].get<int>() + 1},
        {"input", context.value("input", "")},
        {"response", response},
        {"intent", intent}
    });
    
    currentContext["turn"] = currentContext["turn"].get<int>() + 1;
    
    if (conversationHistory.size() > 50) {
        conversationHistory.erase(conversationHistory.begin());
    }
    
    return response;
}

nlohmann::json DialogueManager::GetConversationState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return currentContext;
}

void DialogueManager::ResetConversation() {
    std::lock_guard<std::mutex> lock(s_mutex);
    conversationHistory.clear();
    currentContext = {
        {"turn", 0},
        {"topic", "general"},
        {"user_intent", "unknown"}
    };
}

nlohmann::json DialogueManager::GetConversationHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return conversationHistory;
}
