// ai_smart_completion.cpp - Full implementation
#include "ai_smart_completion.h"
#include "ai_unified_engine.h"
#include <windows.h>
#include <sstream>
#include <algorithm>

namespace RawrXD {
namespace AI {

class SmartCodeCompletion::Impl {
public:
    bool m_enabled = true;
    int m_delayMs = 50;
    float m_temperature = 0.1f;
    std::string m_modelName = "codellama:latest";
    CompletionPreferences m_preferences;
    
    std::string buildPrompt(const CompletionContext& context) {
        std::stringstream ss;
        ss << "Complete the following code. Provide only the completion, no explanations.\n\n";
        ss << "Language: " << context.language << "\n";
        ss << "Scope: " << context.scope << "\n\n";
        
        if (!context.expectedType.empty()) {
            ss << "Expected type: " << context.expectedType << "\n";
        }
        
        ss << "Prefix:\n```" << context.language << "\n";
        ss << context.prefix;
        
        // Mark cursor position
        ss << "<|CURSOR|>";
        ss << context.suffix;
        ss << "\n```\n\n";
        
        ss << "Completion:";
        return ss.str();
    }
    
    std::vector<SmartCompletion> parseCompletions(const std::string& response) {
        std::vector<SmartCompletion> completions;
        
        // Split by newlines for multiple suggestions
        std::stringstream ss(response);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty()) continue;
            
            SmartCompletion completion;
            completion.text = line;
            completion.displayText = line.substr(0, 50);
            if (line.length() > 50) completion.displayText += "...";
            completion.type = CompletionType::WholeLine;
            completion.confidence = 0.8f;
            completion.insertStart = 0;
            completion.insertEnd = 0;
            completion.isSnippet = false;
            
            completions.push_back(completion);
        }
        
        return completions;
    }
    
    float calculateRelevance(const SmartCompletion& completion, 
                              const CompletionContext& context) {
        float score = completion.confidence;
        
        // Boost if matches expected type
        if (!context.expectedType.empty() && 
            completion.detail.find(context.expectedType) != std::string::npos) {
            score += 0.2f;
        }
        
        // Boost if in visible symbols
        for (const auto& symbol : context.visibleSymbols) {
            if (completion.text.find(symbol) != std::string::npos) {
                score += 0.1f;
                break;
            }
        }
        
        return std::min(score, 1.0f);
    }
};

SmartCodeCompletion::SmartCodeCompletion() : m_impl(std::make_unique<Impl>()) {}
SmartCodeCompletion::~SmartCodeCompletion() = default;

std::vector<SmartCompletion> SmartCodeCompletion::getCompletions(
    const CompletionContext& context,
    int maxResults) {
    
    if (!m_impl->m_enabled) {
        return {};
    }
    
    InferenceRequest req;
    req.prompt = m_impl->buildPrompt(context);
    req.systemPrompt = "You are an expert programmer. Provide code completions only.";
    req.model = m_impl->m_modelName;
    req.temperature = m_impl->m_temperature;
    req.maxTokens = 256;
    req.stopSequences = {"\n\n", "<|CURSOR|>"};
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return {};
    }
    
    auto completions = m_impl->parseCompletions(response.text);
    
    // Calculate relevance and sort
    for (auto& completion : completions) {
        completion.confidence = m_impl->calculateRelevance(completion, context);
    }
    
    std::sort(completions.begin(), completions.end(),
              [](const SmartCompletion& a, const SmartCompletion& b) {
                  return a.confidence > b.confidence;
              });
    
    // Limit results
    if (completions.size() > static_cast<size_t>(maxResults)) {
        completions.resize(maxResults);
    }
    
    return completions;
}

std::optional<SmartCompletion> SmartCodeCompletion::getRealtimeCompletion(
    const CompletionContext& context) {
    
    auto completions = getCompletions(context, 1);
    if (completions.empty()) {
        return std::nullopt;
    }
    
    return completions[0];
}

std::optional<SmartCompletion> SmartCodeCompletion::getLineCompletion(
    const CompletionContext& context) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildPrompt(context);
    req.systemPrompt = "Complete the current line of code.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.1f;
    req.maxTokens = 100;
    req.stopSequences = {"\n"};
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return std::nullopt;
    }
    
    SmartCompletion completion;
    completion.text = response.text;
    completion.displayText = response.text;
    completion.type = CompletionType::WholeLine;
    completion.confidence = 0.85f;
    
    return completion;
}

std::optional<SmartCompletion> SmartCodeCompletion::getBlockCompletion(
    const CompletionContext& context) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildPrompt(context);
    req.systemPrompt = "Complete the code block. Provide multiple lines if needed.";
    req.model = m_impl->m_modelName;
    req.temperature = 0.15f;
    req.maxTokens = 512;
    req.stopSequences = {"\n\n\n"};
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return std::nullopt;
    }
    
    SmartCompletion completion;
    completion.text = response.text;
    completion.displayText = response.text.substr(0, 50) + "...";
    completion.type = CompletionType::Block;
    completion.confidence = 0.8f;
    completion.isSnippet = true;
    
    return completion;
}

std::optional<std::string> SmartCodeCompletion::getGhostText(
    const CompletionContext& context) {
    
    auto completion = getRealtimeCompletion(context);
    if (!completion) {
        return std::nullopt;
    }
    
    return completion->text;
}

void SmartCodeCompletion::recordCompletionAccepted(const SmartCompletion& completion) {
    m_impl->m_preferences.acceptedCompletions++;
    m_impl->m_preferences.totalCompletions++;
    
    // Add to frequently used
    m_impl->m_preferences.frequentlyUsed.push_back(completion.text);
    if (m_impl->m_preferences.frequentlyUsed.size() > 100) {
        m_impl->m_preferences.frequentlyUsed.erase(
            m_impl->m_preferences.frequentlyUsed.begin());
    }
}

void SmartCodeCompletion::recordCompletionRejected(const SmartCompletion& completion) {
    m_impl->m_preferences.totalCompletions++;
    
    // Add to rarely accepted
    m_impl->m_preferences.rarelyAccepted.push_back(completion.text);
}

void SmartCodeCompletion::recordCompletionModified(const SmartCompletion& completion, 
                                   const std::string& modifiedText) {
    // Note: Learning from modifications requires ML training pipeline
    // Would analyze differences between completion and modified text
    // to improve future suggestions
}

CompletionPreferences SmartCodeCompletion::getPreferences() const {
    return m_impl->m_preferences;
}

void SmartCodeCompletion::updatePreferences(const CompletionPreferences& prefs) {
    m_impl->m_preferences = prefs;
}

void SmartCodeCompletion::setEnabled(bool enabled) {
    m_impl->m_enabled = enabled;
}

void SmartCodeCompletion::setDelay(int milliseconds) {
    m_impl->m_delayMs = milliseconds;
}

void SmartCodeCompletion::setModel(const std::string& modelName) {
    m_impl->m_modelName = modelName;
}

void SmartCodeCompletion::setTemperature(float temp) {
    m_impl->m_temperature = temp;
}

bool SmartCodeCompletion::isReady() const {
    return GetAIEngine().isReady();
}

float SmartCodeCompletion::getLatencyMs() const {
    return GetAIEngine().getAverageLatency();
}

SmartCodeCompletion& GetSmartCodeCompletion() {
    static SmartCodeCompletion instance;
    return instance;
}

} // namespace AI
} // namespace RawrXD
