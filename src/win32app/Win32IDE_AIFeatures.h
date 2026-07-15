// ============================================================================
// Win32IDE_AIFeatures.h — Advanced AI Features Header
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <functional>

// AI Model Provider Types
enum class AIModelProvider {
    OpenAI_GPT4,
    Anthropic_Claude,
    Google_Gemini,
    Local_Ollama,
    Local_Titan,
    Auto
};

// AI Feature Functions
void initAIFeatures();
void shutdownAIFeatures();

// AI Code Operations
void aiExplainCode(const std::string& code, const std::string& language);
void aiGenerateTests(const std::string& code, const std::string& language);
void aiSuggestRefactoring(const std::string& code, const std::string& language);
void aiFixError(const std::string& code, const std::string& error, const std::string& language);
void aiGenerateFromDescription(const std::string& description, const std::string& language);
void aiCodeReview(const std::string& diff);

// Model Selection
void setAIModelProvider(const std::string& provider);

// Context-Aware Completions
void initContextAwareCompletions();
std::vector<std::string> getContextAwareCompletions(const std::string& prefix, const std::string& context);