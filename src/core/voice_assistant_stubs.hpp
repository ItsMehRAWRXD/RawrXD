// voice_assistant_stubs.hpp - Stub definitions for RAG integration
// Provides minimal implementations for types referenced by voice_assistant_manager.cpp
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

// Stub for CodebaseContextAnalyzer
class CodebaseContextAnalyzer {
public:
    // Stub: Analyze current scope
    struct ScopeInfo {
        std::string type;
        std::string name;
    };
    
    ScopeInfo analyzeCurrentScope(const std::string& file, int line, int column) {
        return ScopeInfo{"global", "unknown"};
    }
    
    // Stub: Get relevant symbols
    struct Symbol {
        std::string name;
        std::string type;
        std::string filePath;
        int lineNumber;
        std::string signature;
    };
    
    std::vector<Symbol> getRelevantSymbols(const std::string& query, 
                                              const std::string& file, 
                                              int maxResults) {
        return {};
    }
    
    // Stub: Get dependencies
    std::vector<std::string> getDependencies(const std::string& file) {
        return {};
    }
};

// Stub for Session
struct Session {
    std::vector<nlohmann::json> messages;
};

// Stub for SiriStyleAssistant
class SiriStyleAssistant {
public:
    SiriStyleAssistant();
    nlohmann::json process_command(const std::string& text, const nlohmann::json& context);
};

// Stub for AlexaStyleAssistant  
class AlexaStyleAssistant {
public:
    AlexaStyleAssistant();
    nlohmann::json process_command(const std::string& text, const nlohmann::json& context);
};

// Stub for HybridAssistant
class HybridAssistant {
public:
    HybridAssistant();
    nlohmann::json process_command(const std::string& text, const nlohmann::json& context);
};

// Stub for VoiceAssistantCommandDispatcher
struct IDEAction {
    std::string description;
    bool requires_confirmation = false;
};

class VoiceAssistantCommandDispatcher {
public:
    void register_default_ide_actions();
    bool has_action(IntentType intent) const;
    IDEAction get_action(IntentType intent) const;
    
private:
    std::unordered_map<IntentType, IDEAction> m_actions;
};

// Utility functions namespace
namespace VoiceAssistantUtils {
    std::string intent_to_string(IntentType intent);
    IntentType string_to_intent(const std::string& str);
    bool is_ide_action_intent(IntentType intent);
}
