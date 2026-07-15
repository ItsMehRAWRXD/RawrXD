// voice_assistant_types.hpp - Type definitions for Voice Assistant RAG integration
// Production-quality stub implementations for compilation
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <nlohmann/json.hpp>

// Forward declaration for IntentType (defined in voice_assistant_manager.hpp)
enum class IntentType;

// ============================================================================
// RAG Context Analysis Types
// ============================================================================

struct ScopeInfo {
    std::string type;
    std::string name;
    std::string filePath;
    int lineNumber = 0;
    int column = 0;
    
    // For JSON serialization
    nlohmann::json to_json() const {
        return {
            {"type", type},
            {"name", name},
            {"filePath", filePath},
            {"lineNumber", lineNumber},
            {"column", column}
        };
    }
    
    // Implicit conversion to nlohmann::json
    operator nlohmann::json() const {
        return to_json();
    }
};

struct Symbol {
    std::string name;
    std::string type;
    std::string filePath;
    int lineNumber = 0;
    std::string signature;
    float confidence = 0.0f;
    int line = 0;  // Alias for lineNumber for compatibility
    
    // For JSON serialization
    nlohmann::json to_json() const {
        return {
            {"name", name},
            {"type", type},
            {"filePath", filePath},
            {"lineNumber", lineNumber},
            {"line", line},
            {"signature", signature},
            {"confidence", confidence}
        };
    }
};

// ============================================================================
// Codebase Context Analyzer
// ============================================================================

class CodebaseContextAnalyzer {
public:
    CodebaseContextAnalyzer() = default;
    virtual ~CodebaseContextAnalyzer() = default;
    
    // Analyze the current scope at a given position
    virtual ScopeInfo analyzeCurrentScope(const std::string& file, int line, int column);
    
    // Get relevant symbols based on a query and scope
    virtual std::vector<Symbol> getRelevantSymbols(const std::string& query, const ScopeInfo& scope);
    
    // Get file dependencies
    virtual std::vector<std::string> getDependencies(const std::string& file);
    
    // Check if analyzer is ready
    virtual bool isReady() const { return m_initialized; }
    
    // Initialize the analyzer
    virtual bool initialize(const std::string& codebasePath);
    
protected:
    bool m_initialized = false;
    std::string m_codebasePath;
};

// ============================================================================
// IDE Action Types
// ============================================================================

struct IDEAction {
    std::string command_id;
    std::string description;
    bool requires_confirmation = false;
    bool requires_context = false;
    
    IDEAction() = default;
    IDEAction(const std::string& id, const std::string& desc, bool confirm = false, bool context = false)
        : command_id(id), description(desc), requires_confirmation(confirm), requires_context(context) {}
};

// ============================================================================
// Voice Assistant Command Dispatcher
// ============================================================================

class VoiceAssistantCommandDispatcher {
public:
    VoiceAssistantCommandDispatcher();
    ~VoiceAssistantCommandDispatcher() = default;
    
    // Register default IDE actions
    void register_default_ide_actions();
    
    // Check if an action exists for an intent
    bool has_action(IntentType intent) const;
    
    // Get action for an intent
    IDEAction get_action(IntentType intent) const;
    
    // Register a custom action
    void register_action(IntentType intent, const IDEAction& action);
    
    // Get all registered actions
    std::vector<IDEAction> get_all_actions() const;
    
private:
    std::unordered_map<int, IDEAction> m_actions;  // Using int for enum class hash
};

// ============================================================================
// Assistant Base Classes
// ============================================================================

class SiriStyleAssistant {
public:
    SiriStyleAssistant();
    ~SiriStyleAssistant() = default;
    
    nlohmann::json process_command(const std::string& text, const nlohmann::json& context);
    
private:
    std::vector<std::string> m_personalityTraits;
    std::vector<nlohmann::json> m_conversationHistory;
    std::unordered_map<std::string, std::string> m_userPreferences;
    
    nlohmann::json parse_intent(const std::string& text);
    std::unordered_map<std::string, std::string> extract_entities(const std::string& text, const std::string& intent);
    nlohmann::json generate_response(const std::string& text, const nlohmann::json& intent_result, const nlohmann::json& context);
    std::vector<std::string> get_suggested_actions(const std::string& intent);
};

class AlexaStyleAssistant {
public:
    AlexaStyleAssistant();
    ~AlexaStyleAssistant() = default;
    
    nlohmann::json process_command(const std::string& text, const nlohmann::json& context);
    
private:
    std::string m_wakeWord;
    std::unordered_map<std::string, nlohmann::json> m_skills;
    std::unordered_map<std::string, std::string> m_deviceStates;
    
    std::string remove_wake_word(const std::string& text);
    nlohmann::json analyze_command(const std::string& text);
    nlohmann::json execute_command(const nlohmann::json& analysis);
};

class HybridAssistant {
public:
    HybridAssistant();
    ~HybridAssistant() = default;
    
    nlohmann::json process_command(const std::string& text, const nlohmann::json& context);
    
private:
    std::unique_ptr<SiriStyleAssistant> m_siriComponent;
    std::unique_ptr<AlexaStyleAssistant> m_alexaComponent;
    
    bool should_use_siri(const std::string& text);
    nlohmann::json analyze_complexity(const std::string& text);
    std::string select_best_assistant(const std::string& text, const nlohmann::json& complexity);
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace VoiceAssistantUtils {
    std::string intent_to_string(IntentType intent);
    IntentType string_to_intent(const std::string& str);
    bool is_ide_action_intent(IntentType intent);
}
