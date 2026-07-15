// voice_assistant_manager.hpp — Voice Assistant Manager Core
// Manages Siri, Alexa, and Hybrid voice assistants
// Integrates with micro-model chain for enhanced processing
// ============================================================================

#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <nlohmann/json.hpp>

// Include type definitions
#include "voice_assistant_types.hpp"

// Include production utilities
#include "utils/uuid_v4.hpp"
#include "utils/rate_limiter.hpp"

// ============================================================================
// Intent Types
// ============================================================================

enum class IntentType {
    WEATHER,
    TIMER,
    REMINDER,
    CALCULATION,
    SEARCH,
    SMART_HOME,
    ENTERTAINMENT,
    INFORMATION,
    COMMUNICATION,
    CODE_GENERATION,
    CODE_ANALYSIS,
    DEBUGGING,
    OPTIMIZATION,
    // IDE action intents
    IDE_BUILD,
    IDE_OPEN_FILE,
    IDE_SAVE_FILE,
    IDE_CLOSE_FILE,
    IDE_FIND,
    IDE_REPLACE,
    IDE_GOTO_LINE,
    IDE_TOGGLE_THEME,
    IDE_TOGGLE_OUTPUT,
    IDE_TOGGLE_TERMINAL,
    IDE_RUN,
    IDE_DEBUG,
    IDE_EXPLAIN_CODE,
    IDE_FIX_CODE,
    IDE_OPTIMIZE_CODE,
    IDE_OPEN_SETTINGS,
    // RAG-enhanced semantic code intents
    CODE_EXPLAIN_SYMBOL,      // "Explain what this function does"
    CODE_FIND_REFERENCES,     // "Who calls this method?"
    CODE_GET_DEPENDENCIES,    // "What files depend on this?"
    CODE_SUGGEST_FIX,         // "How do I fix this error?"
    CODE_ARCHITECTURE_QUERY,  // "How does the network module work?"
    UNKNOWN
};

class VoiceAssistantManager {
public:
    VoiceAssistantManager();
    ~VoiceAssistantManager();
    
    // Process voice input with specified assistant
    nlohmann::json process_voice_input(
        const std::string& text,
        const std::string& assistant_type = "hybrid",
        const std::string& session_id = ""
    );
    
    // Get information about available assistants
    nlohmann::json get_assistant_info() const;
    
    // Session management
    std::string create_session();
    void end_session(const std::string& session_id);
    nlohmann::json get_session_history(const std::string& session_id) const;
    
    // Micro-model chain integration
    void set_micro_chain(void* chain); // Placeholder for actual chain type
    void* get_micro_chain() const;
    
    // IDE action dispatch
    void set_command_dispatcher(std::shared_ptr<VoiceAssistantCommandDispatcher> dispatcher);
    std::shared_ptr<VoiceAssistantCommandDispatcher> get_command_dispatcher() const;
    nlohmann::json dispatch_ide_action(IntentType intent, const std::unordered_map<std::string, std::string>& entities = {});
    
    // RAG Context Integration - Semantic Code Context
    void set_context_analyzer(std::shared_ptr<CodebaseContextAnalyzer> analyzer);
    std::shared_ptr<CodebaseContextAnalyzer> get_context_analyzer() const;
    
    // RAG-enhanced query method with instrumentation hooks
    // Includes telemetry tracking for query latency
    nlohmann::json query_codebase(const std::string& natural_language_query,
                                  const std::string& current_file = "",
                                  int current_line = 0);
    
    // Configuration
    void set_wake_word(const std::string& assistant_type, const std::string& wake_word);
    void enable_voice_output(bool enable);
    void set_response_style(const std::string& style);
    
private:
    // Assistant instances
    std::unique_ptr<SiriStyleAssistant> m_siriAssistant;
    std::unique_ptr<AlexaStyleAssistant> m_alexaAssistant;
    std::unique_ptr<HybridAssistant> m_hybridAssistant;
    
    // Session tracking (thread-safe)
    struct Session {
        std::string session_id;
        std::string assistant_type;
        std::vector<nlohmann::json> messages;
        std::string created_at;
    };
    
    mutable std::shared_mutex m_sessions_mutex;
    std::unordered_map<std::string, Session> m_sessions;
    
    // Rate limiting per session
    mutable std::shared_mutex m_rate_limit_mutex;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_last_query_time;
    
    // Micro-model chain (placeholder)
    void* m_microChain;
    
    // IDE command dispatcher
    std::shared_ptr<VoiceAssistantCommandDispatcher> m_commandDispatcher;
    
    // RAG context analyzer for semantic code queries
    std::shared_ptr<CodebaseContextAnalyzer> m_contextAnalyzer;
    
    // Configuration
    bool m_voiceOutputEnabled;
    std::string m_responseStyle;
    
    // Helper methods
    std::string generate_session_id();
    nlohmann::json route_to_assistant(
        const std::string& text,
        const std::string& assistant_type,
        const Session* session
    );
    
    // RAG pipeline execution helper
    nlohmann::json execute_rag_pipeline(const std::string& query,
                                        const std::string& current_file,
                                        int current_line);
    
    // Limit session history size to prevent unbounded memory growth
    static const size_t MAX_SESSION_HISTORY_ENTRIES = 100;
    void trim_session_history(Session& session);
};

// ============================================================================
// Voice Command Structure
// ============================================================================

struct VoiceCommand {
    std::string text;
    IntentType intent;
    double confidence;
    std::unordered_map<std::string, std::string> entities;
    nlohmann::json context;
};

// ============================================================================
// Utility Functions (extended declarations)
// ============================================================================

namespace VoiceAssistantUtils {
    std::string format_response(const std::string& template_str, const std::unordered_map<std::string, std::string>& entities);
    double calculate_confidence(const std::string& text, const std::string& intent);
    std::string get_ide_command_id(IntentType intent);
    std::string get_ide_action_description(IntentType intent);
}