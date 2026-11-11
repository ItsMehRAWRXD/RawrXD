#pragma once
// ============================================================================
// CoT Multi-Mode Engine — 12 Reasoning Modes
// ============================================================================
// Monolithic implementation for RawrXD CLI v4.0
// Integrates with existing ChainOfThought system
// 12 Modes: Thinker, Auditor, Reviewer, Researcher, ArgueFor, ArgueAgainst,
//           Critic, Synthesizer, Brainstorm, Verifier, Refiner, Summarizer
// ============================================================================

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <nlohmann/json.hpp>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace CoT {

// ============================================================================
// Mode Enumeration
// ============================================================================

enum class ReasoningMode : uint8_t {
    THINKER = 0,        // Deep analytical thinking
    AUDITOR = 1,        // Code/Logic audit and review
    REVIEWER = 2,       // Peer review style analysis
    RESEARCHER = 3,     // Research and fact-finding
    ARGUE_FOR = 4,      // Devil's advocate - argue for position
    ARGUE_AGAINST = 5,  // Devil's advocate - argue against position
    CRITIC = 6,         // Critical analysis and flaw detection
    SYNTHESIZER = 7,    // Combine multiple perspectives
    BRAINSTORM = 8,     // Generate creative ideas
    VERIFIER = 9,       // Verify correctness and validity
    REFINER = 10,       // Refine and polish
    SUMMARIZER = 11     // Summarize and condense
};

constexpr const char* ModeNames[] = {
    "Thinker", "Auditor", "Reviewer", "Researcher",
    "ArgueFor", "ArgueAgainst", "Critic", "Synthesizer",
    "Brainstorm", "Verifier", "Refiner", "Summarizer"
};

constexpr const char* ModeEmojis[] = {
    "💭", "🔍", "👁️", "📚",
    "✅", "❌", "⚠️", "✨",
    "💡", "✓", "🔧", "📝"
};

constexpr const char* ModeDescriptions[] = {
    "Deep analytical thinking and step-by-step reasoning",
    "Audit code/logic for bugs, security issues, and best practices",
    "Peer review style analysis with constructive feedback",
    "Research mode - gather facts, explore alternatives, investigate",
    "Devil's advocate - argue FOR a position strongly",
    "Devil's advocate - argue AGAINST a position strongly",
    "Critical analysis - find flaws, weaknesses, and edge cases",
    "Synthesize multiple perspectives into coherent whole",
    "Generate creative ideas and explore possibilities",
    "Verify correctness, validate assumptions, check facts",
    "Refine and polish - improve clarity and precision",
    "Summarize concisely - extract key points"
};

// ============================================================================
// Data Structures
// ============================================================================

struct CoTStep {
    uint8_t mode;
    std::string modeName;
    std::string emoji;
    std::string thought;
    std::string reasoning;
    float confidence;
    double durationMs;
    uint32_t tokenCount;
    std::chrono::steady_clock::time_point timestamp;
};

struct CoTResult {
    std::string query;
    std::vector<CoTStep> steps;
    std::string finalAnswer;
    float overallConfidence = 0.0f;
    double totalDurationMs = 0.0;
    uint32_t totalTokens = 0;
    nlohmann::json metadata;
    bool success = false;
    std::string error;
    
    // Validation guarantees
    bool IsValid() const {
        return !query.empty() && 
               (success || !error.empty()) &&
               overallConfidence >= 0.0f && overallConfidence <= 1.0f;
    }
    
    bool HasPartialCompletion() const {
        return !steps.empty() && !success;
    }
    
    // Round-trip serialization guarantee
    nlohmann::json ToJSON() const {
        nlohmann::json j;
        j["query"] = query;
        j["steps"] = nlohmann::json::array();
        for (const auto& step : steps) {
            j["steps"].push_back({
                {"mode", step.mode},
                {"modeName", step.modeName},
                {"emoji", step.emoji},
                {"thought", step.thought},
                {"reasoning", step.reasoning},
                {"confidence", step.confidence},
                {"durationMs", step.durationMs},
                {"tokenCount", step.tokenCount}
            });
        }
        j["finalAnswer"] = finalAnswer;
        j["overallConfidence"] = overallConfidence;
        j["totalDurationMs"] = totalDurationMs;
        j["totalTokens"] = totalTokens;
        j["metadata"] = metadata;
        j["success"] = success;
        j["error"] = error;
        return j;
    }
    
    static CoTResult FromJSON(const nlohmann::json& j) {
        CoTResult result;
        result.query = j.value("query", "");
        if (j.contains("steps") && j["steps"].is_array()) {
            for (const auto& s : j["steps"]) {
                CoTStep step;
                step.mode = s.value("mode", 0);
                step.modeName = s.value("modeName", "");
                step.emoji = s.value("emoji", "");
                step.thought = s.value("thought", "");
                step.reasoning = s.value("reasoning", "");
                step.confidence = s.value("confidence", 0.0f);
                step.durationMs = s.value("durationMs", 0.0);
                step.tokenCount = s.value("tokenCount", 0);
                result.steps.push_back(step);
            }
        }
        result.finalAnswer = j.value("finalAnswer", "");
        result.overallConfidence = j.value("overallConfidence", 0.0f);
        result.totalDurationMs = j.value("totalDurationMs", 0.0);
        result.totalTokens = j.value("totalTokens", 0);
        result.metadata = j.value("metadata", nlohmann::json::object());
        result.success = j.value("success", false);
        result.error = j.value("error", "");
        return result;
    }
};

struct ModeConfig {
    ReasoningMode mode;
    std::string systemPrompt;
    float temperature;
    int maxTokens;
    float confidenceThreshold;
    bool requiresContext;
    std::vector<std::string> requiredInputs;
};

// ============================================================================
// Multi-Mode CoT Engine
// ============================================================================

class MultiModeCoTEngine {
public:
    MultiModeCoTEngine();
    ~MultiModeCoTEngine();

    // Configuration
    void SetModelEndpoint(const std::string& endpoint);
    void SetDefaultModel(const std::string& model);
    void SetAPIKey(const std::string& key);
    
    // Core API
    CoTResult ExecuteChain(const std::string& query, 
                          const std::vector<ReasoningMode>& modes,
                          const std::unordered_map<std::string, std::string>& context = {});
    
    // Convenience methods for specific modes
    CoTResult Think(const std::string& query, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Audit(const std::string& code, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Review(const std::string& content, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Research(const std::string& topic, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult ArgueFor(const std::string& position, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult ArgueAgainst(const std::string& position, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Critique(const std::string& content, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Synthesize(const std::vector<std::string>& perspectives, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Brainstorm(const std::string& topic, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Verify(const std::string& claim, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Refine(const std::string& content, const std::unordered_map<std::string, std::string>& context = {});
    CoTResult Summarize(const std::string& content, const std::unordered_map<std::string, std::string>& context = {});
    
    // Full 8-step chain (like the example)
    CoTResult ExecuteFullChain(const std::string& query, 
                               const std::unordered_map<std::string, std::string>& context = {});
    
    // Status and info
    nlohmann::json GetModeInfo(ReasoningMode mode) const;
    nlohmann::json GetAllModes() const;
    nlohmann::json GetStatus() const;
    
    // Export/Import
    nlohmann::json ExportResult(const CoTResult& result) const;
    std::string FormatResultForDisplay(const CoTResult& result, bool verbose = false) const;
    std::string FormatResultForCLI(const CoTResult& result) const;

private:
    std::string m_endpoint;
    std::string m_model;
    std::string m_apiKey;
    bool m_initialized;
    
    std::unordered_map<ReasoningMode, ModeConfig> m_modeConfigs;
    
    // Internal methods
    void InitializeModeConfigs();
    CoTStep ExecuteMode(ReasoningMode mode, const std::string& input, 
                       const std::unordered_map<std::string, std::string>& context);
    std::string BuildPrompt(ReasoningMode mode, const std::string& input, 
                           const std::unordered_map<std::string, std::string>& context);
    std::string CallModel(const std::string& prompt, float temperature, int maxTokens);
    float EvaluateConfidence(const std::string& response, ReasoningMode mode);
    std::string ExtractReasoning(const std::string& response);
    
    // Mode-specific prompt builders
    std::string BuildThinkerPrompt(const std::string& input);
    std::string BuildAuditorPrompt(const std::string& input);
    std::string BuildReviewerPrompt(const std::string& input);
    std::string BuildResearcherPrompt(const std::string& input);
    std::string BuildArgueForPrompt(const std::string& input);
    std::string BuildArgueAgainstPrompt(const std::string& input);
    std::string BuildCriticPrompt(const std::string& input);
    std::string BuildSynthesizerPrompt(const std::vector<std::string>& perspectives);
    std::string BuildBrainstormPrompt(const std::string& input);
    std::string BuildVerifierPrompt(const std::string& input);
    std::string BuildRefinerPrompt(const std::string& input);
    std::string BuildSummarizerPrompt(const std::string& input);
};

// ============================================================================
// CLI Integration Helpers
// ============================================================================

class CoTCLIHelper {
public:
    static std::vector<ReasoningMode> ParseModeString(const std::string& modeStr);
    static std::string ModesToString(const std::vector<ReasoningMode>& modes);
    static bool ValidateModeSequence(const std::vector<ReasoningMode>& modes);
    static std::vector<ReasoningMode> GetDefaultChain();
    static std::vector<ReasoningMode> GetCodeReviewChain();
    static std::vector<ReasoningMode> GetDecisionChain();
    static std::vector<ReasoningMode> GetCreativeChain();
};

} // namespace CoT
} // namespace RawrXD
