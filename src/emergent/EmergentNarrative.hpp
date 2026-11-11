#pragma once

/**
 * EmergentNarrative.hpp
 *
 * Phase C.2 Batch 5/5: Emergent Narrative Layer
 *
 * The system generates explanations, summaries, internal narratives,
 * and causal chains of its own behavior.
 */

#include <vector>
#include <map>
#include <memory>
#include <string>
#include <functional>

namespace Emergent {

/**
 * Narrative element types
 */
enum class NarrativeElementType {
    EVENT,           // Something happened
    ACTION,          // System took action
    DECISION,        // System made decision
    OBSERVATION,     // System observed pattern
    EXPLANATION,     // System explains why
    PREDICTION,      // System predicts future
    REFLECTION,      // System reflects on past
    GOAL_FORMATION,  // System formed goal
    CORRECTION       // System self-corrected
};

/**
 * Single narrative element
 */
struct NarrativeElement {
    std::string elementId;
    NarrativeElementType type;
    std::string timestamp;
    
    // Content
    std::string title;
    std::string description;
    std::string naturalLanguage;  // Human-readable summary
    
    // Context
    std::map<std::string, std::string> context;
    std::vector<std::string> relatedElements;
    std::string causalParent;  // What caused this
    
    // Significance
    double importance;  // 0-1
    double confidence;
    bool isKeyEvent;
    
    std::string ToJson() const;
    std::string ToNaturalLanguage() const;
};

/**
 * Causal chain (explanation of why something happened)
 */
struct CausalChain {
    std::string chainId;
    std::string effect;           // What happened
    std::vector<std::string> causes;  // Chain of causes
    std::string rootCause;
    double explanationConfidence;
    
    std::string ToNaturalLanguage() const;
};

/**
 * System narrative (story of system behavior)
 */
struct SystemNarrative {
    std::string narrativeId;
    std::string title;
    std::string summary;
    
    // Temporal bounds
    int64_t startTimeMs;
    int64_t endTimeMs;
    
    // Elements
    std::vector<NarrativeElement> elements;
    std::vector<CausalChain> causalChains;
    
    // Themes
    std::vector<std::string> themes;
    std::map<std::string, double> themeStrengths;
    
    // Metrics
    int eventCount;
    int decisionCount;
    int correctionCount;
    double averageConfidence;
    
    std::string ToJson() const;
    std::string ToMarkdown() const;
    void PrintSummary() const;
};

/**
 * Narrative generation configuration
 */
struct NarrativeConfig {
    // Generation thresholds
    double minImportanceForNarrative = 0.5;
    int minElementsForSummary = 3;
    
    // Causal chain depth
    int maxCausalDepth = 5;
    double minCausalConfidence = 0.6;
    
    // Language generation
    bool useTechnicalLanguage = false;
    bool includeMetrics = true;
    bool includeTimestamps = true;
    
    // Themes
    int maxThemes = 5;
    double minThemeStrength = 0.3;
};

/**
 * Event for narrative generation
 */
struct SystemEvent {
    int64_t timestampMs;
    std::string eventType;
    std::string description;
    std::map<std::string, std::string> attributes;
    double significance;
};

/**
 * Emergent Narrative Generator
 *
 * Generates explanations and narratives from system behavior
 */
class EmergentNarrative {
public:
    EmergentNarrative();
    ~EmergentNarrative();
    
    // Initialize
    bool Initialize(const NarrativeConfig& config = NarrativeConfig{});
    
    // Feed events
    void FeedEvent(const SystemEvent& event);
    void FeedEvents(const std::vector<SystemEvent>& events);
    
    // Generate narrative
    SystemNarrative GenerateNarrative();
    
    // Specific generation functions
    std::vector<NarrativeElement> GenerateElements(const std::vector<SystemEvent>& events);
    std::vector<CausalChain> GenerateCausalChains(const std::vector<NarrativeElement>& elements);
    std::string GenerateSummary(const SystemNarrative& narrative);
    std::map<std::string, double> ExtractThemes(const std::vector<NarrativeElement>& elements);
    
    // Query narrative
    std::string ExplainDecision(const std::string& decisionId);
    std::string ExplainPattern(const std::string& patternId);
    std::string PredictNextEvents(int count);
    
    // Get current narrative
    const SystemNarrative& GetCurrentNarrative() const { return currentNarrative_; }
    
    // Export
    bool SaveNarrative(const std::string& path) const;
    bool LoadNarrative(const std::string& path);
    
private:
    NarrativeConfig config_;
    std::vector<SystemEvent> eventHistory_;
    SystemNarrative currentNarrative_;
    
    // Helper methods
    NarrativeElementType ClassifyEvent(const SystemEvent& event);
    std::string GenerateNaturalLanguage(const NarrativeElement& element);
    std::vector<std::string> FindCauses(const NarrativeElement& effect, 
                                        const std::vector<NarrativeElement>& candidates);
    double CalculateThematicSimilarity(const NarrativeElement& a, const NarrativeElement& b);
    std::string GenerateElementId() const;
    std::string GenerateChainId() const;
    std::string GenerateNarrativeId() const;
    std::string FormatTimestamp(int64_t ms) const;
};

/**
 * Narrative CLI
 */
class EmergentNarrativeCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintBanner();
    static void PrintUsage();
    static NarrativeConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Emergent
