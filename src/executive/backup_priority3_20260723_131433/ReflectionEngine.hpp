// ============================================================================
// ReflectionEngine.hpp - Self-Critique and Performance Analysis
// The system evaluates itself and identifies improvements
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <chrono>

namespace RawrXD {
namespace Executive {

// Forward declarations
class ExecutiveDirector;

// ============================================================================
// Reflection Types
// ============================================================================
enum class ReflectionType {
    POST_MISSION,     // After mission completion
    PERIODIC,         // Regular self-check
    TRIGGERED,        // Event-driven (e.g., failure)
    STRATEGIC         // Long-term planning reflection
};

// ============================================================================
// Reflection Finding
// ============================================================================
struct ReflectionFinding {
    std::string findingId;
    ReflectionType type;
    std::string category;        // "performance", "quality", "efficiency", "error"
    std::string description;
    std::string severity;        // "critical", "major", "minor", "info"
    
    // Context
    std::string missionId;
    std::string agentId;
    std::string planId;
    
    // Evidence
    std::vector<std::string> evidence;
    float confidence = 0.0f;
    
    // Recommendation
    std::string recommendation;
    std::string suggestedAction;
};

// ============================================================================
// Performance Analysis
// ============================================================================
struct PerformanceAnalysis {
    std::string targetId;        // Mission, agent, or plan
    std::string targetType;
    
    // Metrics
    float efficiencyScore = 0.0f;
    float qualityScore = 0.0f;
    float resourceEfficiency = 0.0f;
    float timelinessScore = 0.0f;
    
    // Comparison
    float vsExpected = 0.0f;     // Ratio to expected performance
    float vsHistorical = 0.0f;   // Ratio to historical average
    float vsOptimal = 0.0f;      // Ratio to theoretical optimal
    
    // Trends
    bool improving = false;
    bool degrading = false;
    float trendSlope = 0.0f;
};

// ============================================================================
// Reflection Engine - Self-Analysis System
// ============================================================================
class ReflectionEngine {
public:
    ReflectionEngine();
    ~ReflectionEngine();

    bool Initialize(ExecutiveDirector* director);
    void Shutdown();
    
    // Trigger reflection
    void ReflectOnMission(const std::string& missionId);
    void ReflectOnPeriod(std::chrono::seconds period);
    void ReflectOnFailure(const std::string& missionId, const std::string& failureReason);
    void ReflectStrategically();
    
    // Analysis methods
    PerformanceAnalysis AnalyzePerformance(const std::string& targetId, const std::string& targetType);
    std::vector<ReflectionFinding> AnalyzeMission(const std::string& missionId);
    std::vector<ReflectionFinding> AnalyzeAgent(const std::string& agentId);
    std::vector<ReflectionFinding> AnalyzePlan(const std::string& planId);
    
    // System-wide analysis
    std::vector<ReflectionFinding> AnalyzeSystemHealth();
    std::vector<ReflectionFinding> IdentifyBottlenecks();
    std::vector<ReflectionFinding> IdentifyWaste();
    std::vector<ReflectionFinding> IdentifyRisks();
    
    // Improvement suggestions
    std::vector<std::string> SuggestImprovements(const std::string& targetId);
    std::vector<std::string> SuggestAgentImprovements(const std::string& agentId);
    std::vector<std::string> SuggestSystemImprovements();
    
    // Knowledge extraction
    std::string ExtractLesson(const std::string& missionId);
    std::vector<std::string> ExtractBestPractices(const std::string& domain);
    std::vector<std::string> ExtractAntiPatterns(const std::string& domain);
    
    // Statistics
    struct Stats {
        size_t reflectionsPerformed = 0;
        size_t findingsGenerated = 0;
        size_t lessonsExtracted = 0;
        double averageReflectionTimeMs = 0.0;
    };
    Stats GetStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
