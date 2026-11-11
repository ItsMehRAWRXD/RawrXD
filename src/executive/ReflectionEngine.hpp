// ============================================================
// ReflectionEngine.hpp - Self-Critique and Performance Analysis
// The system evaluates itself and identifies improvements
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace RawrXD::Executive {

class ExecutiveDirector;

// ============================================================
// Reflection Types
// ============================================================
enum class ReflectionType {
    POST_MISSION,
    PERIODIC,
    TRIGGERED,
    STRATEGIC
};

// ============================================================
// Reflection Finding
// ============================================================
struct ReflectionFinding {
    uint64_t findingId;
    ReflectionType type;
    std::string category;
    std::string description;
    std::string severity;
    
    uint64_t missionId = 0;
    uint64_t agentId = 0;
    uint64_t planId = 0;
    
    std::vector<std::string> evidence;
    float confidence = 0.0f;
    
    std::string recommendation;
    std::string suggestedAction;
};

// ============================================================
// Performance Analysis
// ============================================================
struct PerformanceAnalysis {
    uint64_t targetId;
    std::string targetType;
    
    float efficiencyScore = 0.0f;
    float qualityScore = 0.0f;
    float resourceEfficiency = 0.0f;
    float timelinessScore = 0.0f;
    
    float vsExpected = 0.0f;
    float vsHistorical = 0.0f;
    float vsOptimal = 0.0f;
    
    bool improving = false;
    bool degrading = false;
    float trendSlope = 0.0f;
};

// ============================================================
// Reflection Engine
// ============================================================
class ReflectionEngine {
public:
    ReflectionEngine() = default;
    ~ReflectionEngine() = default;

    bool initialize(ExecutiveDirector* director);
    void shutdown();
    
    void reflectOnMission(uint64_t missionId);
    void reflectOnPeriod(std::chrono::seconds period);
    void reflectOnFailure(uint64_t missionId, const std::string& failureReason);
    void reflectStrategically();
    
    PerformanceAnalysis analyzePerformance(uint64_t targetId, const std::string& targetType);
    std::vector<ReflectionFinding> analyzeMission(uint64_t missionId);
    std::vector<ReflectionFinding> analyzeAgent(uint64_t agentId);
    std::vector<ReflectionFinding> analyzePlan(uint64_t planId);
    std::vector<ReflectionFinding> analyzeSystemHealth();
    
    std::vector<ReflectionFinding> identifyBottlenecks();
    std::vector<ReflectionFinding> identifyWaste();
    std::vector<ReflectionFinding> identifyRisks();
    
    std::vector<std::string> suggestImprovements(uint64_t targetId);
    std::vector<std::string> suggestAgentImprovements(uint64_t agentId);
    std::vector<std::string> suggestSystemImprovements();
    
    std::string extractLesson(uint64_t missionId);
    std::vector<std::string> extractBestPractices(const std::string& domain);
    std::vector<std::string> extractAntiPatterns(const std::string& domain);
    
    struct Stats {
        size_t reflectionsPerformed = 0;
        size_t findingsGenerated = 0;
        size_t lessonsExtracted = 0;
        double averageReflectionTimeMs = 0.0;
    };
    Stats getStats() const;

private:
    ExecutiveDirector* director_ = nullptr;
    std::unordered_map<uint64_t, ReflectionFinding> findings_;
    std::unordered_map<uint64_t, PerformanceAnalysis> analyses_;
    
    std::atomic<uint64_t> nextFindingId_{1};
    std::atomic<size_t> reflectionsPerformed_{0};
    std::atomic<size_t> findingsGenerated_{0};
    std::atomic<size_t> lessonsExtracted_{0};
    double totalReflectionTimeMs_ = 0.0;
    
    mutable std::mutex mutex_;
    
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
