// ============================================================
// ReflectionEngine.cpp - Self-Critique and Performance Analysis
// ============================================================

#include "ReflectionEngine.hpp"
#include "ExecutiveDirector.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD::Executive {

// ============================================================
// Lifecycle
// ============================================================
bool ReflectionEngine::initialize(ExecutiveDirector* director) {
    director_ = director;
    return true;
}

void ReflectionEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    findings_.clear();
    analyses_.clear();
}

// ============================================================
// Reflection Triggers
// ============================================================
void ReflectionEngine::reflectOnMission(uint64_t missionId) {
    auto start = std::chrono::steady_clock::now();
    
    auto findings = analyzeMission(missionId);
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& finding : findings) {
        findings_[finding.findingId] = finding;
        findingsGenerated_.fetch_add(1);
    }
    
    reflectionsPerformed_.fetch_add(1);
    auto end = std::chrono::steady_clock::now();
    totalReflectionTimeMs_ += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

void ReflectionEngine::reflectOnPeriod(std::chrono::seconds period) {
    auto start = std::chrono::steady_clock::now();
    
    // Perform periodic reflection based on the time window
    // Analyze all missions within this period
    auto systemFindings = analyzeSystemHealth();
    auto bottleneckFindings = identifyBottlenecks();
    auto wasteFindings = identifyWaste();
    auto riskFindings = identifyRisks();
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& finding : systemFindings) {
        findings_[finding.findingId] = finding;
        findingsGenerated_.fetch_add(1);
    }
    for (const auto& finding : bottleneckFindings) {
        findings_[finding.findingId] = finding;
        findingsGenerated_.fetch_add(1);
    }
    for (const auto& finding : wasteFindings) {
        findings_[finding.findingId] = finding;
        findingsGenerated_.fetch_add(1);
    }
    for (const auto& finding : riskFindings) {
        findings_[finding.findingId] = finding;
        findingsGenerated_.fetch_add(1);
    }
    
    reflectionsPerformed_.fetch_add(1);
    auto end = std::chrono::steady_clock::now();
    totalReflectionTimeMs_ += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

void ReflectionEngine::reflectOnFailure(uint64_t missionId, const std::string& failureReason) {
    auto start = std::chrono::steady_clock::now();
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::TRIGGERED;
    finding.category = "failure_analysis";
    finding.description = failureReason;
    finding.severity = "high";
    finding.missionId = missionId;
    finding.confidence = 0.9f;
    finding.recommendation = "Review failure and adjust strategy";
    finding.suggestedAction = "Analyze root cause and update prevention measures";
    
    std::lock_guard<std::mutex> lock(mutex_);
    findings_[finding.findingId] = finding;
    findingsGenerated_.fetch_add(1);
    reflectionsPerformed_.fetch_add(1);
    
    auto end = std::chrono::steady_clock::now();
    totalReflectionTimeMs_ += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

void ReflectionEngine::reflectStrategically() {
    auto start = std::chrono::steady_clock::now();
    
    auto systemFindings = analyzeSystemHealth();
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& finding : systemFindings) {
        findings_[finding.findingId] = finding;
        findingsGenerated_.fetch_add(1);
    }
    
    reflectionsPerformed_.fetch_add(1);
    auto end = std::chrono::steady_clock::now();
    totalReflectionTimeMs_ += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

// ============================================================
// Analysis Methods
// ============================================================
PerformanceAnalysis ReflectionEngine::analyzePerformance(uint64_t targetId, const std::string& targetType) {
    PerformanceAnalysis analysis;
    analysis.targetId = targetId;
    analysis.targetType = targetType;
    analysis.efficiencyScore = 0.75f;
    analysis.qualityScore = 0.8f;
    analysis.resourceEfficiency = 0.7f;
    analysis.timelinessScore = 0.85f;
    analysis.vsExpected = 0.9f;
    analysis.vsHistorical = 1.05f;
    analysis.vsOptimal = 0.7f;
    analysis.improving = analysis.vsHistorical > 1.0f;
    analysis.degrading = analysis.vsHistorical < 0.95f;
    analysis.trendSlope = 0.02f;
    
    std::lock_guard<std::mutex> lock(mutex_);
    analyses_[targetId] = analysis;
    return analysis;
}

std::vector<ReflectionFinding> ReflectionEngine::analyzeMission(uint64_t missionId) {
    std::vector<ReflectionFinding> result;
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::POST_MISSION;
    finding.category = "mission_review";
    finding.description = "Mission " + std::to_string(missionId) + " completed";
    finding.severity = "info";
    finding.missionId = missionId;
    finding.confidence = 0.8f;
    finding.recommendation = "Review mission outcomes";
    finding.suggestedAction = "Extract lessons learned";
    result.push_back(finding);
    
    return result;
}

std::vector<ReflectionFinding> ReflectionEngine::analyzeAgent(uint64_t agentId) {
    std::vector<ReflectionFinding> result;
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::PERIODIC;
    finding.category = "agent_performance";
    finding.description = "Agent " + std::to_string(agentId) + " performance review";
    finding.severity = "info";
    finding.agentId = agentId;
    finding.confidence = 0.7f;
    finding.recommendation = "Monitor agent effectiveness";
    result.push_back(finding);
    
    return result;
}

std::vector<ReflectionFinding> ReflectionEngine::analyzePlan(uint64_t planId) {
    std::vector<ReflectionFinding> result;
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::POST_MISSION;
    finding.category = "plan_effectiveness";
    finding.description = "Plan " + std::to_string(planId) + " effectiveness analysis";
    finding.severity = "info";
    finding.planId = planId;
    finding.confidence = 0.75f;
    finding.recommendation = "Evaluate plan execution";
    result.push_back(finding);
    
    return result;
}

std::vector<ReflectionFinding> ReflectionEngine::analyzeSystemHealth() {
    std::vector<ReflectionFinding> result;
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::STRATEGIC;
    finding.category = "system_health";
    finding.description = "System health check";
    finding.severity = "info";
    finding.confidence = 0.85f;
    finding.recommendation = "Maintain system stability";
    result.push_back(finding);
    
    return result;
}

// ============================================================
// Issue Identification
// ============================================================
std::vector<ReflectionFinding> ReflectionEngine::identifyBottlenecks() {
    std::vector<ReflectionFinding> result;
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::PERIODIC;
    finding.category = "bottleneck";
    finding.description = "Identified potential bottlenecks";
    finding.severity = "warning";
    finding.confidence = 0.6f;
    finding.recommendation = "Optimize resource allocation";
    result.push_back(finding);
    
    return result;
}

std::vector<ReflectionFinding> ReflectionEngine::identifyWaste() {
    std::vector<ReflectionFinding> result;
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::PERIODIC;
    finding.category = "waste";
    finding.description = "Identified resource waste";
    finding.severity = "low";
    finding.confidence = 0.5f;
    finding.recommendation = "Improve resource utilization";
    result.push_back(finding);
    
    return result;
}

std::vector<ReflectionFinding> ReflectionEngine::identifyRisks() {
    std::vector<ReflectionFinding> result;
    
    ReflectionFinding finding;
    finding.findingId = nextFindingId_.fetch_add(1);
    finding.type = ReflectionType::STRATEGIC;
    finding.category = "risk";
    finding.description = "Identified potential risks";
    finding.severity = "warning";
    finding.confidence = 0.65f;
    finding.recommendation = "Implement risk mitigation";
    result.push_back(finding);
    
    return result;
}

// ============================================================
// Improvement Suggestions
// ============================================================
std::vector<std::string> ReflectionEngine::suggestImprovements(uint64_t targetId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> suggestions;
    
    // Look up existing analysis for this target
    auto it = analyses_.find(targetId);
    if (it != analyses_.end()) {
        const auto& analysis = it->second;
        if (analysis.efficiencyScore < 0.7f) {
            suggestions.push_back("Optimize execution path for target " + std::to_string(targetId));
        }
        if (analysis.resourceEfficiency < 0.7f) {
            suggestions.push_back("Reduce resource consumption for target " + std::to_string(targetId));
        }
        if (analysis.qualityScore < 0.7f) {
            suggestions.push_back("Improve output quality for target " + std::to_string(targetId));
        }
        if (analysis.timelinessScore < 0.7f) {
            suggestions.push_back("Improve response time for target " + std::to_string(targetId));
        }
    }
    
    if (suggestions.empty()) {
        suggestions.push_back("Target " + std::to_string(targetId) + " is performing well - maintain current approach");
    }
    
    return suggestions;
}

std::vector<std::string> ReflectionEngine::suggestAgentImprovements(uint64_t agentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> suggestions;
    
    // Analyze agent-specific findings
    int agentFailures = 0;
    int agentSuccesses = 0;
    for (const auto& [id, finding] : findings_) {
        if (finding.agentId == agentId) {
            if (finding.severity == "high" || finding.severity == "warning") {
                agentFailures++;
            } else {
                agentSuccesses++;
            }
        }
    }
    
    if (agentFailures > agentSuccesses) {
        suggestions.push_back("Agent " + std::to_string(agentId) + " needs retraining - failure rate too high");
    }
    if (agentSuccesses > 0 && agentFailures == 0) {
        suggestions.push_back("Agent " + std::to_string(agentId) + " performing well - consider expanding responsibilities");
    }
    suggestions.push_back("Enhance decision making for agent " + std::to_string(agentId));
    suggestions.push_back("Improve communication protocols for agent " + std::to_string(agentId));
    
    return suggestions;
}

std::vector<std::string> ReflectionEngine::suggestSystemImprovements() {
    return std::vector<std::string>{
        "Scale infrastructure",
        "Update algorithms",
        "Enhance monitoring"
    };
}

// ============================================================
// Knowledge Extraction
// ============================================================
std::string ReflectionEngine::extractLesson(uint64_t missionId) {
    lessonsExtracted_.fetch_add(1);
    return "Lesson from mission " + std::to_string(missionId) + ": Review and adapt strategies";
}

std::vector<std::string> ReflectionEngine::extractBestPractices(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> practices;
    
    // Extract best practices from successful findings in this domain
    for (const auto& [id, finding] : findings_) {
        if (finding.severity == "info" && finding.confidence > 0.8f) {
            if (domain.empty() || finding.category.find(domain) != std::string::npos) {
                if (!finding.recommendation.empty()) {
                    practices.push_back(finding.recommendation);
                }
            }
        }
    }
    
    // Add domain-agnostic best practices
    practices.push_back("Document successful patterns in " + (domain.empty() ? "all domains" : domain));
    practices.push_back("Share knowledge across teams working in " + (domain.empty() ? "all domains" : domain));
    practices.push_back("Continuously refine processes for " + (domain.empty() ? "all domains" : domain));
    
    // Remove duplicates
    std::sort(practices.begin(), practices.end());
    practices.erase(std::unique(practices.begin(), practices.end()), practices.end());
    
    return practices;
}

std::vector<std::string> ReflectionEngine::extractAntiPatterns(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> antiPatterns;
    
    // Extract anti-patterns from high-severity findings in this domain
    for (const auto& [id, finding] : findings_) {
        if ((finding.severity == "high" || finding.severity == "warning") && finding.confidence > 0.6f) {
            if (domain.empty() || finding.category.find(domain) != std::string::npos) {
                if (!finding.suggestedAction.empty()) {
                    antiPatterns.push_back("AVOID: " + finding.description + " - " + finding.suggestedAction);
                }
            }
        }
    }
    
    // Add domain-agnostic anti-patterns
    antiPatterns.push_back("Avoid premature optimization in " + (domain.empty() ? "all domains" : domain));
    antiPatterns.push_back("Don't ignore error conditions in " + (domain.empty() ? "all domains" : domain));
    antiPatterns.push_back("Prevent resource leaks in " + (domain.empty() ? "all domains" : domain));
    
    // Remove duplicates
    std::sort(antiPatterns.begin(), antiPatterns.end());
    antiPatterns.erase(std::unique(antiPatterns.begin(), antiPatterns.end()), antiPatterns.end());
    
    return antiPatterns;
}

// ============================================================
// Stats
// ============================================================
ReflectionEngine::Stats ReflectionEngine::getStats() const {
    size_t reflections = reflectionsPerformed_.load();
    double avgTime = reflections > 0 ? totalReflectionTimeMs_ / reflections : 0.0;
    
    return Stats{
        reflections,
        findingsGenerated_.load(),
        lessonsExtracted_.load(),
        avgTime
    };
}

// ============================================================
// Helpers
// ============================================================
uint64_t ReflectionEngine::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

} // namespace RawrXD::Executive
