// Phase W.4/5: Evidence Dashboard
// RawrXD Evidence Dashboard - Project state summary and validation evidence

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Convergence {

// Evidence types
enum class EvidenceType {
    IMPLEMENTATION,   // Code implemented
    UNIT_TEST,      // Unit tests
    INTEGRATION_TEST, // Integration tests
    BENCHMARK,      // Performance benchmarks
    DOCUMENTATION,    // Documentation
    VALIDATION,     // Validation results
    PRODUCTION      // Production usage
};

// Evidence status
enum class EvidenceStatus {
    MISSING,        // No evidence
    IN_PROGRESS,    // Evidence being collected
    PARTIAL,        // Partial evidence
    COMPLETE        // Complete evidence
};

// Area status
struct AreaStatus {
    std::string area_name;
    std::string description;
    
    // Status
    EvidenceStatus implementation_status;
    EvidenceStatus test_status;
    EvidenceStatus benchmark_status;
    EvidenceStatus documentation_status;
    EvidenceStatus validation_status;
    
    // Overall
    EvidenceStatus overall_status;
    std::string status_reason;
    
    // Evidence
    std::vector<std::string> evidence_files;
    std::vector<std::string> test_results;
    std::vector<std::string> benchmark_results;
    
    // Metrics
    uint32_t test_coverage_percent;
    double benchmark_score;
    uint32_t validation_pass_rate;
    
    // Last updated
    std::chrono::system_clock::time_point last_updated;
};

// Dashboard view
struct DashboardView {
    std::string view_id;
    std::string name;
    std::chrono::system_clock::time_point generated_at;
    
    // Summary
    uint32_t total_areas;
    uint32_t complete_areas;
    uint32_t partial_areas;
    uint32_t missing_areas;
    
    // Areas
    std::vector<AreaStatus> areas;
    
    // Critical gaps
    std::vector<std::string> critical_gaps;
    std::vector<std::string> recommendations;
    
    // Overall health
    double overall_health_score;
    std::string health_assessment;
};

// Trend data
struct TrendData {
    std::string metric_name;
    std::vector<std::pair<std::chrono::system_clock::time_point, double>> data_points;
    double trend_direction;  // Positive = improving
    double trend_slope;
};

// Evidence dashboard interface
class IEvidenceDashboard {
public:
    virtual ~IEvidenceDashboard() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Area management
    virtual std::string RegisterArea(const AreaStatus& area) = 0;
    virtual bool UpdateArea(const AreaStatus& area) = 0;
    virtual bool UpdateAreaStatus(const std::string& area_id, 
                                   EvidenceType type, 
                                   EvidenceStatus status) = 0;
    virtual std::optional<AreaStatus> GetArea(const std::string& area_id) = 0;
    virtual std::vector<AreaStatus> ListAreas() = 0;
    virtual std::vector<AreaStatus> GetAreasByStatus(EvidenceStatus status) = 0;
    
    // Evidence management
    virtual bool AddEvidence(const std::string& area_id, 
                              EvidenceType type, 
                              const std::string& evidence_path) = 0;
    virtual bool AddTestResult(const std::string& area_id, 
                                  const std::string& test_suite,
                                  bool passed,
                                  uint32_t coverage_percent) = 0;
    virtual bool AddBenchmarkResult(const std::string& area_id,
                                     const std::string& benchmark_name,
                                     double score) = 0;
    
    // Dashboard generation
    virtual DashboardView GenerateDashboard() = 0;
    virtual DashboardView GenerateDashboardForSubsystem(const std::string& subsystem) = 0;
    virtual std::string ExportDashboard(const std::string& format = "markdown") = 0;
    
    // Gap analysis
    virtual std::vector<std::string> IdentifyCriticalGaps() = 0;
    virtual std::vector<std::string> GenerateRecommendations() = 0;
    virtual std::vector<AreaStatus> GetAreasNeedingAttention() = 0;
    
    // Trends
    virtual void RecordMetric(const std::string& metric_name, double value) = 0;
    virtual TrendData GetTrend(const std::string& metric_name, 
                                std::chrono::days lookback = std::chrono::days(30)) = 0;
    virtual std::vector<TrendData> GetAllTrends() = 0;
    
    // Comparison
    virtual bool CompareToTarget(const std::string& area_id) = 0;
    virtual bool CompareToPrevious(const std::string& area_id) = 0;
    
    // Reporting
    virtual std::string GenerateMarkdownReport() = 0;
    virtual std::string GenerateJSONReport() = 0;
    virtual std::string GenerateHTMLReport() = 0;
    virtual bool SaveReport(const std::string& path, const std::string& format = "markdown") = 0;
    
    // Statistics
    virtual struct DashboardStatistics {
        uint32_t total_areas;
        uint32_t complete_areas;
        uint32_t partial_areas;
        uint32_t missing_areas;
        double overall_completion_percent;
        double average_test_coverage;
        double average_benchmark_score;
        uint32_t critical_gaps;
        uint32_t recommendations;
    } GetStatistics() = 0;
};

// Local evidence dashboard
class LocalEvidenceDashboard : public IEvidenceDashboard {
public:
    LocalEvidenceDashboard();
    ~LocalEvidenceDashboard() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RegisterArea(const AreaStatus& area) override;
    bool UpdateArea(const AreaStatus& area) override;
    bool UpdateAreaStatus(const std::string& area_id, 
                           EvidenceType type, 
                           EvidenceStatus status) override;
    std::optional<AreaStatus> GetArea(const std::string& area_id) override;
    std::vector<AreaStatus> ListAreas() override;
    std::vector<AreaStatus> GetAreasByStatus(EvidenceStatus status) override;
    
    bool AddEvidence(const std::string& area_id, 
                      EvidenceType type, 
                      const std::string& evidence_path) override;
    bool AddTestResult(const std::string& area_id, 
                        const std::string& test_suite,
                        bool passed,
                        uint32_t coverage_percent) override;
    bool AddBenchmarkResult(const std::string& area_id,
                             const std::string& benchmark_name,
                             double score) override;
    
    DashboardView GenerateDashboard() override;
    DashboardView GenerateDashboardForSubsystem(const std::string& subsystem) override;
    std::string ExportDashboard(const std::string& format = "markdown") override;
    
    std::vector<std::string> IdentifyCriticalGaps() override;
    std::vector<std::string> GenerateRecommendations() override;
    std::vector<AreaStatus> GetAreasNeedingAttention() override;
    
    void RecordMetric(const std::string& metric_name, double value) override;
    TrendData GetTrend(const std::string& metric_name, 
                        std::chrono::days lookback = std::chrono::days(30)) override;
    std::vector<TrendData> GetAllTrends() override;
    
    bool CompareToTarget(const std::string& area_id) override;
    bool CompareToPrevious(const std::string& area_id) override;
    
    std::string GenerateMarkdownReport() override;
    std::string GenerateJSONReport() override;
    std::string GenerateHTMLReport() override;
    bool SaveReport(const std::string& path, const std::string& format = "markdown") override;
    
    DashboardStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, AreaStatus> areas_;
    std::unordered_map<std::string, std::vector<std::pair<std::chrono::system_clock::time_point, double>>> metrics_;
    bool initialized_ = false;
    
    EvidenceStatus CalculateOverallStatus(const AreaStatus& area);
    double CalculateHealthScore();
    std::vector<std::string> IdentifyGaps();
    std::string GenerateMarkdown();
    std::string GenerateJSON();
    std::string GenerateHTML();
};

// Global evidence dashboard
extern std::unique_ptr<IEvidenceDashboard> g_evidence_dashboard;

// Initialize evidence dashboard
bool InitializeEvidenceDashboard(const std::string& config_path);
void ShutdownEvidenceDashboard();
bool IsEvidenceDashboardEnabled();

// Evidence type helpers
std::string EvidenceTypeToString(EvidenceType type);
EvidenceType EvidenceTypeFromString(const std::string& str);
std::string EvidenceStatusToString(EvidenceStatus status);
EvidenceStatus EvidenceStatusFromString(const std::string& str);

} // namespace Convergence
} // namespace RawrXD
