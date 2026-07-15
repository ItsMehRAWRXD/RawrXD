#pragma once

#include "statistical_analysis.hpp"
#include <string>
#include <vector>
#include <map>

namespace rawrxd {
namespace benchmarks {

/**
 * Phase E.1 Batch 5/5: Validation Report Generation
 * 
 * Produces publication-ready reports from benchmark execution.
 * Generates JSON, Markdown, CSV, and HTML outputs.
 */

// Complete Phase E.1 validation results
struct PhaseE1ValidationResults {
    // Metadata
    std::string validation_id;
    std::string validation_version = "1.0.0";
    std::chrono::system_clock::time_point execution_timestamp;
    std::chrono::seconds total_execution_time;
    
    // Hardware profile
    HardwareProfile hardware;
    
    // Batch results
    CalibrationReport calibration;
    BaselineValidationReport baseline;
    std::vector<HotpatchInterventionResult> interventions;
    AggregatedAnalysis analysis;
    
    // Summary
    int models_tested;
    int patches_tested;
    int successful_interventions;
    int failed_interventions;
    double overall_success_rate;
    
    // Key findings
    double best_improvement_percent;
    std::string best_improvement_model;
    std::string best_improvement_patch;
    double average_improvement_percent;
    int statistically_significant_improvements;
    
    // Validation status
    bool hardware_validated;
    bool baselines_established;
    bool interventions_completed;
    bool analysis_completed;
    bool overall_pass;
    
    std::vector<std::string> critical_findings;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
};

// Report configuration
struct ReportConfig {
    std::string output_directory = "./phase_e1_results";
    std::string validation_name = "RawrXD Hotpatch Validation";
    std::string validation_description = "Phase E.1: Live Runtime Optimization Evidence";
    
    // Output formats
    bool generate_json = true;
    bool generate_markdown = true;
    bool generate_csv = true;
    bool generate_html = true;
    bool generate_graphs = true;
    
    // Graph settings
    int graph_width = 1200;
    int graph_height = 800;
    std::string graph_format = "png";  // png, svg, pdf
    
    // HTML settings
    std::string html_theme = "professional";  // professional, minimal, dark
    bool include_interactive_charts = true;
};

// Validation report generator
class ValidationReportGenerator {
public:
    explicit ValidationReportGenerator(const ReportConfig& config);
    
    // Generate complete report
    void GenerateReport(const PhaseE1ValidationResults& results);
    
    // Individual exports
    void ExportJson(const PhaseE1ValidationResults& results);
    void ExportMarkdown(const PhaseE1ValidationResults& results);
    void ExportCsv(const PhaseE1ValidationResults& results);
    void ExportHtml(const PhaseE1ValidationResults& results);
    void GenerateGraphs(const PhaseE1ValidationResults& results);
    
    // Summary exports
    void ExportExecutiveSummary(const PhaseE1ValidationResults& results);
    void ExportTechnicalAppendix(const PhaseE1ValidationResults& results);
    void ExportRawData(const PhaseE1ValidationResults& results);

private:
    ReportConfig config_;
    
    // Internal helpers
    std::string GenerateJsonContent(const PhaseE1ValidationResults& results);
    std::string GenerateMarkdownContent(const PhaseE1ValidationResults& results);
    std::string GenerateHtmlContent(const PhaseE1ValidationResults& results);
    std::string GenerateExecutiveSummary(const PhaseE1ValidationResults& results);
    std::string GenerateTechnicalDetails(const PhaseE1ValidationResults& results);
    
    // Graph generation (placeholder - would use matplotlib/plotly in real impl)
    void GenerateTpsComparisonGraph(const PhaseE1ValidationResults& results);
    void GenerateEffectSizeGraph(const PhaseE1ValidationResults& results);
    void GenerateSignificanceGraph(const PhaseE1ValidationResults& results);
    void GenerateImprovementDistributionGraph(const PhaseE1ValidationResults& results);
    void GenerateStabilityGraph(const PhaseE1ValidationResults& results);
    
    // File utilities
    void EnsureDirectoryExists(const std::string& path);
    void WriteFile(const std::string& path, const std::string& content);
};

// Predefined report templates
struct ReportTemplate {
    static std::string GetExecutiveSummaryTemplate();
    static std::string GetTechnicalReportTemplate();
    static std::string GetHtmlDashboardTemplate();
    static std::string GetCsvHeader();
};

// Validation verdict
struct ValidationVerdict {
    static std::string GetVerdict(const PhaseE1ValidationResults& results) {
        if (!results.overall_pass) return "FAILED";
        if (results.average_improvement_percent > 15.0 && 
            results.statistically_significant_improvements >= results.patches_tested / 2) {
            return "EXCELLENT";
        }
        if (results.average_improvement_percent > 10.0) return "GOOD";
        if (results.average_improvement_percent > 5.0) return "ACCEPTABLE";
        return "MARGINAL";
    }
    
    static std::string GetDescription(const std::string& verdict) {
        if (verdict == "EXCELLENT") return 
            "Hotpatching delivers substantial, statistically significant TPS improvements across models.";
        if (verdict == "GOOD") return 
            "Hotpatching delivers meaningful TPS improvements with good statistical confidence.";
        if (verdict == "ACCEPTABLE") return 
            "Hotpatching shows measurable improvements but may be model-dependent.";
        if (verdict == "MARGINAL") return 
            "Hotpatching shows limited improvement; further optimization needed.";
        return "Validation failed; critical issues detected.";
    }
};

// Factory
std::unique_ptr<ValidationReportGenerator> CreateValidationReportGenerator(
    const ReportConfig& config = ReportConfig());

// Quick report generation
void GeneratePhaseE1Report(const PhaseE1ValidationResults& results,
                           const std::string& output_dir = "./phase_e1_results");

} // namespace benchmarks
} // namespace rawrxd
