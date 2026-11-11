// VAL-077: Continuous Certification Runner
// CI/CD integration for automated certification

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Certification Stage
// ============================================================================

enum class CertificationStage {
    BUILD,
    UNIT_VALIDATION,
    RUNTIME_VALIDATION,
    PERFORMANCE_ENVELOPE,
    SECURITY_BOUNDARY,
    ARTIFACT_SEALING,
    RELEASE_CANDIDATE
};

struct StageResult {
    CertificationStage stage;
    bool passed;
    uint64_t duration_ms;
    std::string evidence_path;
    std::vector<std::string> logs;
    std::vector<std::string> errors;
    
    bool IsSuccess() const { return passed && errors.empty(); }
    std::string Serialize() const;
};

// ============================================================================
// Certification Pipeline
// ============================================================================

struct CertificationPipeline {
    std::string commit_hash;
    std::string branch;
    std::string timestamp;
    std::vector<StageResult> stages;
    
    bool AllStagesPassed() const;
    std::string GenerateReport() const;
    std::string Serialize() const;
};

// ============================================================================
// CI/CD Integration
// ============================================================================

struct CIConfig {
    std::string provider;           // "github_actions", "gitlab_ci", "jenkins"
    std::string runner_os;
    std::string runner_arch;
    std::vector<std::string> matrix_configs;
    
    // Triggers
    bool run_on_push;
    bool run_on_pr;
    bool run_on_schedule;
    std::string schedule_cron;
    
    // Notifications
    std::string slack_webhook;
    std::string email_recipients;
    
    std::string Serialize() const;
};

class CICertificationRunner {
public:
    CICertificationRunner();
    ~CICertificationRunner();
    
    // Initialize with CI configuration
    bool Initialize(const CIConfig& config);
    
    // Run complete certification pipeline
    CertificationPipeline RunPipeline(const std::string& commit_hash);
    
    // Individual stage runners
    StageResult RunBuildStage();
    StageResult RunUnitValidationStage();
    StageResult RunRuntimeValidationStage();
    StageResult RunPerformanceEnvelopeStage();
    StageResult RunSecurityBoundaryStage();
    StageResult RunArtifactSealingStage();
    StageResult RunReleaseCandidateStage();
    
    // Get pipeline status
    CertificationPipeline GetCurrentPipeline() const;
    
    // Save certification report
    bool SaveCertificationReport(const std::string& output_dir);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Certification Report
// ============================================================================

struct CertificationReport {
    // Metadata
    std::string report_id;
    std::string generated_at;
    std::string commit_hash;
    std::string release_version;
    
    // Pipeline results
    CertificationPipeline pipeline;
    
    // Evidence artifacts
    std::vector<std::string> evidence_paths;
    std::string manifest_path;
    std::string signature_path;
    
    // Telemetry
    std::string telemetry_path;
    std::string performance_path;
    std::string security_path;
    
    // Status
    bool certified;
    std::string certification_level;  // "RC-1", "RC-1.1", "RC-1.2"
    
    std::string Serialize() const;
    static std::optional<CertificationReport> Load(const std::string& path);
};

class CertificationReportGenerator {
public:
    CertificationReportGenerator();
    ~CertificationReportGenerator();
    
    // Generate complete report
    CertificationReport GenerateReport(
        const CertificationPipeline& pipeline,
        const std::string& evidence_dir
    );
    
    // Generate report sections
    std::string GenerateManifestSection() const;
    std::string GenerateTelemetrySection() const;
    std::string GeneratePerformanceSection() const;
    std::string GenerateSecuritySection() const;
    
    // Save report package
    bool SaveReportPackage(
        const CertificationReport& report,
        const std::string& output_dir
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Report Structure
// ============================================================================

/*
CERTIFICATION_REPORT/
├── manifest.json                    ← Complete certification manifest
├── evidence/
│   ├── VAL-050/ → VAL-063/         ← All evidence artifacts
│   └── EVIDENCE_MANIFEST.json
├── telemetry/
│   ├── build.log
│   ├── test_execution.log
│   └── performance_metrics.json
├── performance/
│   ├── throughput_benchmarks.json
│   ├── latency_analysis.json
│   └── memory_profile.json
├── security/
│   ├── threat_boundary_tests.json
│   ├── fault_injection_results.json
│   └── vulnerability_scan.json
└── signature/
    └── manifest_signature.json      ← VAL-074 signature
*/

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Pipeline runner
typedef struct Val077PipelineRunner* Val077RunnerHandle;

Val077RunnerHandle val077_runner_create();
int val077_runner_initialize(Val077RunnerHandle handle, const char* config_json);
int val077_run_pipeline(Val077RunnerHandle handle, const char* commit_hash);
const char* val077_get_pipeline_status(Val077RunnerHandle handle);
void val077_runner_destroy(Val077RunnerHandle handle);

// Report generation
typedef struct Val077ReportGenerator* Val077ReportHandle;

Val077ReportHandle val077_report_create();
const char* val077_generate_report(
    Val077ReportHandle handle,
    const char* pipeline_json,
    const char* evidence_dir
);
int val077_save_report_package(
    Val077ReportHandle handle,
    const char* report_json,
    const char* output_dir
);
void val077_report_destroy(Val077ReportHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
