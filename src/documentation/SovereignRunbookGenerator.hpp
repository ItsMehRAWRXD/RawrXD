// Phase D.11 Batch 2/5: Runbook Generator
// Automated operational runbooks from code annotations
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Documentation {

// ============================================================================
// Runbook Types
// ============================================================================

enum class RunbookSeverity {
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    CRITICAL = 3
};

enum class RunbookCategory {
    DEPLOYMENT = 0,
    MONITORING = 1,
    TROUBLESHOOTING = 2,
    MAINTENANCE = 3,
    SECURITY = 4,
    BACKUP = 5,
    RECOVERY = 6,
    SCALING = 7
};

struct RunbookStep {
    int step_number;
    std::string title;
    std::string description;
    std::string command;
    std::string expected_output;
    std::string validation;
    std::vector<std::string> prerequisites;
    std::chrono::seconds estimated_duration{0};
    bool requires_approval = false;
    std::string approver_role;
    std::vector<std::string> rollback_steps;
};

struct Runbook {
    std::string id;
    std::string title;
    std::string description;
    RunbookCategory category;
    RunbookSeverity severity;
    std::vector<std::string> tags;
    std::vector<RunbookStep> steps;
    std::map<std::string, std::string> metadata;
    std::vector<std::string> related_alerts;
    std::vector<std::string> related_services;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string author;
    std::string version;
    bool automated = false;
    std::string automation_script;
};

// ============================================================================
// Annotation Parser
// ============================================================================

struct RunbookAnnotation {
    std::string trigger;  // alert name, metric threshold, etc.
    std::string description;
    RunbookSeverity severity;
    RunbookCategory category;
    std::vector<std::string> steps;
    std::vector<std::string> prerequisites;
    std::string estimated_time;
    std::string owner;
    std::vector<std::string> related_services;
};

class RunbookAnnotationParser {
public:
    struct Config {
        std::vector<std::string> source_paths;
        std::vector<std::string> annotation_prefixes = {"@runbook", "@playbook"};
        bool parse_markdown = true;
        bool parse_yaml = true;
        bool extract_from_comments = true;
    };
    
    explicit RunbookAnnotationParser(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Parsing
    std::vector<RunbookAnnotation> ParseFile(const std::string& path);
    std::vector<RunbookAnnotation> ParseDirectory(const std::string& path);
    std::vector<RunbookAnnotation> ParseAlertDefinitions(const std::string& path);
    std::vector<RunbookAnnotation> ParseMetricDefinitions(const std::string& path);
    
    // Annotation extraction
    RunbookAnnotation ExtractAnnotation(const std::string& comment);
    std::vector<RunbookAnnotation> ExtractFromCode(const std::string& code);
    
private:
    Config config_;
    
    RunbookAnnotation ParseAnnotationBlock(const std::string& block);
    std::vector<std::string> SplitSteps(const std::string& steps_text);
};

// ============================================================================
// Runbook Generator
// ============================================================================

class RunbookGenerator {
public:
    struct Config {
        std::string output_directory;
        std::string template_directory;
        bool generate_markdown = true;
        bool generate_html = true;
        bool generate_pdf = false;
        bool include_diagrams = true;
        bool validate_commands = true;
    };
    
    explicit RunbookGenerator(const Config& config);
    
    // Generation
    Runbook GenerateFromAnnotation(const RunbookAnnotation& annotation);
    std::vector<Runbook> GenerateFromAlert(const std::string& alert_name,
                                           const std::map<std::string, std::string>& alert_config);
    std::vector<Runbook> GenerateFromMetric(const std::string& metric_name,
                                           double threshold);
    
    // Template-based generation
    Runbook GenerateDeploymentRunbook(const std::string& service_name,
                                       const std::string& version);
    Runbook GenerateScalingRunbook(const std::string& service_name,
                                  int target_replicas);
    Runbook GenerateRecoveryRunbook(const std::string& service_name,
                                   const std::string& failure_scenario);
    Runbook GenerateSecurityIncidentRunbook(const std::string& incident_type);
    
    // Export
    bool ExportToMarkdown(const Runbook& runbook, const std::string& path);
    bool ExportToHTML(const Runbook& runbook, const std::string& path);
    bool ExportToPDF(const Runbook& runbook, const std::string& path);
    bool ExportToConfluence(const Runbook& runbook, const std::string& space_key);
    bool ExportToServiceNow(const Runbook& runbook, const std::string& instance);
    
    // Batch export
    bool ExportAllRunbooks(const std::vector<Runbook>& runbooks,
                          const std::string& output_dir);
    
private:
    Config config_;
    
    std::string GenerateMarkdown(const Runbook& runbook);
    std::string GenerateHTML(const Runbook& runbook);
    std::string GenerateStepMarkdown(const RunbookStep& step);
    std::string GenerateStepHTML(const RunbookStep& step);
};

// ============================================================================
// Interactive Runbook Executor
// ============================================================================

class RunbookExecutor {
public:
    struct ExecutionContext {
        std::string runbook_id;
        std::string executed_by;
        std::chrono::steady_clock::time_point started_at;
        std::map<std::string, std::string> variables;
        std::vector<std::string> approvals;
    };
    
    struct ExecutionResult {
        bool success;
        std::string runbook_id;
        int completed_steps;
        int total_steps;
        std::chrono::seconds duration{0};
        std::string output;
        std::string error;
        std::vector<std::pair<int, bool>> step_results;
    };
    
    explicit RunbookExecutor(const std::string& working_directory);
    
    // Execution
    ExecutionResult Execute(const Runbook& runbook, 
                            const std::map<std::string, std::string>& variables = {});
    ExecutionResult ExecuteStep(const Runbook& runbook, int step_number,
                                 const ExecutionContext& context);
    
    // Interactive mode
    void ExecuteInteractive(const Runbook& runbook);
    bool PromptForConfirmation(const std::string& message);
    std::string PromptForInput(const std::string& prompt);
    
    // Validation
    bool ValidatePrerequisites(const Runbook& runbook);
    bool ValidateStep(const RunbookStep& step, std::string& error);
    
    // Dry run
    ExecutionResult DryRun(const Runbook& runbook);
    
    // Automation
    bool CanAutomate(const Runbook& runbook);
    ExecutionResult ExecuteAutomated(const Runbook& runbook);
    
private:
    std::string working_directory_;
    
    bool ExecuteCommand(const std::string& command, std::string& output, std::string& error);
    bool ValidateOutput(const std::string& actual, const std::string& expected);
};

// ============================================================================
// Runbook Library
// ============================================================================

class RunbookLibrary {
public:
    struct Config {
        std::string storage_path;
        bool enable_versioning = true;
        bool enable_search = true;
    };
    
    explicit RunbookLibrary(const Config& config);
    
    // CRUD operations
    bool AddRunbook(const Runbook& runbook);
    bool UpdateRunbook(const std::string& id, const Runbook& runbook);
    bool DeleteRunbook(const std::string& id);
    Runbook GetRunbook(const std::string& id) const;
    
    // Search
    std::vector<Runbook> Search(const std::string& query) const;
    std::vector<Runbook> GetByCategory(RunbookCategory category) const;
    std::vector<Runbook> GetBySeverity(RunbookSeverity severity) const;
    std::vector<Runbook> GetByTag(const std::string& tag) const;
    std::vector<Runbook> GetByService(const std::string& service) const;
    
    // Related runbooks
    std::vector<Runbook> GetRelatedRunbooks(const std::string& alert_name) const;
    std::vector<Runbook> GetRelatedToService(const std::string& service) const;
    
    // Statistics
    struct LibraryStats {
        int total_runbooks = 0;
        int automated_runbooks = 0;
        std::map<RunbookCategory, int> by_category;
        std::map<RunbookSeverity, int> by_severity;
        std::chrono::steady_clock::time_point last_updated;
    };
    
    LibraryStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, Runbook> runbooks_;
    mutable std::mutex runbooks_mutex_;
};

// ============================================================================
// Alert-Runbook Integration
// ============================================================================

class AlertRunbookIntegration {
public:
    struct Config {
        std::string alertmanager_url;
        std::string runbook_library_path;
        bool auto_suggest_runbooks = true;
        bool auto_link_runbooks = true;
    };
    
    explicit AlertRunbookIntegration(const Config& config);
    
    // Integration
    bool LinkAlertToRunbook(const std::string& alert_name, 
                            const std::string& runbook_id);
    bool UnlinkAlertFromRunbook(const std::string& alert_name);
    
    // Suggestion
    std::vector<Runbook> SuggestRunbooks(const std::string& alert_name,
                                          const std::map<std::string, std::string>& labels);
    std::vector<Runbook> SuggestRunbooksForMetric(const std::string& metric_name,
                                                   double value);
    
    // Auto-execution
    bool CanAutoExecute(const std::string& alert_name);
    bool AutoExecuteRunbook(const std::string& alert_name,
                            const std::map<std::string, std::string>& context);
    
    // Webhook handler
    void HandleAlertWebhook(const std::string& payload);
    
private:
    Config config_;
    std::map<std::string, std::string> alert_runbook_links_;
    mutable std::mutex links_mutex_;
};

// ============================================================================
// Runbook Analytics
// ============================================================================

struct RunbookExecutionMetrics {
    std::string runbook_id;
    int execution_count = 0;
    int success_count = 0;
    int failure_count = 0;
    std::chrono::seconds avg_duration{0};
    std::chrono::seconds min_duration{0};
    std::chrono::seconds max_duration{0};
    std::map<int, int> step_failure_counts;
    std::chrono::steady_clock::time_point last_executed;
};

class RunbookAnalytics {
public:
    // Metrics collection
    void RecordExecution(const ExecutionResult& result);
    void RecordStepExecution(const std::string& runbook_id, int step_number,
                             bool success, std::chrono::seconds duration);
    
    // Analysis
    RunbookExecutionMetrics GetMetrics(const std::string& runbook_id) const;
    std::vector<Runbook> GetMostUsedRunbooks(int limit = 10) const;
    std::vector<Runbook> GetMostFailedRunbooks(int limit = 10) const;
    std::vector<Runbook> GetSlowestRunbooks(int limit = 10) const;
    
    // Optimization suggestions
    std::vector<std::string> SuggestOptimizations(const std::string& runbook_id) const;
    std::vector<std::string> IdentifyBottlenecks(const std::string& runbook_id) const;
    
    // Reporting
    void GenerateExecutionReport(const std::string& output_path,
                                  std::chrono::hours time_range = std::chrono::hours(168));
    
private:
    std::map<std::string, RunbookExecutionMetrics> metrics_;
    mutable std::mutex metrics_mutex_;
};

// ============================================================================
// Runbook Runtime
// ============================================================================

class RunbookRuntime {
public:
    struct Config {
        RunbookAnnotationParser::Config parser;
        RunbookGenerator::Config generator;
        RunbookLibrary::Config library;
        AlertRunbookIntegration::Config integration;
        std::string execution_working_directory;
    };
    
    explicit RunbookRuntime(const Config& config);
    ~RunbookRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    RunbookAnnotationParser* GetParser();
    RunbookGenerator* GetGenerator();
    RunbookLibrary* GetLibrary();
    RunbookExecutor* GetExecutor();
    AlertRunbookIntegration* GetIntegration();
    RunbookAnalytics* GetAnalytics();
    
    // Workflow
    bool ParseAnnotations(const std::string& source_path);
    bool GenerateRunbooks();
    bool ExecuteRunbook(const std::string& runbook_id);
    
    // Integration
    bool LinkAlertsToRunbooks();
    bool SetupAutoExecution();
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<RunbookAnnotationParser> parser_;
    std::unique_ptr<RunbookGenerator> generator_;
    std::unique_ptr<RunbookLibrary> library_;
    std::unique_ptr<RunbookExecutor> executor_;
    std::unique_ptr<AlertRunbookIntegration> integration_;
    std::unique_ptr<RunbookAnalytics> analytics_;
};

} // namespace Documentation
} // namespace Sovereign
