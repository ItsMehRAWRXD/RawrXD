// Phase D.11 Batch 5/5: Architecture Decision Records (ADR)
// ADR management and visualization
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
// ADR Types
// ============================================================================

enum class ADRStatus {
    PROPOSED = 0,
    ACCEPTED = 1,
    DEPRECATED = 2,
    SUPERSEDED = 3,
    REJECTED = 4
};

enum class ADRImpact {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2,
    CRITICAL = 3
};

struct ADRDecision {
    std::string id;
    std::string title;
    std::string context;
    std::string problem_statement;
    std::vector<std::string> options_considered;
    std::string decision;
    std::string rationale;
    std::vector<std::string> consequences;
    std::vector<std::string> pros;
    std::vector<std::string> cons;
    ADRStatus status;
    std::string superseded_by;
    std::vector<std::string> related_decisions;
    std::vector<std::string> stakeholders;
    std::string decider;
    std::chrono::steady_clock::time_point proposed_at;
    std::chrono::steady_clock::time_point decided_at;
    ADRImpact impact_level;
    std::vector<std::string> tags;
    std::map<std::string, std::string> metadata;
};

struct ADRComment {
    std::string id;
    std::string adr_id;
    std::string author;
    std::string content;
    std::chrono::steady_clock::time_point created_at;
    std::vector<std::string> reactions;
};

// ============================================================================
// ADR Manager
// ============================================================================

class ADRManager {
public:
    struct Config {
        std::string storage_path;
        std::string template_path;
        bool require_approval = true;
        int min_approvers = 2;
        bool enable_notifications = true;
    };
    
    explicit ADRManager(const Config& config);
    ~ADRManager();
    
    bool Initialize();
    void Shutdown();
    
    // CRUD operations
    std::string CreateADR(const ADRDecision& adr);
    bool UpdateADR(const std::string& id, const ADRDecision& adr);
    bool DeleteADR(const std::string& id);
    ADRDecision GetADR(const std::string& id) const;
    std::vector<ADRDecision> GetAllADRs() const;
    
    // Status management
    bool ProposeADR(const std::string& id);
    bool AcceptADR(const std::string& id, const std::string& decider);
    bool RejectADR(const std::string& id, const std::string& reason);
    bool DeprecateADR(const std::string& id, const std::string& reason);
    bool SupersedeADR(const std::string& id, const std::string& new_adr_id);
    
    // Search and filter
    std::vector<ADRDecision> GetByStatus(ADRStatus status) const;
    std::vector<ADRDecision> GetByImpact(ADRImpact impact) const;
    std::vector<ADRDecision> GetByTag(const std::string& tag) const;
    std::vector<ADRDecision> GetByStakeholder(const std::string& stakeholder) const;
    std::vector<ADRDecision> Search(const std::string& query) const;
    
    // Relationships
    std::vector<ADRDecision> GetRelatedDecisions(const std::string& id) const;
    std::vector<ADRDecision> GetDecisionChain(const std::string& id) const;
    std::map<std::string, std::vector<std::string>> GetDecisionGraph() const;
    
    // Comments
    std::string AddComment(const std::string& adr_id, const ADRComment& comment);
    std::vector<ADRComment> GetComments(const std::string& adr_id) const;
    bool DeleteComment(const std::string& comment_id);
    
    // Export
    bool ExportToMarkdown(const std::string& id, const std::string& path);
    bool ExportToPDF(const std::string& id, const std::string& path);
    bool ExportAllToDirectory(const std::string& directory);
    
    // Statistics
    struct ADRStats {
        int total_decisions = 0;
        std::map<ADRStatus, int> by_status;
        std::map<ADRImpact, int> by_impact;
        std::map<std::string, int> by_tag;
        std::chrono::steady_clock::time_point last_updated;
    };
    
    ADRStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, ADRDecision> adrs_;
    std::map<std::string, std::vector<ADRComment>> comments_;
    mutable std::mutex adrs_mutex_;
    
    std::string GenerateADRId();
    std::string RenderToMarkdown(const ADRDecision& adr);
};

// ============================================================================
// ADR Template System
// ============================================================================

class ADRTemplateSystem {
public:
    struct Template {
        std::string id;
        std::string name;
        std::string description;
        std::string content;
        std::vector<std::string> required_fields;
        std::map<std::string, std::string> default_values;
    };
    
    // Template management
    bool RegisterTemplate(const Template& tmpl);
    bool UpdateTemplate(const std::string& id, const Template& tmpl);
    Template GetTemplate(const std::string& id) const;
    std::vector<Template> GetAllTemplates() const;
    
    // Template usage
    ADRDecision CreateFromTemplate(const std::string& template_id,
                                    const std::map<std::string, std::string>& values);
    std::string RenderTemplate(const std::string& template_id,
                               const std::map<std::string, std::string>& values);
    
    // Default templates
    static Template CreateBasicTemplate();
    static Template CreateMADRTemplate();  // Markdown ADR
    static Template CreateYStatementTemplate();
    
private:
    std::map<std::string, Template> templates_;
    mutable std::mutex templates_mutex_;
};

// ============================================================================
// ADR Workflow Engine
// ============================================================================

class ADRWorkflowEngine {
public:
    struct WorkflowStep {
        std::string id;
        std::string name;
        std::string description;
        std::vector<std::string> required_roles;
        std::vector<std::string> required_actions;
        bool can_skip = false;
        std::chrono::days timeout{7};
    };
    
    struct Workflow {
        std::string id;
        std::string name;
        std::vector<WorkflowStep> steps;
        std::map<std::string, std::vector<std::string>> transitions;
    };
    
    struct WorkflowInstance {
        std::string id;
        std::string workflow_id;
        std::string adr_id;
        std::string current_step;
        std::map<std::string, std::string> step_assignees;
        std::map<std::string, std::chrono::steady_clock::time_point> step_start_times;
        std::map<std::string, std::chrono::steady_clock::time_point> step_complete_times;
        std::string status;
    };
    
    // Workflow management
    bool RegisterWorkflow(const Workflow& workflow);
    bool UpdateWorkflow(const std::string& id, const Workflow& workflow);
    Workflow GetWorkflow(const std::string& id) const;
    
    // Instance management
    std::string StartWorkflow(const std::string& workflow_id, const std::string& adr_id);
    bool AdvanceStep(const std::string& instance_id, const std::string& user_id);
    bool CompleteStep(const std::string& instance_id, const std::string& step_id,
                      const std::string& user_id);
    bool RejectStep(const std::string& instance_id, const std::string& step_id,
                    const std::string& reason);
    
    // Status
    WorkflowInstance GetInstance(const std::string& instance_id) const;
    std::string GetCurrentStep(const std::string& instance_id) const;
    std::vector<std::string> GetPendingActions(const std::string& instance_id) const;
    bool IsStepOverdue(const std::string& instance_id, const std::string& step_id) const;
    
    // Notifications
    void SendStepNotification(const std::string& instance_id, const std::string& step_id);
    void SendEscalationNotification(const std::string& instance_id);
    
private:
    std::map<std::string, Workflow> workflows_;
    std::map<std::string, WorkflowInstance> instances_;
    mutable std::mutex workflows_mutex_;
    mutable std::mutex instances_mutex_;
    
    std::thread notification_thread_;
    
    void NotificationLoop();
    std::vector<std::string> GetStepAssignees(const std::string& instance_id,
                                               const std::string& step_id);
};

// ============================================================================
// ADR Visualization
// ============================================================================

class ADRVisualization {
public:
    struct GraphNode {
        std::string id;
        std::string label;
        std::string color;
        std::string shape;
        std::map<std::string, std::string> metadata;
    };
    
    struct GraphEdge {
        std::string from;
        std::string to;
        std::string label;
        std::string style;
        std::map<std::string, std::string> metadata;
    };
    
    struct DecisionGraph {
        std::vector<GraphNode> nodes;
        std::vector<GraphEdge> edges;
    };
    
    // Graph generation
    DecisionGraph GenerateDecisionGraph(const std::vector<ADRDecision>& adrs);
    DecisionGraph GenerateImpactGraph(const std::vector<ADRDecision>& adrs);
    DecisionGraph GenerateTimelineGraph(const std::vector<ADRDecision>& adrs);
    DecisionGraph GenerateStakeholderGraph(const std::vector<ADRDecision>& adrs);
    
    // Export formats
    std::string ExportToDOT(const DecisionGraph& graph);
    std::string ExportToMermaid(const DecisionGraph& graph);
    std::string ExportToCytoscapeJSON(const DecisionGraph& graph);
    std::string ExportToD3JSON(const DecisionGraph& graph);
    
    // Rendering
    bool RenderToPNG(const DecisionGraph& graph, const std::string& output_path);
    bool RenderToSVG(const DecisionGraph& graph, const std::string& output_path);
    bool RenderToPDF(const DecisionGraph& graph, const std::string& output_path);
    
    // Interactive visualization
    std::string GenerateInteractiveHTML(const DecisionGraph& graph);
    std::string GenerateEmbeddedWidget(const DecisionGraph& graph);
    
private:
    std::string GetStatusColor(ADRStatus status);
    std::string GetImpactSize(ADRImpact impact);
};

// ============================================================================
// ADR Analytics
// ============================================================================

struct ADRTrends {
    std::map<std::chrono::month, int> decisions_by_month;
    std::map<std::string, int> decisions_by_category;
    std::map<std::string, double> avg_time_to_decision;
    std::vector<std::string> most_active_stakeholders;
    std::vector<std::string> most_debated_decisions;
};

class ADRAnalytics {
public:
    // Metrics collection
    void RecordDecisionProposed(const std::string& adr_id);
    void RecordDecisionAccepted(const std::string& adr_id);
    void RecordDecisionRejected(const std::string& adr_id);
    void RecordStakeholderActivity(const std::string& adr_id, const std::string& stakeholder);
    void RecordCommentAdded(const std::string& adr_id);
    
    // Analysis
    ADRTrends GetTrends(std::chrono::months period = std::chrono::months(12)) const;
    double CalculateDecisionVelocity() const;
    std::map<std::string, double> GetStakeholderParticipation() const;
    std::vector<std::string> GetBottlenecks() const;
    
    // Insights
    std::vector<std::string> IdentifyRecurringPatterns() const;
    std::vector<std::string> SuggestProcessImprovements() const;
    std::map<std::string, int> GetDecisionQualityMetrics() const;
    
    // Reporting
    void GenerateTrendReport(const std::string& output_path);
    void GenerateStakeholderReport(const std::string& output_path);
    void GenerateProcessReport(const std::string& output_path);
    
private:
    std::map<std::string, std::chrono::steady_clock::time_point> proposal_times_;
    std::map<std::string, std::chrono::steady_clock::time_point> decision_times_;
    std::map<std::string, std::map<std::string, int>> stakeholder_activity_;
    mutable std::mutex analytics_mutex_;
};

// ============================================================================
// ADR Integration
// ============================================================================

class ADRIntegration {
public:
    // Git integration
    bool LinkToCommit(const std::string& adr_id, const std::string& commit_hash);
    bool LinkToBranch(const std::string& adr_id, const std::string& branch_name);
    bool LinkToPullRequest(const std::string& adr_id, const std::string& pr_number);
    std::vector<std::string> GetRelatedCommits(const std::string& adr_id) const;
    
    // Issue tracker integration
    bool LinkToIssue(const std::string& adr_id, const std::string& issue_id);
    bool CreateIssueFromADR(const std::string& adr_id, const std::string& tracker);
    std::vector<std::string> GetRelatedIssues(const std::string& adr_id) const;
    
    // Documentation integration
    bool LinkToDocumentation(const std::string& adr_id, const std::string& doc_id);
    bool UpdateDocumentationFromADR(const std::string& adr_id);
    
    // Notification integration
    void NotifyStakeholders(const std::string& adr_id, const std::string& event);
    void SendToSlack(const std::string& adr_id, const std::string& webhook_url);
    void SendToTeams(const std::string& adr_id, const std::string& webhook_url);
    void SendToEmail(const std::string& adr_id, const std::vector<std::string>& recipients);
    
private:
    std::map<std::string, std::vector<std::string>> commit_links_;
    std::map<std::string, std::vector<std::string>> issue_links_;
    mutable std::mutex links_mutex_;
};

// ============================================================================
// ADR Runtime
// ============================================================================

class ADRRuntime {
public:
    struct Config {
        ADRManager::Config manager;
        ADRTemplateSystem::Config templates;
        ADRWorkflowEngine::Config workflow;
    };
    
    explicit ADRRuntime(const Config& config);
    ~ADRRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ADRManager* GetManager();
    ADRTemplateSystem* GetTemplateSystem();
    ADRWorkflowEngine* GetWorkflowEngine();
    ADRVisualization* GetVisualization();
    ADRAnalytics* GetAnalytics();
    ADRIntegration* GetIntegration();
    
    // Complete workflow
    std::string CreateDecision(const std::string& template_id,
                               const std::map<std::string, std::string>& values);
    bool StartApprovalWorkflow(const std::string& adr_id, const std::string& workflow_id);
    bool FinalizeDecision(const std::string& adr_id);
    
    // Reporting
    void GenerateDecisionReport(const std::string& adr_id, const std::string& output_path);
    void GenerateArchitectureReport(const std::string& output_path);
    void GenerateVisualization(const std::string& output_path, const std::string& format);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ADRManager> manager_;
    std::unique_ptr<ADRTemplateSystem> templates_;
    std::unique_ptr<ADRWorkflowEngine> workflow_;
    std::unique_ptr<ADRVisualization> visualization_;
    std::unique_ptr<ADRAnalytics> analytics_;
    std::unique_ptr<ADRIntegration> integration_;
};

} // namespace Documentation
} // namespace Sovereign
