// Phase D.19 Batch 3/5: Security Automation
// Automated security response and orchestration
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Security {

// Forward declarations
struct SecurityPlaybook;
struct AutomationRule;
struct SecurityAction;

// ============================================================================
// Security Automation Types
// ============================================================================

enum class AutomationTrigger {
    ALERT = 0,
    THREAT_DETECTED = 1,
    ANOMALY = 2,
    SCHEDULED = 3,
    MANUAL = 4,
    API = 5
};

enum class ActionType {
    BLOCK_IP = 0,
    ISOLATE_HOST = 1,
    TERMINATE_SESSION = 2,
    REVOKE_TOKEN = 3,
    QUARANTINE_FILE = 4,
    DISABLE_ACCOUNT = 5,
    NOTIFY = 6,
    RUN_SCRIPT = 7,
    CREATE_TICKET = 8,
    CUSTOM = 9
};

enum class ExecutionStatus {
    PENDING = 0,
    RUNNING = 1,
    COMPLETED = 2,
    FAILED = 3,
    CANCELLED = 4,
    WAITING_APPROVAL = 5
};

struct SecurityPlaybook {
    std::string playbook_id;
    std::string name;
    std::string description;
    AutomationTrigger trigger;
    std::vector<std::string> conditions;
    std::vector<SecurityAction> actions;
    bool requires_approval;
    std::vector<std::string> approvers;
    int timeout_seconds;
    bool enabled;
    std::chrono::steady_clock::time_point created_at;
};

struct AutomationRule {
    std::string rule_id;
    std::string name;
    std::string description;
    AutomationTrigger trigger;
    std::map<std::string, std::any> conditions;
    std::vector<std::string> playbook_ids;
    int priority;
    bool enabled;
    std::chrono::steady_clock::time_point created_at;
};

struct SecurityAction {
    std::string action_id;
    ActionType type;
    std::map<std::string, std::any> parameters;
    int timeout_seconds;
    bool continue_on_failure;
    std::vector<std::string> dependencies;
};

struct ExecutionResult {
    std::string execution_id;
    std::string playbook_id;
    ExecutionStatus status;
    std::vector<std::pair<std::string, bool>> action_results;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    std::string error_message;
    std::map<std::string, std::any> output;
};

// ============================================================================
// Playbook Engine
// ============================================================================

class PlaybookEngine {
public:
    struct Config {
        int max_concurrent_executions = 50;
        std::chrono::seconds action_timeout{300};
        bool enable_audit_logging = true;
    };
    
    explicit PlaybookEngine(const Config& config);
    ~PlaybookEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Playbook management
    std::string CreatePlaybook(const SecurityPlaybook& playbook);
    bool UpdatePlaybook(const std::string& playbook_id, const SecurityPlaybook& playbook);
    bool DeletePlaybook(const std::string& playbook_id);
    SecurityPlaybook GetPlaybook(const std::string& playbook_id) const;
    std::vector<SecurityPlaybook> GetPlaybooks() const;
    bool EnablePlaybook(const std::string& playbook_id);
    bool DisablePlaybook(const std::string& playbook_id);
    
    // Execution
    std::string ExecutePlaybook(const std::string& playbook_id, 
                                const std::map<std::string, std::any>& context);
    bool CancelExecution(const std::string& execution_id);
    ExecutionResult GetExecutionResult(const std::string& execution_id) const;
    ExecutionStatus GetExecutionStatus(const std::string& execution_id) const;
    
    // Approval
    bool RequestApproval(const std::string& execution_id);
    bool ApproveExecution(const std::string& execution_id, const std::string& approver);
    bool RejectExecution(const std::string& execution_id, const std::string& reason);
    
private:
    Config config_;
    std::map<std::string, SecurityPlaybook> playbooks_;
    std::map<std::string, ExecutionResult> executions_;
    mutable std::mutex playbooks_mutex_;
    std::thread_pool workers_;
    
    bool ExecuteAction(const SecurityAction& action, 
                       const std::map<std::string, std::any>& context,
                       std::map<std::string, std::any>& output);
};

// ============================================================================
// Automation Rules Engine
// ============================================================================

class AutomationRulesEngine {
public:
    struct Config {
        int max_rules = 1000;
        bool enable_rule_chaining = true;
        std::chrono::seconds evaluation_interval{10};
    };
    
    struct RuleEvaluation {
        std::string rule_id;
        bool matched;
        std::map<std::string, std::any> matched_conditions;
        std::chrono::steady_clock::time_point evaluated_at;
    };
    
    explicit AutomationRulesEngine(const Config& config);
    ~AutomationRulesEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Rule management
    std::string CreateRule(const AutomationRule& rule);
    bool UpdateRule(const std::string& rule_id, const AutomationRule& rule);
    bool DeleteRule(const std::string& rule_id);
    AutomationRule GetRule(const std::string& rule_id) const;
    std::vector<AutomationRule> GetRules() const;
    std::vector<AutomationRule> GetRulesByTrigger(AutomationTrigger trigger) const;
    
    // Evaluation
    std::vector<RuleEvaluation> EvaluateRules(const std::map<std::string, std::any>& event);
    bool EvaluateCondition(const std::string& condition, const std::map<std::string, std::any>& context);
    
    // Activation
    bool EnableRule(const std::string& rule_id);
    bool DisableRule(const std::string& rule_id);
    
private:
    Config config_;
    std::map<std::string, AutomationRule> rules_;
    mutable std::mutex rules_mutex_;
    std::thread evaluation_thread_;
    std::atomic<bool> running_{false};
    
    void EvaluationLoop();
    bool CheckConditions(const std::vector<std::string>& conditions, 
                         const std::map<std::string, std::any>& context);
};

// ============================================================================
// Action Executor
// ============================================================================

class ActionExecutor {
public:
    struct Config {
        int max_retries = 3;
        std::chrono::seconds retry_delay{5};
        bool dry_run = false;
    };
    
    struct ActionResult {
        bool success;
        std::string action_id;
        std::map<std::string, std::any> output;
        std::string error_message;
        int retry_count;
        std::chrono::milliseconds execution_time;
    };
    
    explicit ActionExecutor(const Config& config);
    ~ActionExecutor();
    
    bool Initialize();
    void Shutdown();
    
    // Action execution
    ActionResult Execute(const SecurityAction& action, 
                        const std::map<std::string, std::any>& context);
    
    // Built-in actions
    ActionResult BlockIP(const std::string& ip_address, std::chrono::hours duration);
    ActionResult IsolateHost(const std::string& host_id);
    ActionResult TerminateSession(const std::string& session_id);
    ActionResult RevokeToken(const std::string& token_id);
    ActionResult QuarantineFile(const std::string& file_path);
    ActionResult DisableAccount(const std::string& account_id);
    ActionResult SendNotification(const std::string& recipient, const std::string& message);
    ActionResult RunScript(const std::string& script_path, const std::vector<std::string>& args);
    ActionResult CreateTicket(const std::string& title, const std::string& description);
    
    // Custom actions
    bool RegisterCustomAction(const std::string& name, 
                              std::function<ActionResult(const std::map<std::string, std::any>&)> handler);
    bool UnregisterCustomAction(const std::string& name);
    
private:
    Config config_;
    std::map<std::string, std::function<ActionResult(const std::map<std::string, std::any>&)>> 
        custom_actions_;
    mutable std::mutex actions_mutex_;
    
    ActionResult ExecuteWithRetry(const SecurityAction& action, 
                                  const std::map<std::string, std::any>& context);
};

// ============================================================================
// Incident Responder
// ============================================================================

class IncidentResponder {
public:
    struct Config {
        bool auto_create_incidents = true;
        bool auto_assign = true;
        std::chrono::minutes escalation_time{30};
    };
    
    struct SecurityIncident {
        std::string incident_id;
        std::string title;
        std::string description;
        std::string severity;
        std::string status;
        std::string assignee;
        std::vector<std::string> related_alerts;
        std::vector<std::string> indicators;
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point updated_at;
        std::chrono::steady_clock::time_point resolved_at;
        std::map<std::string, std::any> metadata;
    };
    
    explicit IncidentResponder(const Config& config);
    ~IncidentResponder();
    
    bool Initialize();
    void Shutdown();
    
    // Incident management
    std::string CreateIncident(const SecurityIncident& incident);
    bool UpdateIncident(const std::string& incident_id, const SecurityIncident& incident);
    bool CloseIncident(const std::string& incident_id, const std::string& resolution);
    SecurityIncident GetIncident(const std::string& incident_id) const;
    std::vector<SecurityIncident> GetOpenIncidents() const;
    std::vector<SecurityIncident> GetIncidentsBySeverity(const std::string& severity) const;
    
    // Response
    bool AssignIncident(const std::string& incident_id, const std::string& assignee);
    bool EscalateIncident(const std::string& incident_id, const std::string& reason);
    bool LinkAlertToIncident(const std::string& alert_id, const std::string& incident_id);
    
    // Automation
    bool TriggerResponsePlaybook(const std::string& incident_id, const std::string& playbook_id);
    
private:
    Config config_;
    std::map<std::string, SecurityIncident> incidents_;
    mutable std::mutex incidents_mutex_;
    std::thread escalation_thread_;
    std::atomic<bool> running_{false};
    
    void EscalationLoop();
    std::string AutoAssignIncident(const SecurityIncident& incident);
};

// ============================================================================
// Security Automation Runtime
// ============================================================================

class SecurityAutomationRuntime {
public:
    struct Config {
        PlaybookEngine::Config playbook;
        AutomationRulesEngine::Config rules;
        ActionExecutor::Config executor;
        IncidentResponder::Config responder;
    };
    
    explicit SecurityAutomationRuntime(const Config& config);
    ~SecurityAutomationRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    PlaybookEngine* GetPlaybookEngine();
    AutomationRulesEngine* GetRulesEngine();
    ActionExecutor* GetActionExecutor();
    IncidentResponder* GetIncidentResponder();
    
    // High-level API
    std::string CreatePlaybook(const std::string& name, AutomationTrigger trigger,
                                const std::vector<SecurityAction>& actions);
    std::string ExecuteAutomation(const std::string& playbook_id, 
                                   const std::map<std::string, std::any>& context);
    std::string CreateIncident(const std::string& title, const std::string& severity);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<PlaybookEngine> playbook_engine_;
    std::unique_ptr<AutomationRulesEngine> rules_engine_;
    std::unique_ptr<ActionExecutor> action_executor_;
    std::unique_ptr<IncidentResponder> incident_responder_;
};

} // namespace Security
} // namespace Sovereign
