// Phase P.4/5: Maintenance Scheduler
// RawrXD Maintenance Scheduler - Planned maintenance and updates

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>

namespace RawrXD {
namespace Operations {

// Maintenance window types
enum class MaintenanceType {
    SECURITY_PATCH,     // Security updates
    VERSION_UPGRADE,    // Software version upgrade
    CONFIGURATION,      // Configuration changes
    HARDWARE,           // Hardware maintenance
    DATABASE,           // Database maintenance
    BACKUP,             // Backup operations
    CLEANUP,            // Cleanup and compaction
    CUSTOM              // Custom maintenance task
};

// Maintenance window status
enum class MaintenanceStatus {
    SCHEDULED,          // Planned but not started
    PENDING_APPROVAL,   // Waiting for approval
    APPROVED,           // Approved to proceed
    IN_PROGRESS,        // Currently executing
    COMPLETED,          // Finished successfully
    FAILED,             // Failed with error
    CANCELLED,          // Cancelled before completion
    DEFERRED            // Postponed to later
};

// Maintenance impact level
enum class ImpactLevel {
    NONE,               // No user impact
    LOW,                // Minimal impact
    MEDIUM,             // Some degradation
    HIGH,               // Significant impact
    CRITICAL            // Service interruption
};

// Maintenance window definition
struct MaintenanceWindow {
    std::string id;
    std::string name;
    std::string description;
    MaintenanceType type;
    MaintenanceStatus status;
    ImpactLevel impact_level;
    
    // Timing
    std::chrono::system_clock::time_point scheduled_start;
    std::chrono::system_clock::time_point scheduled_end;
    std::chrono::minutes estimated_duration;
    std::chrono::system_clock::time_point actual_start;
    std::chrono::system_clock::time_point actual_end;
    
    // Scope
    std::vector<std::string> affected_services;
    std::vector<std::string> affected_tenants;
    std::vector<std::string> affected_regions;
    
    // Execution
    struct Task {
        std::string id;
        std::string name;
        std::string command;
        std::vector<std::string> dependencies;
        int timeout_seconds;
        bool can_rollback;
        std::string rollback_command;
    };
    std::vector<Task> tasks;
    
    // Notifications
    struct Notification {
        std::chrono::minutes before_start;
        std::vector<std::string> channels;  // email, slack, pagerduty
        std::string message_template;
    };
    std::vector<Notification> notifications;
    
    // Approval
    std::string requested_by;
    std::string approved_by;
    std::chrono::system_clock::time_point approved_at;
    std::string approval_notes;
    
    // Results
    std::string result_summary;
    std::vector<std::string> logs;
    std::string error_message;
    
    // Metadata
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
};

// Recurring maintenance schedule
struct RecurringSchedule {
    std::string id;
    std::string name;
    MaintenanceType type;
    
    // Schedule expression (cron-like)
    std::string schedule_expression;  // e.g., "0 2 * * 0" for Sundays at 2 AM
    
    // Duration
    std::chrono::minutes duration;
    std::chrono::minutes max_duration;
    
    // Scope
    std::vector<std::string> target_services;
    std::vector<std::string> target_regions;
    
    // Execution
    std::vector<MaintenanceWindow::Task> tasks;
    
    // Settings
    bool auto_approve;
    ImpactLevel default_impact_level;
    std::vector<MaintenanceWindow::Notification> notifications;
    
    // State
    bool enabled;
    std::chrono::system_clock::time_point last_run;
    std::chrono::system_clock::time_point next_run;
    uint32_t run_count;
};

// Maintenance scheduler interface
class IMaintenanceScheduler {
public:
    virtual ~IMaintenanceScheduler() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Window management
    virtual std::string CreateWindow(const MaintenanceWindow& window) = 0;
    virtual bool UpdateWindow(const MaintenanceWindow& window) = 0;
    virtual bool CancelWindow(const std::string& window_id, const std::string& reason) = 0;
    virtual bool DeleteWindow(const std::string& window_id) = 0;
    virtual std::optional<MaintenanceWindow> GetWindow(const std::string& window_id) = 0;
    virtual std::vector<MaintenanceWindow> ListWindows(
        MaintenanceStatus status = MaintenanceStatus::SCHEDULED) = 0;
    virtual std::vector<MaintenanceWindow> GetUpcomingWindows(
        std::chrono::hours horizon = std::chrono::hours(168)) = 0;
    
    // Approval workflow
    virtual bool RequestApproval(const std::string& window_id) = 0;
    virtual bool ApproveWindow(const std::string& window_id, 
                                const std::string& approver,
                                const std::string& notes) = 0;
    virtual bool RejectWindow(const std::string& window_id,
                               const std::string& approver,
                               const std::string& reason) = 0;
    
    // Execution
    virtual bool StartWindow(const std::string& window_id) = 0;
    virtual bool CompleteWindow(const std::string& window_id, 
                                 const std::string& summary) = 0;
    virtual bool FailWindow(const std::string& window_id,
                             const std::string& error_message) = 0;
    virtual bool ExecuteTask(const std::string& window_id,
                              const std::string& task_id) = 0;
    virtual bool RollbackTask(const std::string& window_id,
                               const std::string& task_id) = 0;
    
    // Recurring schedules
    virtual std::string CreateRecurringSchedule(const RecurringSchedule& schedule) = 0;
    virtual bool UpdateRecurringSchedule(const RecurringSchedule& schedule) = 0;
    virtual bool DeleteRecurringSchedule(const std::string& schedule_id) = 0;
    virtual bool EnableRecurringSchedule(const std::string& schedule_id) = 0;
    virtual bool DisableRecurringSchedule(const std::string& schedule_id) = 0;
    virtual std::optional<RecurringSchedule> GetRecurringSchedule(const std::string& schedule_id) = 0;
    virtual std::vector<RecurringSchedule> ListRecurringSchedules() = 0;
    virtual bool TriggerRecurringSchedule(const std::string& schedule_id) = 0;
    
    // Conflict detection
    virtual std::vector<MaintenanceWindow> FindConflicts(
        const MaintenanceWindow& window) = 0;
    virtual bool CheckForConflicts(const MaintenanceWindow& window) = 0;
    
    // Notifications
    virtual bool SendNotification(const std::string& window_id,
                                   const MaintenanceWindow::Notification& notification) = 0;
    
    // Health check during maintenance
    virtual bool IsSystemHealthy() = 0;
    virtual bool CanProceedWithMaintenance(const std::string& window_id) = 0;
    
    // History
    virtual std::vector<MaintenanceWindow> GetMaintenanceHistory(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) = 0;
    
    // Statistics
    virtual struct MaintenanceStatistics {
        uint32_t total_windows;
        uint32_t completed_windows;
        uint32_t failed_windows;
        uint32_t cancelled_windows;
        double average_duration_minutes;
        double success_rate;
    } GetStatistics(std::chrono::system_clock::time_point start,
                    std::chrono::system_clock::time_point end) = 0;
};

// Local maintenance scheduler
class LocalMaintenanceScheduler : public IMaintenanceScheduler {
public:
    LocalMaintenanceScheduler();
    ~LocalMaintenanceScheduler() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreateWindow(const MaintenanceWindow& window) override;
    bool UpdateWindow(const MaintenanceWindow& window) override;
    bool CancelWindow(const std::string& window_id, const std::string& reason) override;
    bool DeleteWindow(const std::string& window_id) override;
    std::optional<MaintenanceWindow> GetWindow(const std::string& window_id) override;
    std::vector<MaintenanceWindow> ListWindows(MaintenanceStatus status = MaintenanceStatus::SCHEDULED) override;
    std::vector<MaintenanceWindow> GetUpcomingWindows(std::chrono::hours horizon = std::chrono::hours(168)) override;
    
    bool RequestApproval(const std::string& window_id) override;
    bool ApproveWindow(const std::string& window_id, 
                       const std::string& approver,
                       const std::string& notes) override;
    bool RejectWindow(const std::string& window_id,
                       const std::string& approver,
                       const std::string& reason) override;
    
    bool StartWindow(const std::string& window_id) override;
    bool CompleteWindow(const std::string& window_id, 
                         const std::string& summary) override;
    bool FailWindow(const std::string& window_id,
                     const std::string& error_message) override;
    bool ExecuteTask(const std::string& window_id,
                      const std::string& task_id) override;
    bool RollbackTask(const std::string& window_id,
                       const std::string& task_id) override;
    
    std::string CreateRecurringSchedule(const RecurringSchedule& schedule) override;
    bool UpdateRecurringSchedule(const RecurringSchedule& schedule) override;
    bool DeleteRecurringSchedule(const std::string& schedule_id) override;
    bool EnableRecurringSchedule(const std::string& schedule_id) override;
    bool DisableRecurringSchedule(const std::string& schedule_id) override;
    std::optional<RecurringSchedule> GetRecurringSchedule(const std::string& schedule_id) override;
    std::vector<RecurringSchedule> ListRecurringSchedules() override;
    bool TriggerRecurringSchedule(const std::string& schedule_id) override;
    
    std::vector<MaintenanceWindow> FindConflicts(const MaintenanceWindow& window) override;
    bool CheckForConflicts(const MaintenanceWindow& window) override;
    
    bool SendNotification(const std::string& window_id,
                          const MaintenanceWindow::Notification& notification) override;
    
    bool IsSystemHealthy() override;
    bool CanProceedWithMaintenance(const std::string& window_id) override;
    
    std::vector<MaintenanceWindow> GetMaintenanceHistory(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) override;
    
    MaintenanceStatistics GetStatistics(std::chrono::system_clock::time_point start,
                                         std::chrono::system_clock::time_point end) override;
    
private:
    std::unordered_map<std::string, MaintenanceWindow> windows_;
    std::unordered_map<std::string, RecurringSchedule> schedules_;
    bool initialized_ = false;
    
    std::string GenerateWindowId();
    bool ValidateWindow(const MaintenanceWindow& window);
    bool HasTimeConflict(const MaintenanceWindow& window1, const MaintenanceWindow& window2);
    void ProcessRecurringSchedules();
};

// Maintenance task executor
class MaintenanceExecutor {
public:
    using TaskCallback = std::function<bool(const std::string& command, std::string& output)>;
    
    explicit MaintenanceExecutor(TaskCallback callback);
    
    struct ExecutionResult {
        bool success;
        std::string output;
        std::string error;
        std::chrono::milliseconds duration;
        int exit_code;
    };
    
    ExecutionResult ExecuteTask(const MaintenanceWindow::Task& task);
    ExecutionResult ExecuteRollback(const MaintenanceWindow::Task& task);
    
    // Dry run
    ExecutionResult DryRunTask(const MaintenanceWindow::Task& task);
    
private:
    TaskCallback callback_;
};

// Pre-maintenance checks
class PreMaintenanceChecks {
public:
    struct CheckResult {
        std::string check_name;
        bool passed;
        std::string message;
        std::string remediation;
    };
    
    // System health checks
    std::vector<CheckResult> RunHealthChecks();
    
    // Capacity checks
    std::vector<CheckResult> RunCapacityChecks();
    
    // Backup verification
    std::vector<CheckResult> RunBackupChecks();
    
    // Dependency checks
    std::vector<CheckResult> RunDependencyChecks(const std::vector<std::string>& services);
    
    // All checks
    std::vector<CheckResult> RunAllChecks(const MaintenanceWindow& window);
    
    bool AllChecksPassed(const std::vector<CheckResult>& results);
};

// Global maintenance scheduler
extern std::unique_ptr<IMaintenanceScheduler> g_maintenance_scheduler;

// Initialize maintenance scheduling
bool InitializeMaintenanceScheduling(const std::string& config_path);
void ShutdownMaintenanceScheduling();
bool IsMaintenanceSchedulingEnabled();

} // namespace Operations
} // namespace RawrXD
