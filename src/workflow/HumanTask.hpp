/**
 * HumanTask.hpp
 *
 * Phase O Batch 3/5: Human Tasks & Forms
 *
 * Human task management with user assignments, forms, and
 * approval workflows.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace Workflow {

// ============================================================================
// Forward Declarations
// ============================================================================

class User;
class Group;
class Task;
class TaskList;
class Form;
class HumanTaskManager;

// ============================================================================
// User
// ============================================================================

/**
 * User in the workflow system.
 */
class User {
public:
    struct Config {
        std::string id;
        std::string username;
        std::string email;
        std::string firstName;
        std::string lastName;
        std::vector<std::string> roles;
        std::map<std::string, std::string> attributes;
        bool active;
    };
    
    explicit User(const Config& config);
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const std::string& GetUsername() const { return config_.username; }
    const std::string& GetEmail() const { return config_.email; }
    std::string GetDisplayName() const;
    
    // Roles
    bool HasRole(const std::string& role) const;
    void AddRole(const std::string& role);
    void RemoveRole(const std::string& role);
    const std::vector<std::string>& GetRoles() const { return config_.roles; }
    
    // Attributes
    void SetAttribute(const std::string& key, const std::string& value);
    std::optional<std::string> GetAttribute(const std::string& key) const;
    
    // Status
    bool IsActive() const { return config_.active; }
    void Activate();
    void Deactivate();
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Group
// ============================================================================

/**
 * User group for task assignment.
 */
class Group {
public:
    struct Config {
        std::string id;
        std::string name;
        std::string description;
        std::vector<std::string> memberIds;
        std::map<std::string, std::string> attributes;
    };
    
    explicit Group(const Config& config);
    
    // Members
    void AddMember(const std::string& userId);
    void RemoveMember(const std::string& userId);
    bool HasMember(const std::string& userId) const;
    std::vector<std::string> GetMembers() const;
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const std::string& GetName() const { return config_.name; }
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Task Priority
// ============================================================================

enum class TaskPriority {
    LOWEST = 0,
    LOW = 1,
    NORMAL = 2,
    HIGH = 3,
    HIGHEST = 4
};

// ============================================================================
// Task Status
// ============================================================================

enum class TaskStatus {
    CREATED,
    ASSIGNED,
    RESERVED,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    EXPIRED,
    DELEGATED,
    SUSPENDED,
    TERMINATED
};

// ============================================================================
// Task
// ============================================================================

/**
 * Human task in workflow.
 */
class Task {
public:
    enum class AssignmentType {
        DIRECT,
        GROUP,
        ROLE,
        EXPRESSION,
        ROUND_ROBIN,
        LOAD_BALANCED
    };
    
    struct Config {
        std::string id;
        std::string name;
        std::string description;
        std::string workflowInstanceId;
        std::string activityId;
        
        // Assignment
        AssignmentType assignmentType;
        std::optional<std::string> assigneeId;
        std::vector<std::string> candidateUsers;
        std::vector<std::string> candidateGroups;
        std::vector<std::string> candidateRoles;
        std::optional<std::string> assignmentExpression;
        
        // Priority and scheduling
        TaskPriority priority;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> dueDate;
        std::optional<std::chrono::seconds> reminderInterval;
        std::optional<std::chrono::seconds> escalationInterval;
        
        // Form
        std::optional<std::string> formId;
        std::map<std::string, std::any> formData;
        
        // Status
        TaskStatus status;
        std::optional<std::string> ownerId;
        std::optional<std::string> delegatedToId;
        
        // Completion
        std::optional<std::string> outcome;
        std::optional<std::map<std::string, std::any>> outputData;
        std::optional<std::chrono::system_clock::time_point> completedAt;
        std::optional<std::string> completionComment;
        
        // Metadata
        std::map<std::string, std::string> metadata;
    };
    
    explicit Task(const Config& config);
    
    // Lifecycle
    void Claim(const std::string& userId);
    void Start();
    void Complete(const std::string& outcome,
                    const std::optional<std::map<std::string, std::any>>& outputData = std::nullopt);
    void Fail(const std::string& reason);
    void Delegate(const std::string& userId);
    void Suspend();
    void Resume();
    void Terminate();
    
    // Assignment
    void Assign(const std::string& userId);
    void Unassign();
    void SetCandidateUsers(const std::vector<std::string>& userIds);
    void SetCandidateGroups(const std::vector<std::string>& groupIds);
    bool IsAvailableFor(const std::string& userId) const;
    bool IsAssignedTo(const std::string& userId) const;
    
    // Form
    void AttachForm(const std::string& formId);
    void SetFormData(const std::map<std::string, std::any>& data);
    std::optional<std::string> GetFormId() const { return config_.formId; }
    std::map<std::string, std::any> GetFormData() const { return config_.formData; }
    
    // Notifications
    void SendReminder();
    void Escalate();
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const std::string& GetName() const { return config_.name; }
    TaskStatus GetStatus() const { return config_.status; }
    TaskPriority GetPriority() const { return config_.priority; }
    std::optional<std::string> GetAssignee() const { return config_.assigneeId; }
    std::optional<std::chrono::system_clock::time_point> GetDueDate() const { return config_.dueDate; }
    bool IsOverdue() const;
    
    // Comments
    void AddComment(const std::string& userId, const std::string& comment);
    std::vector<std::pair<std::string, std::string>> GetComments() const;
    
    // Attachments
    void AddAttachment(const std::string& name, const std::string& url);
    std::vector<std::pair<std::string, std::string>> GetAttachments() const;
    
private:
    Config config_;
    std::vector<std::pair<std::string, std::string>> comments_;
    std::vector<std::pair<std::string, std::string>> attachments_;
    mutable std::mutex mutex_;
    
    void UpdateStatus(TaskStatus newStatus);
};

// ============================================================================
// Form Field
// ============================================================================

/**
 * Form field definition.
 */
struct FormField {
    enum class Type {
        TEXT,
        TEXTAREA,
        NUMBER,
        DATE,
        DATETIME,
        BOOLEAN,
        SELECT,
        MULTI_SELECT,
        RADIO,
        CHECKBOX,
        FILE,
        EMAIL,
        PHONE,
        URL,
        PASSWORD,
        CURRENCY,
        PERCENTAGE,
        CUSTOM
    };
    
    std::string id;
    std::string label;
    Type type;
    bool required;
    std::optional<std::string> defaultValue;
    std::optional<std::string> placeholder;
    std::optional<std::string> helpText;
    std::vector<std::pair<std::string, std::string>> options;  // For select/radio/checkbox
    std::optional<std::string> validationRegex;
    std::optional<std::string> validationMessage;
    std::map<std::string, std::string> attributes;
    std::optional<std::string> visibilityCondition;
    std::optional<std::string> enableCondition;
};

// ============================================================================
// Form
// ============================================================================

/**
 * Form definition for human tasks.
 */
class Form {
public:
    struct Config {
        std::string id;
        std::string name;
        std::string description;
        std::vector<FormField> fields;
        std::map<std::string, std::string> layout;
        std::map<std::string, std::string> styling;
        std::vector<std::string> outcomes;
        std::optional<std::string> submitButtonLabel;
        std::optional<std::string> cancelButtonLabel;
    };
    
    explicit Form(const Config& config);
    
    // Fields
    void AddField(const FormField& field);
    void RemoveField(const std::string& fieldId);
    void UpdateField(const std::string& fieldId, const FormField& field);
    std::optional<FormField> GetField(const std::string& fieldId) const;
    std::vector<FormField> GetFields() const;
    
    // Validation
    bool Validate(const std::map<std::string, std::any>& data) const;
    std::vector<std::string> GetValidationErrors(const std::map<std::string, std::any>& data) const;
    
    // Rendering
    std::string RenderHtml() const;
    std::string RenderJson() const;
    std::string RenderReactComponent() const;
    std::string RenderVueComponent() const;
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const std::string& GetName() const { return config_.name; }
    const std::vector<std::string>& GetOutcomes() const { return config_.outcomes; }
    
private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Task List
// ============================================================================

/**
 * Task list for users.
 */
class TaskList {
public:
    struct Filter {
        std::optional<std::vector<TaskStatus>> statuses;
        std::optional<std::vector<TaskPriority>> priorities;
        std::optional<std::chrono::system_clock::time_point> dueBefore;
        std::optional<std::chrono::system_clock::time_point> dueAfter;
        std::optional<std::string> workflowId;
        std::optional<std::string> searchText;
        std::map<std::string, std::string> metadataFilter;
    };
    
    struct SortOptions {
        enum class Field {
            CREATED_DATE,
            DUE_DATE,
            PRIORITY,
            NAME
        };
        
        Field field;
        bool ascending;
    };
    
    explicit TaskList(const std::string& userId);
    
    // Task access
    std::vector<std::shared_ptr<Task>> GetTasks() const;
    std::vector<std::shared_ptr<Task>> GetTasks(const Filter& filter) const;
    std::vector<std::shared_ptr<Task>> GetTasks(const Filter& filter,
                                                 const SortOptions& sort) const;
    
    // Task counts
    size_t GetTaskCount() const;
    size_t GetTaskCount(const Filter& filter) const;
    size_t GetOverdueCount() const;
    size_t GetDueTodayCount() const;
    size_t GetHighPriorityCount() const;
    
    // Pagination
    std::vector<std::shared_ptr<Task>> GetPage(size_t page, size_t pageSize) const;
    std::vector<std::shared_ptr<Task>> GetPage(size_t page,
                                                size_t pageSize,
                                                const Filter& filter,
                                                const SortOptions& sort) const;
    
    // Refresh
    void Refresh();
    void SetAutoRefresh(std::chrono::seconds interval);
    void StopAutoRefresh();
    
private:
    std::string userId_;
    std::vector<std::shared_ptr<Task>> tasks_;
    mutable std::mutex mutex_;
    
    std::thread refreshThread_;
    std::atomic<bool> stopRefresh_;
    
    void RefreshLoop(std::chrono::seconds interval);
    bool MatchesFilter(std::shared_ptr<Task> task, const Filter& filter) const;
    void SortTasks(std::vector<std::shared_ptr<Task>>& tasks, const SortOptions& sort) const;
};

// ============================================================================
// Human Task Manager
// ============================================================================

/**
 * Central human task manager.
 */
class HumanTaskManager {
public:
    struct Config {
        std::chrono::seconds reminderCheckInterval;
        std::chrono::seconds escalationCheckInterval;
        bool enableEmailNotifications;
        bool enablePushNotifications;
        std::string notificationTemplatePath;
    };
    
    explicit HumanTaskManager(const Config& config);
    ~HumanTaskManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // User management
    void RegisterUser(std::shared_ptr<User> user);
    void UnregisterUser(const std::string& userId);
    std::shared_ptr<User> GetUser(const std::string& userId) const;
    std::shared_ptr<User> GetUserByUsername(const std::string& username) const;
    std::vector<std::shared_ptr<User>> GetUsers() const;
    
    // Group management
    void CreateGroup(const Group::Config& config);
    void DeleteGroup(const std::string& groupId);
    std::shared_ptr<Group> GetGroup(const std::string& groupId) const;
    std::vector<std::shared_ptr<Group>> GetGroups() const;
    
    // Task management
    std::shared_ptr<Task> CreateTask(const Task::Config& config);
    void CancelTask(const std::string& taskId);
    std::shared_ptr<Task> GetTask(const std::string& taskId) const;
    std::vector<std::shared_ptr<Task>> GetTasksForUser(const std::string& userId) const;
    std::vector<std::shared_ptr<Task>> GetTasksForGroup(const std::string& groupId) const;
    
    // Form management
    void RegisterForm(std::shared_ptr<Form> form);
    void UnregisterForm(const std::string& formId);
    std::shared_ptr<Form> GetForm(const std::string& formId) const;
    
    // Task lists
    std::unique_ptr<TaskList> GetTaskList(const std::string& userId);
    
    // Assignment strategies
    void SetAssignmentStrategy(Task::AssignmentType type,
                                std::function<std::string(const std::vector<std::string>&)> strategy);
    std::string AssignTask(std::shared_ptr<Task> task);
    
    // Notifications
    void SendNotification(const std::string& userId,
                          const std::string& subject,
                          const std::string& message);
    void SendTaskAssignedNotification(std::shared_ptr<Task> task);
    void SendTaskDueNotification(std::shared_ptr<Task> task);
    void SendTaskEscalatedNotification(std::shared_ptr<Task> task);
    
    // Statistics
    struct TaskStats {
        uint64_t totalTasksCreated;
        uint64_t totalTasksCompleted;
        uint64_t totalTasksOverdue;
        double averageCompletionTimeHours;
        std::map<TaskStatus, uint64_t> tasksByStatus;
        std::map<std::string, uint64_t> tasksByUser;
    };
    TaskStats GetStats() const;
    void ResetStats();
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<User>> users_;
    std::map<std::string, std::shared_ptr<Group>> groups_;
    std::map<std::string, std::shared_ptr<Task>> tasks_;
    std::map<std::string, std::shared_ptr<Form>> forms_;
    mutable std::mutex mutex_;
    
    std::map<Task::AssignmentType, std::function<std::string(const std::vector<std::string>&)>>
        assignmentStrategies_;
    
    TaskStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread reminderThread_;
    std::thread escalationThread_;
    std::atomic<bool> stopThreads_;
    
    void ReminderLoop();
    void EscalationLoop();
    void CheckReminders();
    void CheckEscalations();
};

} // namespace Workflow
