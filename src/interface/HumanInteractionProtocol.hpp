/**
 * HumanInteractionProtocol.hpp
 *
 * Phase D.2 Batch 4/5: Human Interaction Protocol
 *
 * Defines the protocol for human interaction with the sovereign runtime.
 * Provides command language, intent translation, and approval gates.
 *
 * Interaction Model:
 *   - Commands: Structured text commands
 *   - Intents: High-level goals translated to actions
 *   - Approvals: Human-in-the-loop for critical operations
 *   - Notifications: Proactive updates to human operators
 */

#pragma once

#include "../core/SovereignState.hpp"
#include "../autonomy/DecisionTypes.hpp"

#include <string>
#include <vector>
#include <map>
#include <variant>
#include <memory>
#include <functional>
#include <queue>

namespace Interface {

/**
 * Command types
 */
enum class CommandType {
    UNKNOWN,
    QUERY,           // Query runtime state
    CONTROL,         // Control runtime (start, stop, pause)
    MUTATE,          // Mutate graph or state
    DECISION,        // Make or approve a decision
    CHECKPOINT,      // Create or restore checkpoint
    CONFIGURE,       // Configure runtime settings
    STATUS,          // Get status
    HELP             // Get help
};

std::string CommandTypeToString(CommandType type);
CommandType StringToCommandType(const std::string& str);

/**
 * Command structure
 */
struct Command {
    std::string raw;                    // Raw command text
    CommandType type{CommandType::UNKNOWN};
    std::string verb;                   // Primary action
    std::vector<std::string> args;     // Arguments
    std::map<std::string, std::string> options;  // Named options
    std::string source;                 // Source (cli, api, file)
    std::string userId;                 // User identifier
    int64_t timestampMs{0};
    std::string commandId;              // Unique command ID
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Command result
 */
struct CommandResult {
    bool success{false};
    std::string commandId;
    std::string message;
    std::string errorMessage;
    std::map<std::string, std::string> data;
    int64_t executionTimeMs{0};
    bool requiresApproval{false};
    std::string approvalId;
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Intent types
 */
enum class IntentType {
    UNKNOWN,
    INSPECT,         // Inspect runtime state
    MODIFY,          // Modify runtime configuration
    EXECUTE,         // Execute an action
    APPROVE,         // Approve a pending action
    REJECT,          // Reject a pending action
    QUERY,           // Query information
    EMERGENCY        // Emergency action
};

std::string IntentTypeToString(IntentType type);
IntentType StringToIntentType(const std::string& str);

/**
 * Intent structure
 */
struct Intent {
    IntentType type{IntentType::UNKNOWN};
    std::string description;
    std::map<std::string, std::string> parameters;
    double confidence{0.0};              // Translation confidence
    std::vector<Command> translatedCommands;
    std::string intentId;
    int64_t timestampMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Intent translation result
 */
struct IntentTranslation {
    bool success{false};
    Intent intent;
    std::vector<Command> commands;
    std::string errorMessage;
    double confidence{0.0};
    
    std::string ToJson() const;
};

/**
 * Approval request
 */
struct ApprovalRequest {
    std::string approvalId;
    std::string requestType;             // "decision", "mutation", "checkpoint"
    std::string description;
    std::string requesterId;
    std::map<std::string, std::string> details;
    int64_t requestedAtMs{0};
    int timeoutMs{300000};               // 5 minute default
    Autonomy::DecisionPriority priority{Autonomy::DecisionPriority::MEDIUM};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Approval response
 */
struct ApprovalResponse {
    std::string approvalId;
    bool approved{false};
    std::string approverId;
    std::string reason;
    int64_t respondedAtMs{0};
    
    std::string ToJson() const;
};

/**
 * Approval gate status
 */
enum class ApprovalStatus {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED,
    CANCELLED
};

std::string ApprovalStatusToString(ApprovalStatus status);

/**
 * Pending approval
 */
struct PendingApproval {
    ApprovalRequest request;
    ApprovalStatus status{ApprovalStatus::PENDING};
    std::optional<ApprovalResponse> response;
    int64_t expiresAtMs{0};
};

/**
 * Notification types
 */
enum class NotificationType {
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
    DECISION_REQUIRED,
    PATTERN_DETECTED,
    STATE_CHANGE
};

std::string NotificationTypeToString(NotificationType type);

/**
 * Notification
 */
struct Notification {
    std::string notificationId;
    NotificationType type{NotificationType::INFO};
    std::string title;
    std::string message;
    std::map<std::string, std::string> data;
    int64_t timestampMs{0};
    bool acknowledged{false};
    std::string acknowledgedBy;
    int64_t acknowledgedAtMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Command parser
 */
class CommandParser {
public:
    CommandParser();
    ~CommandParser();

    /**
     * Parse a command string
     */
    Command Parse(const std::string& input, const std::string& source = "cli");

    /**
     * Validate a command
     */
    bool Validate(const Command& command, std::string& error) const;

    /**
     * Get command help
     */
    std::string GetHelp(const std::string& command = "") const;

    /**
     * Get available commands
     */
    std::vector<std::string> GetAvailableCommands() const;

private:
    std::map<std::string, std::string> commandHelp_;
    
    void InitializeHelp();
    std::vector<std::string> Tokenize(const std::string& input) const;
    CommandType ParseCommandType(const std::string& verb) const;
};

/**
 * Intent translator
 */
class IntentTranslator {
public:
    IntentTranslator();
    ~IntentTranslator();

    /**
     * Translate natural language to intent
     */
    IntentTranslation Translate(const std::string& input, const std::string& userId = "");

    /**
     * Translate intent to commands
     */
    std::vector<Command> IntentToCommands(const Intent& intent);

    /**
     * Register intent pattern
     */
    void RegisterPattern(const std::string& pattern, IntentType type, double confidence);

    /**
     * Get translation confidence
     */
    double GetConfidence(const std::string& input, IntentType type) const;

private:
    struct IntentPattern {
        std::string pattern;
        IntentType type;
        double baseConfidence;
    };
    
    std::vector<IntentPattern> patterns_;
    
    IntentType MatchPattern(const std::string& input) const;
    std::vector<Command> GenerateCommands(const Intent& intent) const;
};

/**
 * Approval gate
 */
class ApprovalGate {
public:
    ApprovalGate();
    ~ApprovalGate();

    /**
     * Initialize the approval gate
     */
    bool Initialize(int defaultTimeoutMs = 300000);

    /**
     * Request approval
     */
    std::string RequestApproval(const ApprovalRequest& request);

    /**
     * Respond to approval request
     */
    bool Respond(const std::string& approvalId, const ApprovalResponse& response);

    /**
     * Get approval status
     */
    ApprovalStatus GetStatus(const std::string& approvalId) const;

    /**
     * Get pending approvals
     */
    std::vector<PendingApproval> GetPendingApprovals() const;

    /**
     * Cancel an approval request
     */
    bool Cancel(const std::string& approvalId, const std::string& reason);

    /**
     * Check if approval is required for an action
     */
    bool IsApprovalRequired(const std::string& actionType, 
                           Autonomy::DecisionPriority priority) const;

    /**
     * Set approval policy
     */
    void SetApprovalPolicy(const std::string& actionType, 
                          Autonomy::DecisionPriority minPriority,
                          bool requireApproval);

    /**
     * Cleanup expired approvals
     */
    void CleanupExpired();

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    int defaultTimeoutMs_{300000};
    std::map<std::string, PendingApproval> approvals_;
    mutable std::mutex approvalsMutex_;
    
    // Approval policies: actionType -> (minPriority, requireApproval)
    std::map<std::string, std::pair<Autonomy::DecisionPriority, bool>> policies_;
    
    int64_t GetCurrentTimeMs() const;
};

/**
 * Notification manager
 */
class NotificationManager {
public:
    NotificationManager();
    ~NotificationManager();

    /**
     * Initialize the notification manager
     */
    bool Initialize(int maxNotifications = 1000);

    /**
     * Send a notification
     */
    std::string Notify(const Notification& notification);

    /**
     * Acknowledge a notification
     */
    bool Acknowledge(const std::string& notificationId, const std::string& userId);

    /**
     * Get notifications
     */
    std::vector<Notification> GetNotifications(bool unacknowledgedOnly = false,
                                                int limit = 100) const;

    /**
     * Get notifications by type
     */
    std::vector<Notification> GetNotificationsByType(NotificationType type,
                                                     int limit = 100) const;

    /**
     * Clear old notifications
     */
    void ClearOld(int maxAgeMs);

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    int maxNotifications_{1000};
    std::map<std::string, Notification> notifications_;
    mutable std::mutex notificationsMutex_;
    
    std::string GenerateNotificationId();
    int64_t GetCurrentTimeMs() const;
};

/**
 * Human Interaction Protocol
 *
 * Main interface for human interaction with the sovereign runtime.
 */
class HumanInteractionProtocol {
public:
    HumanInteractionProtocol();
    ~HumanInteractionProtocol();

    // Disable copy
    HumanInteractionProtocol(const HumanInteractionProtocol&) = delete;
    HumanInteractionProtocol& operator=(const HumanInteractionProtocol&) = delete;

    /**
     * Initialize the protocol
     */
    bool Initialize(int approvalTimeoutMs = 300000, int maxNotifications = 1000);

    /**
     * Process a command
     */
    CommandResult ProcessCommand(const std::string& input, 
                                const std::string& source = "cli",
                                const std::string& userId = "");

    /**
     * Process an intent
     */
    CommandResult ProcessIntent(const std::string& input,
                               const std::string& userId = "");

    /**
     * Request approval for an action
     */
    std::string RequestApproval(const std::string& actionType,
                               const std::string& description,
                               const std::map<std::string, std::string>& details,
                               const std::string& requesterId,
                               Autonomy::DecisionPriority priority);

    /**
     * Respond to approval request
     */
    bool RespondToApproval(const std::string& approvalId, 
                          bool approved,
                          const std::string& reason,
                          const std::string& userId);

    /**
     * Send notification
     */
    std::string SendNotification(NotificationType type,
                                const std::string& title,
                                const std::string& message,
                                const std::map<std::string, std::string>& data = {});

    /**
     * Get pending approvals
     */
    std::vector<PendingApproval> GetPendingApprovals() const;

    /**
     * Get notifications
     */
    std::vector<Notification> GetNotifications(bool unacknowledgedOnly = false) const;

    /**
     * Get command help
     */
    std::string GetHelp(const std::string& command = "") const;

    /**
     * Print status
     */
    void PrintStatus() const;

    // Access to components
    CommandParser& GetParser() { return parser_; }
    IntentTranslator& GetTranslator() { return translator_; }
    ApprovalGate& GetApprovalGate() { return approvalGate_; }
    NotificationManager& GetNotificationManager() { return notificationManager_; }

private:
    bool initialized_{false};
    
    CommandParser parser_;
    IntentTranslator translator_;
    ApprovalGate approvalGate_;
    NotificationManager notificationManager_;
    
    // Command handlers
    std::map<CommandType, std::function<CommandResult(const Command&)>> handlers_;
    
    void RegisterHandlers();
    CommandResult HandleQuery(const Command& cmd);
    CommandResult HandleControl(const Command& cmd);
    CommandResult HandleMutate(const Command& cmd);
    CommandResult HandleDecision(const Command& cmd);
    CommandResult HandleCheckpoint(const Command& cmd);
    CommandResult HandleConfigure(const Command& cmd);
    CommandResult HandleStatus(const Command& cmd);
    CommandResult HandleHelp(const Command& cmd);
};

/**
 * CLI for testing the human interaction protocol
 */
class HumanInteractionProtocolCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static void InteractiveMode(HumanInteractionProtocol& protocol);
    static void PrintPrompt();
};

} // namespace Interface
