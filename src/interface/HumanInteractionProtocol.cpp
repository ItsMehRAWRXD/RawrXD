/**
 * HumanInteractionProtocol.cpp
 *
 * Phase D.2 Batch 4/5: Human Interaction Protocol
 */

#include "HumanInteractionProtocol.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <random>

namespace Interface {

// ============================================================================
// Command Type Conversions
// ============================================================================

std::string CommandTypeToString(CommandType type) {
    switch (type) {
        case CommandType::QUERY: return "QUERY";
        case CommandType::CONTROL: return "CONTROL";
        case CommandType::MUTATE: return "MUTATE";
        case CommandType::DECISION: return "DECISION";
        case CommandType::CHECKPOINT: return "CHECKPOINT";
        case CommandType::CONFIGURE: return "CONFIGURE";
        case CommandType::STATUS: return "STATUS";
        case CommandType::HELP: return "HELP";
        default: return "UNKNOWN";
    }
}

CommandType StringToCommandType(const std::string& str) {
    if (str == "query") return CommandType::QUERY;
    if (str == "control") return CommandType::CONTROL;
    if (str == "mutate") return CommandType::MUTATE;
    if (str == "decision") return CommandType::DECISION;
    if (str == "checkpoint") return CommandType::CHECKPOINT;
    if (str == "configure") return CommandType::CONFIGURE;
    if (str == "status") return CommandType::STATUS;
    if (str == "help") return CommandType::HELP;
    return CommandType::UNKNOWN;
}

// ============================================================================
// Intent Type Conversions
// ============================================================================

std::string IntentTypeToString(IntentType type) {
    switch (type) {
        case IntentType::INSPECT: return "INSPECT";
        case IntentType::MODIFY: return "MODIFY";
        case IntentType::EXECUTE: return "EXECUTE";
        case IntentType::APPROVE: return "APPROVE";
        case IntentType::REJECT: return "REJECT";
        case IntentType::QUERY: return "QUERY";
        case IntentType::EMERGENCY: return "EMERGENCY";
        default: return "UNKNOWN";
    }
}

IntentType StringToIntentType(const std::string& str) {
    if (str == "inspect") return IntentType::INSPECT;
    if (str == "modify") return IntentType::MODIFY;
    if (str == "execute") return IntentType::EXECUTE;
    if (str == "approve") return IntentType::APPROVE;
    if (str == "reject") return IntentType::REJECT;
    if (str == "query") return IntentType::QUERY;
    if (str == "emergency") return IntentType::EMERGENCY;
    return IntentType::UNKNOWN;
}

// ============================================================================
// Approval Status Conversions
// ============================================================================

std::string ApprovalStatusToString(ApprovalStatus status) {
    switch (status) {
        case ApprovalStatus::PENDING: return "PENDING";
        case ApprovalStatus::APPROVED: return "APPROVED";
        case ApprovalStatus::REJECTED: return "REJECTED";
        case ApprovalStatus::EXPIRED: return "EXPIRED";
        case ApprovalStatus::CANCELLED: return "CANCELLED";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Notification Type Conversions
// ============================================================================

std::string NotificationTypeToString(NotificationType type) {
    switch (type) {
        case NotificationType::INFO: return "INFO";
        case NotificationType::WARNING: return "WARNING";
        case NotificationType::ERROR: return "ERROR";
        case NotificationType::CRITICAL: return "CRITICAL";
        case NotificationType::DECISION_REQUIRED: return "DECISION_REQUIRED";
        case NotificationType::PATTERN_DETECTED: return "PATTERN_DETECTED";
        case NotificationType::STATE_CHANGE: return "STATE_CHANGE";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Command Implementation
// ============================================================================

std::string Command::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"commandId\":\"" << commandId << "\",";
    json << "\"type\":\"" << CommandTypeToString(type) << "\",";
    json << "\"verb\":\"" << verb << "\",";
    json << "\"source\":\"" << source << "\",";
    json << "\"userId\":\"" << userId << "\",";
    json << "\"timestampMs\":" << timestampMs;
    json << "}";
    return json.str();
}

void Command::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  COMMAND                                                         ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ID:      " << std::left << std::setw(48) << commandId << " ║\n";
    std::cout << "║  Type:    " << std::setw(48) << CommandTypeToString(type) << " ║\n";
    std::cout << "║  Verb:    " << std::setw(48) << verb << " ║\n";
    std::cout << "║  Source:  " << std::setw(48) << source << " ║\n";
    std::cout << "║  User:    " << std::setw(48) << userId << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// CommandResult Implementation
// ============================================================================

std::string CommandResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"commandId\":\"" << commandId << "\",";
    json << "\"message\":\"" << message << "\",";
    json << "\"executionTimeMs\":" << executionTimeMs << ",";
    json << "\"requiresApproval\":" << (requiresApproval ? "true" : "false");
    if (!errorMessage.empty()) {
        json << ",\"errorMessage\":\"" << errorMessage << "\"";
    }
    if (!approvalId.empty()) {
        json << ",\"approvalId\":\"" << approvalId << "\"";
    }
    json << "}";
    return json.str();
}

void CommandResult::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  RESULT                                                          ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Status:  " << std::left << std::setw(48) 
              << (success ? "SUCCESS" : "FAILED") << " ║\n";
    std::cout << "║  Time:    " << std::setw(10) << executionTimeMs << " ms" 
              << std::string(38, ' ') << "║\n";
    
    if (!message.empty()) {
        std::cout << "║  Message: " << std::setw(49) << message << " ║\n";
    }
    
    if (!errorMessage.empty()) {
        std::cout << "║  Error:   " << std::setw(49) << errorMessage << " ║\n";
    }
    
    if (requiresApproval) {
        std::cout << "║  Approval Required: YES                                          ║\n";
        std::cout << "║  Approval ID: " << std::setw(45) << approvalId << " ║\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Intent Implementation
// ============================================================================

std::string Intent::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"intentId\":\"" << intentId << "\",";
    json << "\"type\":\"" << IntentTypeToString(type) << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"confidence\":" << confidence << ",";
    json << "\"timestampMs\":" << timestampMs;
    json << "}";
    return json.str();
}

void Intent::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  INTENT                                                          ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ID:          " << std::left << std::setw(43) << intentId << " ║\n";
    std::cout << "║  Type:        " << std::setw(43) << IntentTypeToString(type) << " ║\n";
    std::cout << "║  Description: " << std::setw(43) << description << " ║\n";
    std::cout << "║  Confidence:  " << std::setw(10) << std::fixed << std::setprecision(2) << confidence << "%" 
              << std::string(32, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// IntentTranslation Implementation
// ============================================================================

std::string IntentTranslation::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"confidence\":" << confidence << ",";
    json << "\"intent\":" << intent.ToJson() << ",";
    json << "\"commands\":" << commands.size();
    if (!errorMessage.empty()) {
        json << ",\"errorMessage\":\"" << errorMessage << "\"";
    }
    json << "}";
    return json.str();
}

// ============================================================================
// ApprovalRequest Implementation
// ============================================================================

std::string ApprovalRequest::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"approvalId\":\"" << approvalId << "\",";
    json << "\"requestType\":\"" << requestType << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"requesterId\":\"" << requesterId << "\",";
    json << "\"requestedAtMs\":" << requestedAtMs << ",";
    json << "\"timeoutMs\":" << timeoutMs << ",";
    json << "\"priority\":\"" << Autonomy::DecisionPriorityToString(priority) << "\"";
    json << "}";
    return json.str();
}

void ApprovalRequest::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  APPROVAL REQUEST                                                ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ID:          " << std::left << std::setw(43) << approvalId << " ║\n";
    std::cout << "║  Type:        " << std::setw(43) << requestType << " ║\n";
    std::cout << "║  Description: " << std::setw(43) << description << " ║\n";
    std::cout << "║  Requester:   " << std::setw(43) << requesterId << " ║\n";
    std::cout << "║  Priority:    " << std::setw(43) << Autonomy::DecisionPriorityToString(priority) << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// ApprovalResponse Implementation
// ============================================================================

std::string ApprovalResponse::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"approvalId\":\"" << approvalId << "\",";
    json << "\"approved\":" << (approved ? "true" : "false") << ",";
    json << "\"approverId\":\"" << approverId << "\",";
    json << "\"reason\":\"" << reason << "\",";
    json << "\"respondedAtMs\":" << respondedAtMs;
    json << "}";
    return json.str();
}

// ============================================================================
// Notification Implementation
// ============================================================================

std::string Notification::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"notificationId\":\"" << notificationId << "\",";
    json << "\"type\":\"" << NotificationTypeToString(type) << "\",";
    json << "\"title\":\"" << title << "\",";
    json << "\"message\":\"" << message << "\",";
    json << "\"timestampMs\":" << timestampMs << ",";
    json << "\"acknowledged\":" << (acknowledged ? "true" : "false");
    json << "}";
    return json.str();
}

void Notification::Print() const {
    const char* typeStr = NotificationTypeToString(type).c_str();
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  NOTIFICATION                                                    ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ID:    " << std::left << std::setw(50) << notificationId << " ║\n";
    std::cout << "║  Type:  " << std::setw(50) << typeStr << " ║\n";
    std::cout << "║  Title: " << std::setw(50) << title << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    // Wrap message
    std::istringstream msgStream(message);
    std::string word;
    std::string line = "║  ";
    while (msgStream >> word) {
        if (line.length() + word.length() + 1 > 61) {
            std::cout << std::left << std::setw(62) << line << "║\n";
            line = "║  " + word;
        } else {
            if (line.length() > 4) line += " ";
            line += word;
        }
    }
    if (line.length() > 4) {
        std::cout << std::left << std::setw(62) << line << "║\n";
    }
    
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Acknowledged: " << std::setw(45) << (acknowledged ? "YES" : "NO") << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// CommandParser Implementation
// ============================================================================

CommandParser::CommandParser() {
    InitializeHelp();
}

CommandParser::~CommandParser() = default;

void CommandParser::InitializeHelp() {
    commandHelp_["query"] = "Query runtime state: query <what> [--format json|text]";
    commandHelp_["control"] = "Control runtime: control <start|stop|pause|resume>";
    commandHelp_["mutate"] = "Mutate graph: mutate add_node|remove_node|add_edge <args>";
    commandHelp_["decision"] = "Decision operations: decision approve|reject <id>";
    commandHelp_["checkpoint"] = "Checkpoint operations: checkpoint create|restore|list";
    commandHelp_["configure"] = "Configure settings: configure <key> <value>";
    commandHelp_["status"] = "Get runtime status";
    commandHelp_["help"] = "Show help: help [command]";
}

Command CommandParser::Parse(const std::string& input, const std::string& source) {
    Command cmd;
    cmd.raw = input;
    cmd.source = source;
    cmd.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    cmd.commandId = "cmd_" + std::to_string(cmd.timestampMs);
    
    auto tokens = Tokenize(input);
    if (tokens.empty()) {
        cmd.type = CommandType::UNKNOWN;
        return cmd;
    }
    
    cmd.verb = tokens[0];
    cmd.type = ParseCommandType(cmd.verb);
    
    // Parse arguments and options
    for (size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i].find("--") == 0) {
            // Option
            std::string opt = tokens[i].substr(2);
            size_t eqPos = opt.find('=');
            if (eqPos != std::string::npos) {
                cmd.options[opt.substr(0, eqPos)] = opt.substr(eqPos + 1);
            } else if (i + 1 < tokens.size()) {
                cmd.options[opt] = tokens[++i];
            }
        } else {
            // Argument
            cmd.args.push_back(tokens[i]);
        }
    }
    
    return cmd;
}

bool CommandParser::Validate(const Command& command, std::string& error) const {
    if (command.type == CommandType::UNKNOWN) {
        error = "Unknown command: " + command.verb;
        return false;
    }
    return true;
}

std::string CommandParser::GetHelp(const std::string& command) const {
    if (command.empty()) {
        std::ostringstream help;
        help << "Available commands:\n\n";
        for (const auto& [cmd, desc] : commandHelp_) {
            help << "  " << std::left << std::setw(15) << cmd << " - " << desc << "\n";
        }
        return help.str();
    }
    
    auto it = commandHelp_.find(command);
    if (it != commandHelp_.end()) {
        return it->second;
    }
    return "Unknown command: " + command;
}

std::vector<std::string> CommandParser::GetAvailableCommands() const {
    std::vector<std::string> commands;
    for (const auto& [cmd, _] : commandHelp_) {
        commands.push_back(cmd);
    }
    return commands;
}

std::vector<std::string> CommandParser::Tokenize(const std::string& input) const {
    std::vector<std::string> tokens;
    std::istringstream stream(input);
    std::string token;
    
    while (stream >> token) {
        tokens.push_back(token);
    }
    
    return tokens;
}

CommandType CommandParser::ParseCommandType(const std::string& verb) const {
    return StringToCommandType(verb);
}

// ============================================================================
// IntentTranslator Implementation
// ============================================================================

IntentTranslator::IntentTranslator() {
    // Register default patterns
    RegisterPattern("show", IntentType::INSPECT, 0.8);
    RegisterPattern("display", IntentType::INSPECT, 0.8);
    RegisterPattern("get", IntentType::INSPECT, 0.8);
    RegisterPattern("what is", IntentType::QUERY, 0.9);
    RegisterPattern("change", IntentType::MODIFY, 0.7);
    RegisterPattern("set", IntentType::MODIFY, 0.7);
    RegisterPattern("update", IntentType::MODIFY, 0.7);
    RegisterPattern("run", IntentType::EXECUTE, 0.8);
    RegisterPattern("execute", IntentType::EXECUTE, 0.8);
    RegisterPattern("start", IntentType::EXECUTE, 0.8);
    RegisterPattern("approve", IntentType::APPROVE, 0.9);
    RegisterPattern("reject", IntentType::REJECT, 0.9);
    RegisterPattern("emergency", IntentType::EMERGENCY, 0.95);
    RegisterPattern("stop", IntentType::EMERGENCY, 0.6);
}

IntentTranslator::~IntentTranslator() = default;

IntentTranslation IntentTranslator::Translate(const std::string& input, const std::string& userId) {
    IntentTranslation translation;
    translation.intent.intentId = "intent_" + std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    translation.intent.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    translation.intent.description = input;
    
    // Match pattern
    translation.intent.type = MatchPattern(input);
    translation.intent.confidence = GetConfidence(input, translation.intent.type);
    
    // Generate commands
    translation.commands = GenerateCommands(translation.intent);
    translation.intent.translatedCommands = translation.commands;
    
    translation.success = true;
    translation.confidence = translation.intent.confidence;
    
    return translation;
}

std::vector<Command> IntentTranslator::IntentToCommands(const Intent& intent) {
    return GenerateCommands(intent);
}

void IntentTranslator::RegisterPattern(const std::string& pattern, IntentType type, double confidence) {
    patterns_.push_back({pattern, type, confidence});
}

double IntentTranslator::GetConfidence(const std::string& input, IntentType type) const {
    for (const auto& pattern : patterns_) {
        if (input.find(pattern.pattern) != std::string::npos && pattern.type == type) {
            return pattern.baseConfidence;
        }
    }
    return 0.5;  // Default confidence
}

IntentType IntentTranslator::MatchPattern(const std::string& input) const {
    std::string lowerInput = input;
    std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(), ::tolower);
    
    for (const auto& pattern : patterns_) {
        if (lowerInput.find(pattern.pattern) != std::string::npos) {
            return pattern.type;
        }
    }
    
    return IntentType::UNKNOWN;
}

std::vector<Command> IntentTranslator::GenerateCommands(const Intent& intent) const {
    std::vector<Command> commands;
    
    Command cmd;
    cmd.intentId = intent.intentId;
    cmd.timestampMs = intent.timestampMs;
    
    switch (intent.type) {
        case IntentType::INSPECT:
        case IntentType::QUERY:
            cmd.type = CommandType::QUERY;
            cmd.verb = "query";
            break;
        case IntentType::MODIFY:
            cmd.type = CommandType::CONFIGURE;
            cmd.verb = "configure";
            break;
        case IntentType::EXECUTE:
            cmd.type = CommandType::CONTROL;
            cmd.verb = "control";
            break;
        case IntentType::APPROVE:
            cmd.type = CommandType::DECISION;
            cmd.verb = "decision";
            break;
        case IntentType::REJECT:
            cmd.type = CommandType::DECISION;
            cmd.verb = "decision";
            break;
        default:
            cmd.type = CommandType::UNKNOWN;
            cmd.verb = "help";
            break;
    }
    
    commands.push_back(cmd);
    return commands;
}

// ============================================================================
// ApprovalGate Implementation
// ============================================================================

ApprovalGate::ApprovalGate() = default;
ApprovalGate::~ApprovalGate() = default;

bool ApprovalGate::Initialize(int defaultTimeoutMs) {
    defaultTimeoutMs_ = defaultTimeoutMs;
    
    // Set default policies
    policies_["mutation"] = {Autonomy::DecisionPriority::HIGH, true};
    policies_["checkpoint_restore"] = {Autonomy::DecisionPriority::HIGH, true};
    policies_["emergency_stop"] = {Autonomy::DecisionPriority::CRITICAL, false};
    policies_["configuration"] = {Autonomy::DecisionPriority::MEDIUM, true};
    
    std::cout << "[ApprovalGate] Initialized\n";
    return true;
}

std::string ApprovalGate::RequestApproval(const ApprovalRequest& request) {
    PendingApproval pending;
    pending.request = request;
    pending.status = ApprovalStatus::PENDING;
    pending.expiresAtMs = GetCurrentTimeMs() + request.timeoutMs;
    
    {
        std::lock_guard<std::mutex> lock(approvalsMutex_);
        approvals_[request.approvalId] = pending;
    }
    
    std::cout << "[ApprovalGate] Approval requested: " << request.approvalId << "\n";
    
    return request.approvalId;
}

bool ApprovalGate::Respond(const std::string& approvalId, const ApprovalResponse& response) {
    std::lock_guard<std::mutex> lock(approvalsMutex_);
    
    auto it = approvals_.find(approvalId);
    if (it == approvals_.end()) {
        return false;
    }
    
    it->second.status = response.approved ? ApprovalStatus::APPROVED : ApprovalStatus::REJECTED;
    it->second.response = response;
    
    std::cout << "[ApprovalGate] Approval " << approvalId << " "
              << (response.approved ? "APPROVED" : "REJECTED") << "\n";
    
    return true;
}

ApprovalStatus ApprovalGate::GetStatus(const std::string& approvalId) const {
    std::lock_guard<std::mutex> lock(approvalsMutex_);
    
    auto it = approvals_.find(approvalId);
    if (it == approvals_.end()) {
        return ApprovalStatus::EXPIRED;
    }
    
    // Check expiration
    if (it->second.status == ApprovalStatus::PENDING && 
        GetCurrentTimeMs() > it->second.expiresAtMs) {
        it->second.status = ApprovalStatus::EXPIRED;
    }
    
    return it->second.status;
}

std::vector<PendingApproval> ApprovalGate::GetPendingApprovals() const {
    std::lock_guard<std::mutex> lock(approvalsMutex_);
    
    std::vector<PendingApproval> pending;
    for (const auto& [id, approval] : approvals_) {
        if (approval.status == ApprovalStatus::PENDING) {
            pending.push_back(approval);
        }
    }
    
    return pending;
}

bool ApprovalGate::Cancel(const std::string& approvalId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(approvalsMutex_);
    
    auto it = approvals_.find(approvalId);
    if (it == approvals_.end()) {
        return false;
    }
    
    it->second.status = ApprovalStatus::CANCELLED;
    
    std::cout << "[ApprovalGate] Approval " << approvalId << " CANCELLED: " << reason << "\n";
    
    return true;
}

bool ApprovalGate::IsApprovalRequired(const std::string& actionType,
                                    Autonomy::DecisionPriority priority) const {
    auto it = policies_.find(actionType);
    if (it == policies_.end()) {
        return priority >= Autonomy::DecisionPriority::HIGH;
    }
    
    return it->second.second && priority >= it->second.first;
}

void ApprovalGate::SetApprovalPolicy(const std::string& actionType,
                                     Autonomy::DecisionPriority minPriority,
                                     bool requireApproval) {
    policies_[actionType] = {minPriority, requireApproval};
}

void ApprovalGate::CleanupExpired() {
    std::lock_guard<std::mutex> lock(approvalsMutex_);
    
    auto now = GetCurrentTimeMs();
    for (auto& [id, approval] : approvals_) {
        if (approval.status == ApprovalStatus::PENDING && now > approval.expiresAtMs) {
            approval.status = ApprovalStatus::EXPIRED;
        }
    }
}

void ApprovalGate::PrintStatus() const {
    std::lock_guard<std::mutex> lock(approvalsMutex_);
    
    int pending = 0, approved = 0, rejected = 0, expired = 0;
    for (const auto& [id, approval] : approvals_) {
        switch (approval.status) {
            case ApprovalStatus::PENDING: pending++; break;
            case ApprovalStatus::APPROVED: approved++; break;
            case ApprovalStatus::REJECTED: rejected++; break;
            case ApprovalStatus::EXPIRED: expired++; break;
            default: break;
        }
    }
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     APPROVAL GATE STATUS                                         ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total:     " << std::setw(48) << approvals_.size() << " ║\n";
    std::cout << "║  Pending:  " << std::setw(48) << pending << " ║\n";
    std::cout << "║  Approved: " << std::setw(48) << approved << " ║\n";
    std::cout << "║  Rejected: " << std::setw(48) << rejected << " ║\n";
    std::cout << "║  Expired:  " << std::setw(48) << expired << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

int64_t ApprovalGate::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// NotificationManager Implementation
// ============================================================================

NotificationManager::NotificationManager() = default;
NotificationManager::~NotificationManager() = default;

bool NotificationManager::Initialize(int maxNotifications) {
    maxNotifications_ = maxNotifications;
    std::cout << "[NotificationManager] Initialized\n";
    return true;
}

std::string NotificationManager::Notify(const Notification& notification) {
    std::lock_guard<std::mutex> lock(notificationsMutex_);
    
    std::string id = notification.notificationId.empty() ? 
        GenerateNotificationId() : notification.notificationId;
    
    Notification notif = notification;
    notif.notificationId = id;
    notif.timestampMs = GetCurrentTimeMs();
    
    notifications_[id] = notif;
    
    // Prune if too many
    while (notifications_.size() > static_cast<size_t>(maxNotifications_)) {
        auto oldest = notifications_.begin();
        for (auto it = notifications_.begin(); it != notifications_.end(); ++it) {
            if (it->second.timestampMs < oldest->second.timestampMs) {
                oldest = it;
            }
        }
        notifications_.erase(oldest);
    }
    
    std::cout << "[NotificationManager] Notification: " << id << "\n";
    
    return id;
}

bool NotificationManager::Acknowledge(const std::string& notificationId, const std::string& userId) {
    std::lock_guard<std::mutex> lock(notificationsMutex_);
    
    auto it = notifications_.find(notificationId);
    if (it == notifications_.end()) {
        return false;
    }
    
    it->second.acknowledged = true;
    it->second.acknowledgedBy = userId;
    it->second.acknowledgedAtMs = GetCurrentTimeMs();
    
    return true;
}

std::vector<Notification> NotificationManager::GetNotifications(bool unacknowledgedOnly,
                                                                 int limit) const {
    std::lock_guard<std::mutex> lock(notificationsMutex_);
    
    std::vector<Notification> result;
    for (const auto& [id, notif] : notifications_) {
        if (!unacknowledgedOnly || !notif.acknowledged) {
            result.push_back(notif);
            if (result.size() >= static_cast<size_t>(limit)) break;
        }
    }
    
    return result;
}

std::vector<Notification> NotificationManager::GetNotificationsByType(NotificationType type,
                                                                        int limit) const {
    std::lock_guard<std::mutex> lock(notificationsMutex_);
    
    std::vector<Notification> result;
    for (const auto& [id, notif] : notifications_) {
        if (notif.type == type) {
            result.push_back(notif);
            if (result.size() >= static_cast<size_t>(limit)) break;
        }
    }
    
    return result;
}

void NotificationManager::ClearOld(int maxAgeMs) {
    std::lock_guard<std::mutex> lock(notificationsMutex_);
    
    auto now = GetCurrentTimeMs();
    for (auto it = notifications_.begin(); it != notifications_.end();) {
        if (now - it->second.timestampMs > maxAgeMs) {
            it = notifications_.erase(it);
        } else {
            ++it;
        }
    }
}

void NotificationManager::PrintStatus() const {
    std::lock_guard<std::mutex> lock(notificationsMutex_);
    
    int unacknowledged = 0;
    for (const auto& [id, notif] : notifications_) {
        if (!notif.acknowledged) unacknowledged++;
    }
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     NOTIFICATION MANAGER STATUS                                    ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total:           " << std::setw(41) << notifications_.size() << " ║\n";
    std::cout << "║  Unacknowledged: " << std::setw(41) << unacknowledged << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

std::string NotificationManager::GenerateNotificationId() {
    return "notif_" + std::to_string(GetCurrentTimeMs());
}

int64_t NotificationManager::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// HumanInteractionProtocol Implementation
// ============================================================================

HumanInteractionProtocol::HumanInteractionProtocol() = default;
HumanInteractionProtocol::~HumanInteractionProtocol() = default;

bool HumanInteractionProtocol::Initialize(int approvalTimeoutMs, int maxNotifications) {
    approvalGate_.Initialize(approvalTimeoutMs);
    notificationManager_.Initialize(maxNotifications);
    RegisterHandlers();
    
    initialized_ = true;
    std::cout << "[HumanInteractionProtocol] Initialized\n";
    return true;
}

void HumanInteractionProtocol::RegisterHandlers() {
    handlers_[CommandType::QUERY] = [this](const Command& cmd) { return HandleQuery(cmd); };
    handlers_[CommandType::CONTROL] = [this](const Command& cmd) { return HandleControl(cmd); };
    handlers_[CommandType::MUTATE] = [this](const Command& cmd) { return HandleMutate(cmd); };
    handlers_[CommandType::DECISION] = [this](const Command& cmd) { return HandleDecision(cmd); };
    handlers_[CommandType::CHECKPOINT] = [this](const Command& cmd) { return HandleCheckpoint(cmd); };
    handlers_[CommandType::CONFIGURE] = [this](const Command& cmd) { return HandleConfigure(cmd); };
    handlers_[CommandType::STATUS] = [this](const Command& cmd) { return HandleStatus(cmd); };
    handlers_[CommandType::HELP] = [this](const Command& cmd) { return HandleHelp(cmd); };
}

CommandResult HumanInteractionProtocol::ProcessCommand(const std::string& input,
                                                       const std::string& source,
                                                       const std::string& userId) {
    auto startTime = std::chrono::steady_clock::now();
    
    CommandResult result;
    
    // Parse command
    Command cmd = parser_.Parse(input, source);
    cmd.userId = userId;
    result.commandId = cmd.commandId;
    
    // Validate
    std::string error;
    if (!parser_.Validate(cmd, error)) {
        result.success = false;
        result.errorMessage = error;
        return result;
    }
    
    // Execute handler
    auto it = handlers_.find(cmd.type);
    if (it != handlers_.end()) {
        result = it->second(cmd);
    } else {
        result.success = false;
        result.errorMessage = "No handler for command type";
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    return result;
}

CommandResult HumanInteractionProtocol::ProcessIntent(const std::string& input,
                                                      const std::string& userId) {
    // Translate intent
    auto translation = translator_.Translate(input, userId);
    
    if (!translation.success || translation.commands.empty()) {
        CommandResult result;
        result.success = false;
        result.errorMessage = "Failed to translate intent: " + translation.errorMessage;
        return result;
    }
    
    // Execute first command
    const auto& cmd = translation.commands[0];
    auto it = handlers_.find(cmd.type);
    if (it != handlers_.end()) {
        return it->second(cmd);
    }
    
    CommandResult result;
    result.success = false;
    result.errorMessage = "No handler for translated command";
    return result;
}

std::string HumanInteractionProtocol::RequestApproval(const std::string& actionType,
                                                     const std::string& description,
                                                     const std::map<std::string, std::string>& details,
                                                     const std::string& requesterId,
                                                     Autonomy::DecisionPriority priority) {
    ApprovalRequest request;
    request.approvalId = "appr_" + std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    request.requestType = actionType;
    request.description = description;
    request.details = details;
    request.requesterId = requesterId;
    request.priority = priority;
    request.requestedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return approvalGate_.RequestApproval(request);
}

bool HumanInteractionProtocol::RespondToApproval(const std::string& approvalId,
                                                bool approved,
                                                const std::string& reason,
                                                const std::string& userId) {
    ApprovalResponse response;
    response.approvalId = approvalId;
    response.approved = approved;
    response.approverId = userId;
    response.reason = reason;
    response.respondedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return approvalGate_.Respond(approvalId, response);
}

std::string HumanInteractionProtocol::SendNotification(NotificationType type,
                                                       const std::string& title,
                                                       const std::string& message,
                                                       const std::map<std::string, std::string>& data) {
    Notification notification;
    notification.type = type;
    notification.title = title;
    notification.message = message;
    notification.data = data;
    
    return notificationManager_.Notify(notification);
}

std::vector<PendingApproval> HumanInteractionProtocol::GetPendingApprovals() const {
    return approvalGate_.GetPendingApprovals();
}

std::vector<Notification> HumanInteractionProtocol::GetNotifications(bool unacknowledgedOnly) const {
    return notificationManager_.GetNotifications(unacknowledgedOnly);
}

std::string HumanInteractionProtocol::GetHelp(const std::string& command) const {
    return parser_.GetHelp(command);
}

void HumanInteractionProtocol::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     HUMAN INTERACTION PROTOCOL STATUS                              ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized: " << std::setw(44) << (initialized_ ? "YES" : "NO") << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
    
    approvalGate_.PrintStatus();
    notificationManager_.PrintStatus();
}

// Command handlers
CommandResult HumanInteractionProtocol::HandleQuery(const Command& cmd) {
    CommandResult result;
    result.success = true;
    result.message = "Query executed successfully";
    return result;
}

CommandResult HumanInteractionProtocol::HandleControl(const Command& cmd) {
    CommandResult result;
    result.success = true;
    result.message = "Control command executed: " + cmd.verb;
    return result;
}

CommandResult HumanInteractionProtocol::HandleMutate(const Command& cmd) {
    CommandResult result;
    
    // Check if approval is required
    if (approvalGate_.IsApprovalRequired("mutation", Autonomy::DecisionPriority::HIGH)) {
        result.requiresApproval = true;
        result.approvalId = RequestApproval("mutation", 
            "Graph mutation: " + cmd.raw, {}, cmd.userId, Autonomy::DecisionPriority::HIGH);
        result.message = "Approval requested: " + result.approvalId;
        return result;
    }
    
    result.success = true;
    result.message = "Mutation executed";
    return result;
}

CommandResult HumanInteractionProtocol::HandleDecision(const Command& cmd) {
    CommandResult result;
    result.success = true;
    result.message = "Decision processed";
    return result;
}

CommandResult HumanInteractionProtocol::HandleCheckpoint(const Command& cmd) {
    CommandResult result;
    result.success = true;
    result.message = "Checkpoint operation completed";
    return result;
}

CommandResult HumanInteractionProtocol::HandleConfigure(const Command& cmd) {
    CommandResult result;
    result.success = true;
    result.message = "Configuration updated";
    return result;
}

CommandResult HumanInteractionProtocol::HandleStatus(const Command& cmd) {
    CommandResult result;
    result.success = true;
    result.message = "Runtime is operational";
    return result;
}

CommandResult HumanInteractionProtocol::HandleHelp(const Command& cmd) {
    CommandResult result;
    result.success = true;
    result.message = parser_.GetHelp(cmd.args.empty() ? "" : cmd.args[0]);
    return result;
}

// ============================================================================
// CLI Implementation
// ============================================================================

void HumanInteractionProtocolCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     HUMAN INTERACTION PROTOCOL - Phase D.2                        ║\n";
    std::cout << "║     Command Language • Intent Translation • Approval Gates         ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void HumanInteractionProtocolCLI::PrintUsage() {
    std::cout << "Usage: sovereign-humancmd [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --interactive        Start interactive mode\n";
    std::cout << "  --help               Show this help\n\n";
}

void HumanInteractionProtocolCLI::PrintPrompt() {
    std::cout << "\n┌─[sovereign]\n└─▶ ";
}

void HumanInteractionProtocolCLI::InteractiveMode(HumanInteractionProtocol& protocol) {
    std::cout << "\nInteractive Command Mode\n";
    std::cout << "Type 'help' for available commands, 'quit' to exit\n\n";
    
    std::string input;
    while (true) {
        PrintPrompt();
        std::getline(std::cin, input);
        
        if (input == "quit" || input == "exit") {
            break;
        }
        
        if (input == "help") {
            std::cout << "\n" << protocol.GetHelp() << "\n";
            continue;
        }
        
        if (input == "status") {
            protocol.PrintStatus();
            continue;
        }
        
        if (input.empty()) {
            continue;
        }
        
        auto result = protocol.ProcessCommand(input, "cli", "user");
        result.Print();
    }
}

int HumanInteractionProtocolCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    HumanInteractionProtocol protocol;
    if (!protocol.Initialize()) {
        std::cerr << "Failed to initialize human interaction protocol\n";
        return 1;
    }
    
    // Check for --interactive
    if (argc > 1 && std::string(argv[1]) == "--interactive") {
        InteractiveMode(protocol);
        return 0;
    }
    
    // No command provided, enter interactive mode
    InteractiveMode(protocol);
    return 0;
}

} // namespace Interface
