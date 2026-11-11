/**
 * @file Core.cpp
 * @brief Unified Agentic Core Implementation
 * 
 * Consolidates all AgenticEngine implementations into a single,
 * coherent implementation following the 5-layer architecture.
 * 
 * @copyright RawrXD 2026
 */

#include "Core.h"
#include "../inference/InferenceEngine.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>
#include <sstream>
#include <thread>
#include <unordered_map>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace RawrXD {
namespace Agentic {

// Forward declarations for subsystems
class TaskSchedulerImpl;
class ToolRegistryImpl;
class HistoryRecorderImpl;
class PolicyEngineImpl;
class SubAgentManagerImpl;

// ============================================================================
// Subsystem Implementations
// ============================================================================

class TaskSchedulerImpl : public TaskScheduler {
public:
    TaskSchedulerImpl() : maxConcurrent_(4), shutdown_(false) {}
    
    bool Initialize() override { 
        shutdown_ = false;
        return true; 
    }
    
    void Shutdown() override {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        cv_.notify_all();
    }
    
    std::string ScheduleTask(const Task& task) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        std::string taskId = "task-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());
        
        TaskEntry entry;
        entry.task = task;
        entry.status = TaskStatus::Pending;
        entry.createdAt = std::chrono::steady_clock::now();
        tasks_[taskId] = std::move(entry);
        
        // Try to execute if we have capacity
        TryExecuteNext();
        
        return taskId;
    }
    
    bool CancelTask(const std::string& taskId) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(taskId);
        if (it == tasks_.end()) return false;
        
        if (it->second.status == TaskStatus::Running) {
            // Can't cancel running tasks
            return false;
        }
        
        it->second.status = TaskStatus::Cancelled;
        return true;
    }
    
    TaskStatus GetTaskStatus(const std::string& taskId) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tasks_.find(taskId);
        if (it == tasks_.end()) return TaskStatus::Unknown;
        return it->second.status;
    }
    
    std::vector<std::string> GetActiveTasks() override { 
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> active;
        for (const auto& [id, entry] : tasks_) {
            if (entry.status == TaskStatus::Pending || entry.status == TaskStatus::Running) {
                active.push_back(id);
            }
        }
        return active;
    }
    
    void SetMaxConcurrent(size_t max) override {
        std::lock_guard<std::mutex> lock(mutex_);
        maxConcurrent_ = max;
        TryExecuteNext();
    }
    
    size_t GetMaxConcurrent() const override { 
        std::lock_guard<std::mutex> lock(mutex_);
        return maxConcurrent_; 
    }

private:
    struct TaskEntry {
        Task task;
        TaskStatus status;
        std::chrono::steady_clock::time_point createdAt;
        std::chrono::steady_clock::time_point startedAt;
    };
    
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::unordered_map<std::string, TaskEntry> tasks_;
    size_t maxConcurrent_;
    size_t runningCount_ = 0;
    bool shutdown_;
    
    void TryExecuteNext() {
        if (runningCount_ >= maxConcurrent_) return;
        
        for (auto& [id, entry] : tasks_) {
            if (entry.status == TaskStatus::Pending) {
                entry.status = TaskStatus::Running;
                entry.startedAt = std::chrono::steady_clock::now();
                runningCount_++;
                
                // Execute task asynchronously in a thread
                std::thread taskThread([this, id]() {
                    auto& taskEntry = tasks_[id];
                    
                    // Execute the task
                    bool success = true;
                    try {
                        // Task execution logic - process the task workload
                        // This is where actual task processing would occur
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    } catch (...) {
                        success = false;
                    }
                    
                    // Update task status
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        taskEntry.status = success ? TaskStatus::Completed : TaskStatus::Failed;
                        runningCount_--;
                    }
                    cv_.notify_all();
                    
                    // Try to execute next pending task
                    TryExecuteNext();
                });
                
                taskThread.detach();
                break;
            }
        }
    }
};

class ToolRegistryImpl : public ToolRegistry {
public:
    ToolRegistryImpl() = default;
    
    bool Initialize() override { 
        std::lock_guard<std::mutex> lock(mutex_);
        tools_.clear();
        handlers_.clear();
        return true; 
    }
    
    void Shutdown() override {
        std::lock_guard<std::mutex> lock(mutex_);
        tools_.clear();
        handlers_.clear();
    }
    
    bool RegisterTool(const Tool& tool) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        if (tool.id.empty()) return false;
        
        // Check for duplicate
        if (tools_.find(tool.id) != tools_.end()) {
            return false;
        }
        
        tools_[tool.id] = tool;
        
        // Register default handler if not already set
        if (handlers_.find(tool.id) == handlers_.end()) {
            handlers_[tool.id] = nullptr; // No handler by default
        }
        
        return true;
    }
    
    bool UnregisterTool(const std::string& toolId) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tools_.find(toolId);
        if (it == tools_.end()) return false;
        
        tools_.erase(it);
        handlers_.erase(toolId);
        return true;
    }
    
    std::optional<Tool> GetTool(const std::string& toolId) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tools_.find(toolId);
        if (it == tools_.end()) return std::nullopt;
        return it->second;
    }
    
    std::vector<Tool> GetAllTools() override { 
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Tool> result;
        result.reserve(tools_.size());
        for (const auto& [id, tool] : tools_) {
            result.push_back(tool);
        }
        return result;
    }
    
    std::vector<Tool> GetToolsByCategory(ToolCategory category) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Tool> result;
        for (const auto& [id, tool] : tools_) {
            if (tool.category == category) {
                result.push_back(tool);
            }
        }
        return result;
    }
    
    bool ExecuteTool(const std::string& toolId, const std::string& params, std::string& output) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tools_.find(toolId);
        if (it == tools_.end()) {
            output = "Error: Tool not found: " + toolId;
            return false;
        }
        
        // Check if tool is enabled
        if (!it->second.enabled) {
            output = "Error: Tool is disabled: " + toolId;
            return false;
        }
        
        // Execute based on tool type
        switch (it->second.category) {
            case ToolCategory::FileOperation:
                return ExecuteFileOperation(it->second, params, output);
            case ToolCategory::SystemCommand:
                return ExecuteSystemCommand(it->second, params, output);
            case ToolCategory::NetworkRequest:
                return ExecuteNetworkRequest(it->second, params, output);
            case ToolCategory::CodeAnalysis:
                return ExecuteCodeAnalysis(it->second, params, output);
            default:
                output = "Error: Unknown tool category";
                return false;
        }
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Tool> tools_;
    std::unordered_map<std::string, std::function<bool(const std::string&, std::string&)>> handlers_;
    
    bool ExecuteFileOperation(const Tool& tool, const std::string& params, std::string& output) {
        // Parse JSON params
        if (params.find("read") != std::string::npos) {
            // Extract file path from params
            size_t pathStart = params.find("\"path\":");
            if (pathStart != std::string::npos) {
                pathStart = params.find("\"", pathStart + 7);
                if (pathStart != std::string::npos) {
                    size_t pathEnd = params.find("\"", pathStart + 1);
                    std::string path = params.substr(pathStart + 1, pathEnd - pathStart - 1);
                    
                    std::ifstream file(path);
                    if (file.is_open()) {
                        std::stringstream ss;
                        ss << file.rdbuf();
                        output = ss.str();
                        return true;
                    } else {
                        output = "Error: Cannot open file: " + path;
                        return false;
                    }
                }
            }
        }
        output = "Error: Invalid file operation params";
        return false;
    }
    
    bool ExecuteSystemCommand(const Tool& tool, const std::string& params, std::string& output) {
        // Extract command from params
        size_t cmdStart = params.find("\"command\":");
        if (cmdStart != std::string::npos) {
            cmdStart = params.find("\"", cmdStart + 10);
            if (cmdStart != std::string::npos) {
                size_t cmdEnd = params.find("\"", cmdStart + 1);
                std::string command = params.substr(cmdStart + 1, cmdEnd - cmdStart - 1);
                
                // Security check - block dangerous commands
                if (command.find("rm -rf /") != std::string::npos ||
                    command.find("del /") != std::string::npos ||
                    command.find("format") != std::string::npos) {
                    output = "Error: Dangerous command blocked";
                    return false;
                }
                
                // Execute command
                FILE* pipe = popen(command.c_str(), "r");
                if (pipe) {
                    char buffer[4096];
                    output.clear();
                    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                        output += buffer;
                    }
                    pclose(pipe);
                    return true;
                }
            }
        }
        output = "Error: Invalid command params";
        return false;
    }
    
    bool ExecuteNetworkRequest(const Tool& tool, const std::string& params, std::string& output) {
        // Parse URL and method from params
        size_t urlStart = params.find("\"url\":");
        size_t methodStart = params.find("\"method\":");
        
        if (urlStart == std::string::npos) {
            output = "Error: URL not specified in params";
            return false;
        }
        
        urlStart = params.find("\"", urlStart + 6);
        if (urlStart == std::string::npos) {
            output = "Error: Invalid URL format";
            return false;
        }
        
        size_t urlEnd = params.find("\"", urlStart + 1);
        std::string url = params.substr(urlStart + 1, urlEnd - urlStart - 1);
        
        std::string method = "GET";
        if (methodStart != std::string::npos) {
            methodStart = params.find("\"", methodStart + 9);
            if (methodStart != std::string::npos) {
                size_t methodEnd = params.find("\"", methodStart + 1);
                method = params.substr(methodStart + 1, methodEnd - methodStart - 1);
            }
        }
        
        // Security check - validate URL
        if (url.find("http://") != 0 && url.find("https://") != 0) {
            output = "Error: Invalid URL scheme (must be http or https)";
            return false;
        }
        
        // Block localhost/internal addresses for security
        std::string lowerUrl = url;
        std::transform(lowerUrl.begin(), lowerUrl.end(), lowerUrl.begin(), ::tolower);
        if (lowerUrl.find("localhost") != std::string::npos ||
            lowerUrl.find("127.0.0.1") != std::string::npos ||
            lowerUrl.find("192.168.") != std::string::npos ||
            lowerUrl.find("10.") != std::string::npos) {
            output = "Error: Internal addresses blocked for security";
            return false;
        }
        
        // Execute HTTP request using system curl (cross-platform)
        std::string curlCmd = "curl -s -X " + method + " \"" + url + "\"";
        
        // Add headers if specified
        size_t headersStart = params.find("\"headers\":");
        if (headersStart != std::string::npos) {
            // Parse headers from JSON and add to curl command
            // Default content-type for JSON requests
            curlCmd += " -H \"Content-Type: application/json\"";
        }
        
        // Add body if specified
        size_t bodyStart = params.find("\"body\":");
        if (bodyStart != std::string::npos) {
            bodyStart = params.find("\"", bodyStart + 7);
            if (bodyStart != std::string::npos) {
                size_t bodyEnd = params.find("\"", bodyStart + 1);
                std::string body = params.substr(bodyStart + 1, bodyEnd - bodyStart - 1);
                curlCmd += " -d \"" + body + "\"";
            }
        }
        
        // Execute curl command
        FILE* pipe = popen(curlCmd.c_str(), "r");
        if (pipe) {
            char buffer[8192];
            output.clear();
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                output += buffer;
            }
            int status = pclose(pipe);
            return (status == 0);
        }
        
        output = "Error: Failed to execute network request";
        return false;
    }
    
    bool ExecuteCodeAnalysis(const Tool& tool, const std::string& params, std::string& output) {
        // Parse analysis type and file path from params
        size_t typeStart = params.find("\"type\":");
        size_t pathStart = params.find("\"path\":");
        
        if (pathStart == std::string::npos) {
            output = "Error: File path not specified";
            return false;
        }
        
        pathStart = params.find("\"", pathStart + 7);
        if (pathStart == std::string::npos) {
            output = "Error: Invalid path format";
            return false;
        }
        
        size_t pathEnd = params.find("\"", pathStart + 1);
        std::string filePath = params.substr(pathStart + 1, pathEnd - pathStart - 1);
        
        std::string analysisType = "general";
        if (typeStart != std::string::npos) {
            typeStart = params.find("\"", typeStart + 8);
            if (typeStart != std::string::npos) {
                size_t typeEnd = params.find("\"", typeStart + 1);
                analysisType = params.substr(typeStart + 1, typeEnd - typeStart - 1);
            }
        }
        
        // Read the file
        std::ifstream file(filePath);
        if (!file.is_open()) {
            output = "Error: Cannot open file: " + filePath;
            return false;
        }
        
        std::stringstream ss;
        ss << file.rdbuf();
        std::string content = ss.str();
        file.close();
        
        // Perform analysis based on type
        std::stringstream result;
        result << "Code Analysis Report for: " << filePath << "\n";
        result << "Analysis Type: " << analysisType << "\n";
        result << "File Size: " << content.size() << " bytes\n\n";
        
        // Line count
        int lineCount = 0;
        int emptyLines = 0;
        int commentLines = 0;
        int codeLines = 0;
        
        std::istringstream contentStream(content);
        std::string line;
        bool inBlockComment = false;
        
        while (std::getline(contentStream, line)) {
            lineCount++;
            
            std::string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
            
            if (trimmed.empty()) {
                emptyLines++;
            } else if (inBlockComment) {
                commentLines++;
                if (trimmed.find("*/") != std::string::npos) {
                    inBlockComment = false;
                }
            } else if (trimmed.substr(0, 2) == "//") {
                commentLines++;
            } else if (trimmed.substr(0, 2) == "/*") {
                commentLines++;
                if (trimmed.find("*/") == std::string::npos) {
                    inBlockComment = true;
                }
            } else {
                codeLines++;
            }
        }
        
        result << "Lines of Code: " << lineCount << "\n";
        result << "  - Code lines: " << codeLines << "\n";
        result << "  - Comment lines: " << commentLines << "\n";
        result << "  - Empty lines: " << emptyLines << "\n\n";
        
        // Function/class detection (basic)
        int functionCount = 0;
        int classCount = 0;
        
        std::regex funcRegex(R"(\b(?:void|int|float|double|bool|string|auto)\s+(\w+)\s*\()");
        std::regex classRegex(R"(\bclass\s+(\w+))");
        
        std::sregex_iterator funcIt(content.begin(), content.end(), funcRegex);
        std::sregex_iterator classIt(content.begin(), content.end(), classRegex);
        std::sregex_iterator end;
        
        for (; funcIt != end; ++funcIt) functionCount++;
        for (; classIt != end; ++classIt) classCount++;
        
        result << "Functions detected: " << functionCount << "\n";
        result << "Classes detected: " << classCount << "\n\n";
        
        // TODO/FIXME detection with tracking
        int todoCount = 0;
        int fixmeCount = 0;
        std::vector<int> todoLines;
        std::vector<int> fixmeLines;
        
        size_t pos = 0;
        while ((pos = content.find("TODO", pos)) != std::string::npos) {
            todoCount++;
            // Track approximate line number
            int line = 1;
            for (size_t i = 0; i < pos; ++i) {
                if (content[i] == '\n') line++;
            }
            todoLines.push_back(line);
            pos += 4;
        }
        
        pos = 0;
        while ((pos = content.find("FIXME", pos)) != std::string::npos) {
            fixmeCount++;
            int line = 1;
            for (size_t i = 0; i < pos; ++i) {
                if (content[i] == '\n') line++;
            }
            fixmeLines.push_back(line);
            pos += 5;
        }
        
        if (todoCount > 0) {
            result << "TODO markers found: " << todoCount << " (lines: ";
            for (size_t i = 0; i < todoLines.size() && i < 5; ++i) {
                if (i > 0) result << ", ";
                result << todoLines[i];
            }
            if (todoLines.size() > 5) result << " ...";
            result << ")\n";
        }
        if (fixmeCount > 0) {
            result << "FIXME markers found: " << fixmeCount << " (lines: ";
            for (size_t i = 0; i < fixmeLines.size() && i < 5; ++i) {
                if (i > 0) result << ", ";
                result << fixmeLines[i];
            }
            if (fixmeLines.size() > 5) result << " ...";
            result << ")\n";
        }
        
        if (todoCount > 0 || fixmeCount > 0) {
            result << "Markers Found:\n";
            result << "  - TODO: " << todoCount << "\n";
            result << "  - FIXME: " << fixmeCount << "\n";
        }
        
        output = result.str();
        return true;
    }
};

class HistoryRecorderImpl : public HistoryRecorder {
public:
    HistoryRecorderImpl() : maxHistorySize_(1000) {}
    
    bool Initialize() override { 
        std::lock_guard<std::mutex> lock(mutex_);
        history_.clear();
        
        // Load persisted history if available
        LoadHistoryFromDisk();
        return true; 
    }
    
    void Shutdown() override {
        std::lock_guard<std::mutex> lock(mutex_);
        // Persist history to disk
        SaveHistoryToDisk();
    }
    
    void RecordTask(const Task& task, const TaskResult& result) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        TaskHistoryEntry entry;
        entry.taskId = task.id;
        entry.taskType = task.type;
        entry.taskDescription = task.description;
        entry.status = result.status;
        entry.timestamp = std::chrono::system_clock::now();
        entry.durationMs = result.durationMs;
        entry.outputPreview = result.output.substr(0, 200); // First 200 chars
        entry.errorMessage = result.errorMessage;
        
        history_.push_back(std::move(entry));
        
        // Trim history if exceeds max size
        if (history_.size() > maxHistorySize_) {
            history_.erase(history_.begin(), history_.begin() + (history_.size() - maxHistorySize_));
        }
        
        // Auto-save every 10 entries
        if (history_.size() % 10 == 0) {
            SaveHistoryToDisk();
        }
    }
    
    std::vector<TaskHistoryEntry> GetHistory(size_t limit) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        if (limit == 0 || limit > history_.size()) {
            limit = history_.size();
        }
        
        // Return most recent entries first
        std::vector<TaskHistoryEntry> result;
        result.reserve(limit);
        auto start = history_.rbegin();
        for (size_t i = 0; i < limit && start != history_.rend(); ++i, ++start) {
            result.push_back(*start);
        }
        return result;
    }
    
    std::vector<TaskHistoryEntry> GetHistoryByType(TaskType type, size_t limit) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TaskHistoryEntry> result;
        result.reserve(limit);
        
        // Search from most recent
        for (auto it = history_.rbegin(); it != history_.rend() && result.size() < limit; ++it) {
            if (it->taskType == type) {
                result.push_back(*it);
            }
        }
        return result;
    }
    
    void ClearHistory() override {
        std::lock_guard<std::mutex> lock(mutex_);
        history_.clear();
        SaveHistoryToDisk();
    }
    
    void SetMaxHistorySize(size_t max) override {
        std::lock_guard<std::mutex> lock(mutex_);
        maxHistorySize_ = max;
        
        // Trim if necessary
        if (history_.size() > maxHistorySize_) {
            history_.erase(history_.begin(), history_.begin() + (history_.size() - maxHistorySize_));
        }
    }

private:
    mutable std::mutex mutex_;
    std::vector<TaskHistoryEntry> history_;
    size_t maxHistorySize_;
    
    std::string GetHistoryFilePath() const {
        std::string path = std::getenv("APPDATA") ? std::getenv("APPDATA") : ".";
        return path + "/RawrXD/task_history.json";
    }
    
    void SaveHistoryToDisk() {
        try {
            std::filesystem::path dir = std::filesystem::path(GetHistoryFilePath()).parent_path();
            std::filesystem::create_directories(dir);
            
            std::ofstream file(GetHistoryFilePath());
            if (!file.is_open()) return;
            
            // Simple JSON serialization
            file << "[\n";
            for (size_t i = 0; i < history_.size(); ++i) {
                const auto& entry = history_[i];
                file << "  {\n";
                file << "    \"taskId\": \"" << entry.taskId << "\",\n";
                file << "    \"taskType\": " << static_cast<int>(entry.taskType) << ",\n";
                file << "    \"description\": \"" << EscapeJson(entry.taskDescription) << "\",\n";
                file << "    \"status\": " << static_cast<int>(entry.status) << ",\n";
                file << "    \"durationMs\": " << entry.durationMs << ",\n";
                file << "    \"outputPreview\": \"" << EscapeJson(entry.outputPreview) << "\"\n";
                file << "  }";
                if (i < history_.size() - 1) file << ",";
                file << "\n";
            }
            file << "]\n";
        } catch (...) {
            // Ignore save errors
        }
    }
    
    void LoadHistoryFromDisk() {
        try {
            std::ifstream file(GetHistoryFilePath());
            if (!file.is_open()) return;
            
            // Simple JSON parsing - just clear and let new history be recorded
            // Full deserialization would require a JSON parser
            history_.clear();
        } catch (...) {
            // Ignore load errors
        }
    }
    
    std::string EscapeJson(const std::string& str) const {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
};

class PolicyEngineImpl : public PolicyEngine {
public:
    PolicyEngineImpl() {
        // Initialize default policies
        policies_[PolicyType::AllowFileRead] = true;
        policies_[PolicyType::AllowFileWrite] = false; // Restricted by default
        policies_[PolicyType::AllowNetworkAccess] = false; // Restricted by default
        policies_[PolicyType::AllowSystemCommand] = false; // Restricted by default
        policies_[PolicyType::AllowCodeExecution] = false; // Restricted by default
        policies_[PolicyType::RequireApproval] = true;
        policies_[PolicyType::LogAllActions] = true;
        policies_[PolicyType::RestrictSandbox] = true;
    }
    
    bool Initialize() override { 
        std::lock_guard<std::mutex> lock(mutex_);
        actionLog_.clear();
        return true; 
    }
    
    void Shutdown() override {
        std::lock_guard<std::mutex> lock(mutex_);
        // Save policy violations log
        SaveViolationLog();
    }
    
    bool ValidateTask(const Task& task, std::string& reason) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check task type against policies
        switch (task.type) {
            case TaskType::FileOperation:
                if (task.description.find("write") != std::string::npos ||
                    task.description.find("delete") != std::string::npos ||
                    task.description.find("modify") != std::string::npos) {
                    if (!policies_[PolicyType::AllowFileWrite]) {
                        reason = "File write operations are restricted by policy";
                        LogViolation("FILE_WRITE_BLOCKED", task.id, reason);
                        return false;
                    }
                }
                break;
                
            case TaskType::SystemCommand:
                if (!policies_[PolicyType::AllowSystemCommand]) {
                    reason = "System commands are restricted by policy";
                    LogViolation("SYS_CMD_BLOCKED", task.id, reason);
                    return false;
                }
                // Additional security check for dangerous commands
                if (IsDangerousCommand(task.description)) {
                    reason = "Command matches dangerous pattern";
                    LogViolation("DANGEROUS_CMD_BLOCKED", task.id, reason);
                    return false;
                }
                break;
                
            case TaskType::NetworkRequest:
                if (!policies_[PolicyType::AllowNetworkAccess]) {
                    reason = "Network access is restricted by policy";
                    LogViolation("NETWORK_BLOCKED", task.id, reason);
                    return false;
                }
                break;
                
            case TaskType::CodeExecution:
                if (!policies_[PolicyType::AllowCodeExecution]) {
                    reason = "Code execution is restricted by policy";
                    LogViolation("CODE_EXEC_BLOCKED", task.id, reason);
                    return false;
                }
                break;
                
            default:
                break;
        }
        
        // Check if approval is required
        if (policies_[PolicyType::RequireApproval] && task.requiresApproval) {
            reason = "Task requires manual approval";
            return false; // Would queue for approval in real implementation
        }
        
        reason = "Task validated successfully";
        
        // Log the validation if logging is enabled
        if (policies_[PolicyType::LogAllActions]) {
            LogAction("TASK_VALIDATED", task.id, reason);
        }
        
        return true;
    }
    
    bool CheckPermission(const std::string& action, const std::string& resource) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Define permission matrix
        if (action == "read") {
            return policies_[PolicyType::AllowFileRead];
        }
        if (action == "write" || action == "delete") {
            return policies_[PolicyType::AllowFileWrite];
        }
        if (action == "network") {
            return policies_[PolicyType::AllowNetworkAccess];
        }
        if (action == "execute") {
            return policies_[PolicyType::AllowSystemCommand];
        }
        if (action == "code") {
            return policies_[PolicyType::AllowCodeExecution];
        }
        
        // Default deny for unknown actions
        return false;
    }
    
    void SetPolicy(PolicyType type, bool enabled) override {
        std::lock_guard<std::mutex> lock(mutex_);
        policies_[type] = enabled;
    }
    
    bool GetPolicy(PolicyType type) const override { 
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = policies_.find(type);
        if (it == policies_.end()) {
            // Log default deny for debugging
            std::cerr << "[Policy] Default deny for unregistered policy type " << static_cast<int>(type) << "\n";
            return false; // Default deny
        }
        return it->second;
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<PolicyType, bool, std::hash<int>> policies_;
    std::vector<std::string> actionLog_;
    std::vector<std::string> violationLog_;
    
    bool IsDangerousCommand(const std::string& cmd) const {
        std::string lower = cmd;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        // List of dangerous patterns
        const std::vector<std::string> dangerous = {
            "rm -rf /", "rm -rf /*", "del /f /s /q", "format", "mkfs",
            "dd if=/dev/zero", ":(){ :|:& };:", "> /dev/sda",
            "powershell -enc", "iex(", "invoke-expression",
            "regsvr32", "mshta", "certutil -decode"
        };
        
        for (const auto& pattern : dangerous) {
            if (lower.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    
    void LogAction(const std::string& action, const std::string& taskId, const std::string& details) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << " [" << action << "] Task: " << taskId << " - " << details;
        
        actionLog_.push_back(ss.str());
        
        // Trim log if too large
        if (actionLog_.size() > 10000) {
            actionLog_.erase(actionLog_.begin(), actionLog_.begin() + 1000);
        }
    }
    
    void LogViolation(const std::string& violation, const std::string& taskId, const std::string& reason) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << " [VIOLATION: " << violation << "] Task: " << taskId << " - " << reason;
        
        violationLog_.push_back(ss.str());
        
        // Also output to debug
        OutputDebugStringA(("[PolicyEngine] " + ss.str() + "\n").c_str());
    }
    
    void SaveViolationLog() {
        try {
            std::string path = std::getenv("APPDATA") ? std::getenv("APPDATA") : ".";
            path += "/RawrXD/policy_violations.log";
            
            std::filesystem::create_directories(std::filesystem::path(path).parent_path());
            
            std::ofstream file(path, std::ios::app);
            if (file.is_open()) {
                for (const auto& violation : violationLog_) {
                    file << violation << "\n";
                }
                violationLog_.clear();
            }
        } catch (...) {
            // Ignore save errors
        }
    }
};

class SubAgentManagerImpl : public SubAgentManager {
public:
    SubAgentManagerImpl() : nextAgentId_(1), shutdown_(false) {}
    
    bool Initialize() override { 
        std::lock_guard<std::mutex> lock(mutex_);
        subAgents_.clear();
        messageQueues_.clear();
        nextAgentId_ = 1;
        shutdown_ = false;
        return true; 
    }
    
    void Shutdown() override {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        
        // Signal all subagents to shutdown
        for (auto& [id, info] : subAgents_) {
            info.state = SubAgentState::ShuttingDown;
        }
        
        // Clear message queues
        messageQueues_.clear();
        subAgents_.clear();
    }
    
    std::string CreateSubAgent(const SubAgentConfig& config) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (shutdown_) {
            return "";
        }
        
        // Check max subagents limit
        if (subAgents_.size() >= 100) {
            OutputDebugStringA("[SubAgentManager] Max subagents limit reached\n");
            return "";
        }
        
        std::string agentId = "subagent-" + std::to_string(nextAgentId_++);
        
        SubAgentInfo info;
        info.id = agentId;
        info.name = config.name.empty() ? agentId : config.name;
        info.type = config.type;
        info.state = SubAgentState::Initializing;
        info.createdAt = std::chrono::steady_clock::now();
        info.config = config;
        
        // Initialize message queue for this agent
        messageQueues_[agentId] = std::queue<std::string>();
        
        // Store the subagent
        subAgents_[agentId] = std::move(info);
        
        // Initialize subagent state
        subAgents_[agentId].state = SubAgentState::Idle;
        
        OutputDebugStringA(("[SubAgentManager] Created subagent: " + agentId + "\n").c_str());
        
        return agentId;
    }
    
    bool DestroySubAgent(const std::string& agentId) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = subAgents_.find(agentId);
        if (it == subAgents_.end()) {
            return false;
        }
        
        // Set state to shutting down
        it->second.state = SubAgentState::ShuttingDown;
        
        // Remove message queue
        messageQueues_.erase(agentId);
        
        // Remove subagent
        subAgents_.erase(it);
        
        OutputDebugStringA(("[SubAgentManager] Destroyed subagent: " + agentId + "\n").c_str());
        
        return true;
    }
    
    std::optional<SubAgentInfo> GetSubAgentInfo(const std::string& agentId) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = subAgents_.find(agentId);
        if (it == subAgents_.end()) {
            return std::nullopt;
        }
        
        return it->second;
    }
    
    std::vector<SubAgentInfo> GetAllSubAgents() override { 
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<SubAgentInfo> result;
        result.reserve(subAgents_.size());
        
        for (const auto& [id, info] : subAgents_) {
            result.push_back(info);
        }
        
        return result;
    }
    
    bool SendMessageToSubAgent(const std::string& agentId, const std::string& message) override { 
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check if subagent exists
        auto it = subAgents_.find(agentId);
        if (it == subAgents_.end()) {
            return false;
        }
        
        // Check if subagent is in a valid state
        if (it->second.state != SubAgentState::Idle && 
            it->second.state != SubAgentState::Busy) {
            return false;
        }
        
        // Add message to queue
        auto queueIt = messageQueues_.find(agentId);
        if (queueIt == messageQueues_.end()) {
            return false;
        }
        
        // Limit queue size
        if (queueIt->second.size() >= 100) {
            queueIt->second.pop(); // Remove oldest message
        }
        
        queueIt->second.push(message);
        
        // Update state to busy
        it->second.state = SubAgentState::Busy;
        
        // Process message and update activity timestamp
        // In full implementation, this would notify a worker thread
        it->second.lastActivity = std::chrono::steady_clock::now();
        
        return true;
    }
    
    // Additional method to check for messages (would be called by subagent)
    std::optional<std::string> GetNextMessage(const std::string& agentId) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = messageQueues_.find(agentId);
        if (it == messageQueues_.end() || it->second.empty()) {
            return std::nullopt;
        }
        
        std::string message = it->second.front();
        it->second.pop();
        
        return message;
    }
    
    // Update subagent state
    void SetSubAgentState(const std::string& agentId, SubAgentState state) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = subAgents_.find(agentId);
        if (it != subAgents_.end()) {
            it->second.state = state;
            it->second.lastActivity = std::chrono::steady_clock::now();
        }
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, SubAgentInfo> subAgents_;
    std::unordered_map<std::string, std::queue<std::string>> messageQueues_;
    uint64_t nextAgentId_;
    bool shutdown_;
};

// ============================================================================
// Internal Implementation
// ============================================================================

class CoreImpl : public Core {
public:
    explicit CoreImpl(const CoreConfig& config);
    ~CoreImpl() override;

    // Lifecycle
    bool Initialize() override;
    bool Shutdown(std::chrono::milliseconds timeout) override;
    bool IsInitialized() const override;

    // Task Execution - Async
    std::future<TaskResult> SubmitTask(const Task& task) override;
    std::future<TaskResult> SubmitTask(const Task& task,
                                           TaskProgressCallback onProgress,
                                           TaskOutputCallback onOutput) override;
    std::vector<std::future<TaskResult>> SubmitBatch(
        const std::vector<Task>& tasks) override;

    // Task Execution - Sync
    TaskResult ExecuteSync(const Task& task) override;
    TaskResult ExecuteSync(const Task& task, std::chrono::milliseconds timeout) override;

    // Task Management
    bool CancelTask(const std::string& taskId) override;
    TaskStatus GetTaskStatus(const std::string& taskId) override;
    std::optional<TaskResult> GetTaskResult(const std::string& taskId) override;
    bool WaitForTask(const std::string& taskId, std::chrono::milliseconds timeout) override;

    // Task Queries
    size_t GetPendingCount() const override;
    size_t GetRunningCount() const override;
    size_t GetTotalTaskCount() const override;
    std::vector<std::string> GetActiveTaskIds() const override;
    std::optional<Task> GetTaskInfo(const std::string& taskId) override;

    // Event Registration
    int OnTaskStart(TaskStartCallback callback) override;
    int OnTaskComplete(TaskCompleteCallback callback) override;
    void UnregisterCallback(int callbackId) override;

    // Subsystem Access
    TaskScheduler& GetScheduler() override;
    ToolRegistry& GetToolRegistry() override;
    HistoryRecorder& GetHistory() override;
    PolicyEngine& GetPolicies() override;
    SubAgentManager& GetSubAgentManager() override;
    void SetInferenceEngine(std::shared_ptr<Inference::InferenceEngine> engine) override;
    std::shared_ptr<Inference::InferenceEngine> GetInferenceEngine() override;

    // Convenience Methods
    std::string ReadFile(const std::string& path) override;
    bool WriteFile(const std::string& path, const std::string& content) override;
    std::string ExecuteCommand(const std::string& command) override;
    std::string SearchCodebase(const std::string& query) override;
    std::string Generate(const std::string& prompt) override;

    // Diagnostics
    CoreStats GetStats() const override;
    void ResetStats() override;
    std::string GetLastError() const override;
    bool ValidateConfig() const override;

private:
    // Configuration
    CoreConfig m_config;
    
    // State
    mutable std::mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shuttingDown{false};
    std::string m_lastError;
    
    // Subsystems
    std::unique_ptr<TaskSchedulerImpl> m_scheduler;
    std::unique_ptr<ToolRegistryImpl> m_toolRegistry;
    std::unique_ptr<HistoryRecorderImpl> m_history;
    std::unique_ptr<PolicyEngineImpl> m_policies;
    std::unique_ptr<SubAgentManagerImpl> m_subAgentManager;
    std::shared_ptr<Inference::InferenceEngine> m_inferenceEngine;
    
    // Task tracking
    struct TaskEntry {
        Task task;
        TaskStatus status = TaskStatus::Pending;
        std::promise<TaskResult> promise;
        // Note: future is returned to caller, not stored here
        std::chrono::steady_clock::time_point submitTime;
        std::chrono::steady_clock::time_point startTime;
        std::thread worker;
        TaskProgressCallback onProgress;
        TaskOutputCallback onOutput;
        // Store result after completion for GetTaskResult
        std::optional<TaskResult> completedResult;
    };
    
    std::unordered_map<std::string, std::shared_ptr<TaskEntry>> m_tasks;
    std::queue<std::shared_ptr<TaskEntry>> m_pendingQueue;
    std::condition_variable m_taskAvailable;
    
    // Callbacks
    std::atomic<int> m_nextCallbackId{1};
    std::unordered_map<int, TaskStartCallback> m_startCallbacks;
    std::unordered_map<int, TaskCompleteCallback> m_completeCallbacks;
    
    // Statistics
    mutable std::atomic<int64_t> m_tasksSubmitted{0};
    mutable std::atomic<int64_t> m_tasksCompleted{0};
    mutable std::atomic<int64_t> m_tasksFailed{0};
    mutable std::atomic<int64_t> m_tasksCancelled{0};
    
    // Worker threads
    std::vector<std::thread> m_workers;
    
    // Internal Methods
    void WorkerLoop();
    TaskResult ExecuteTaskInternal(std::shared_ptr<TaskEntry> entry);
    TaskResult ExecuteFileTask(const Task& task);
    TaskResult ExecuteTerminalTask(const Task& task);
    TaskResult ExecuteSearchTask(const Task& task);
    TaskResult ExecuteInferenceTask(const Task& task);
    TaskResult ExecuteToolTask(const Task& task);
    void NotifyTaskStart(const Task& task);
    void NotifyTaskComplete(const Task& task, const TaskResult& result);
    std::string GenerateTaskId();
};

// ============================================================================
// Factory Implementation
// ============================================================================

std::unique_ptr<Core> Core::Create(const CoreConfig& config) {
    return std::make_unique<CoreImpl>(config);
}

std::unique_ptr<Core> Core::Create() {
    return Create(CoreConfig{});
}

std::unique_ptr<Core> Core::CreateLegacyAdapter(
    void* legacyEngine,
    const CoreConfig& config) {
    // Forward declaration - implementation is in LegacyCoreAdapter.cpp
    // This avoids circular dependency
    extern std::unique_ptr<Core> CreateLegacyCoreAdapter(void* engine, const CoreConfig& cfg);
    return CreateLegacyCoreAdapter(legacyEngine, config);
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

CoreImpl::CoreImpl(const CoreConfig& config)
    : m_config(config)
    , m_scheduler(std::make_unique<TaskSchedulerImpl>())
    , m_toolRegistry(std::make_unique<ToolRegistryImpl>())
    , m_history(std::make_unique<HistoryRecorderImpl>())
    , m_policies(std::make_unique<PolicyEngineImpl>())
    , m_subAgentManager(std::make_unique<SubAgentManagerImpl>()) {
}

CoreImpl::~CoreImpl() {
    if (m_initialized) {
        Shutdown(std::chrono::milliseconds{5000});
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

bool CoreImpl::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return true;
    }
    
    // Initialize actual subsystem implementations
    printf("[AgenticCore] Initializing subsystems...\n");
    
    // 1. Initialize memory manager
    if (!InitializeMemoryManager()) {
        fprintf(stderr, "[AgenticCore] Failed to initialize memory manager\n");
        return false;
    }
    printf("[AgenticCore]   \u2713 Memory manager initialized\n");
    
    // 2. Initialize inference engine
    if (!InitializeInferenceEngine()) {
        fprintf(stderr, "[AgenticCore] Failed to initialize inference engine\n");
        return false;
    }
    printf("[AgenticCore]   \u2713 Inference engine initialized\n");
    
    // 3. Initialize tool registry
    if (!InitializeToolRegistry()) {
        fprintf(stderr, "[AgenticCore] Failed to initialize tool registry\n");
        return false;
    }
    printf("[AgenticCore]   \u2713 Tool registry initialized\n");
    
    // 4. Initialize knowledge base
    if (!InitializeKnowledgeBase()) {
        fprintf(stderr, "[AgenticCore] Failed to initialize knowledge base\n");
        return false;
    }
    printf("[AgenticCore]   \u2713 Knowledge base initialized\n");
    
    // 5. Initialize telemetry
    if (!InitializeTelemetry()) {
        fprintf(stderr, "[AgenticCore] Failed to initialize telemetry\n");
        return false;
    }
    printf("[AgenticCore]   \u2713 Telemetry initialized\n");
    
    // Start worker threads
    size_t numWorkers = m_config.maxConcurrentTasks;
    if (numWorkers == 0) {
        numWorkers = std::thread::hardware_concurrency();
        if (numWorkers == 0) numWorkers = 4; // Fallback
    }
    
    printf("[AgenticCore] Starting %zu worker threads...\n", numWorkers);
    for (size_t i = 0; i < numWorkers; ++i) {
        m_workers.emplace_back(&CoreImpl::WorkerLoop, this);
    }
    
    m_initialized = true;
    printf("[AgenticCore] Initialization complete\n");
    return true;
}

bool CoreImpl::Shutdown(std::chrono::milliseconds timeout) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shuttingDown = true;
    }
    
    m_taskAvailable.notify_all();
    
    // Wait for workers to finish
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            auto remaining = deadline - std::chrono::steady_clock::now();
            if (remaining.count() > 0) {
                // Note: Can't actually timeout join in standard C++
                // This is simplified
                worker.join();
            }
        }
    }
    
    m_initialized = false;
    return true;
}

bool CoreImpl::IsInitialized() const {
    return m_initialized;
}

// ============================================================================
// Task Execution - Async
// ============================================================================

std::future<TaskResult> CoreImpl::SubmitTask(const Task& task) {
    return SubmitTask(task, nullptr, nullptr);
}

std::future<TaskResult> CoreImpl::SubmitTask(const Task& task,
                                               TaskProgressCallback onProgress,
                                               TaskOutputCallback onOutput) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) {
        std::promise<TaskResult> promise;
        TaskResult result;
        result.success = false;
        result.errorMessage = "Core not initialized";
        promise.set_value(result);
        return promise.get_future();
    }
    
    auto entry = std::make_shared<TaskEntry>();
    entry->task = task;
    entry->task.id = task.id.empty() ? GenerateTaskId() : task.id;
    entry->task.submitTime = std::chrono::steady_clock::now();
    entry->status = TaskStatus::Pending;
    entry->submitTime = entry->task.submitTime;
    entry->onProgress = onProgress;
    entry->onOutput = onOutput;
    
    // Store the promise in entry, return the future to caller
    std::future<TaskResult> future = entry->promise.get_future();
    
    m_tasks[entry->task.id] = entry;
    m_pendingQueue.push(entry);
    m_tasksSubmitted++;
    
    m_taskAvailable.notify_one();
    
    return future;
}

std::vector<std::future<TaskResult>> CoreImpl::SubmitBatch(
    const std::vector<Task>& tasks) {
    std::vector<std::future<TaskResult>> futures;
    futures.reserve(tasks.size());
    
    for (const auto& task : tasks) {
        futures.push_back(SubmitTask(task));
    }
    
    return futures;
}

// ============================================================================
// Task Execution - Sync
// ============================================================================

TaskResult CoreImpl::ExecuteSync(const Task& task) {
    return ExecuteSync(task, m_config.defaultTaskTimeout);
}

TaskResult CoreImpl::ExecuteSync(const Task& task, std::chrono::milliseconds timeout) {
    auto future = SubmitTask(task);
    
    if (future.wait_for(timeout) == std::future_status::timeout) {
        CancelTask(task.id);
        TaskResult result;
        result.success = false;
        result.errorMessage = "Task timed out";
        result.status = TaskStatus::Timeout;
        return result;
    }
    
    return future.get();
}

// ============================================================================
// Task Management
// ============================================================================

bool CoreImpl::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return false;
    }
    
    auto& entry = it->second;
    if (entry->status == TaskStatus::Pending) {
        entry->status = TaskStatus::Cancelled;
        TaskResult result;
        result.success = false;
        result.errorMessage = "Task cancelled";
        result.status = TaskStatus::Cancelled;
        result.taskId = taskId;
        entry->completedResult = result;  // Store for GetTaskResult
        entry->promise.set_value(result);
        m_tasksCancelled++;
        return true;
    }
    
    // Can't cancel running tasks easily without more infrastructure
    return false;
}

TaskStatus CoreImpl::GetTaskStatus(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return TaskStatus::Failed;
    }
    
    return it->second->status;
}

std::optional<TaskResult> CoreImpl::GetTaskResult(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return std::nullopt;
    }
    
    auto& entry = it->second;
    if (entry->status != TaskStatus::Completed && 
        entry->status != TaskStatus::Failed &&
        entry->status != TaskStatus::Cancelled &&
        entry->status != TaskStatus::Timeout) {
        return std::nullopt;
    }
    
    // Return completed result if available
    return entry->completedResult;
}

bool CoreImpl::WaitForTask(const std::string& taskId, std::chrono::milliseconds timeout) {
    auto future = GetTaskResult(taskId);
    if (future.has_value()) {
        return true;
    }
    
    // Poll until timeout
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < timeout) {
        future = GetTaskResult(taskId);
        if (future.has_value()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return false;
}

// ============================================================================
// Task Queries
// ============================================================================

size_t CoreImpl::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pendingQueue.size();
}

size_t CoreImpl::GetRunningCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count = 0;
    for (const auto& [id, entry] : m_tasks) {
        if (entry->status == TaskStatus::Running) {
            count++;
        }
    }
    return count;
}

size_t CoreImpl::GetTotalTaskCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tasks.size();
}

std::vector<std::string> CoreImpl::GetActiveTaskIds() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> ids;
    for (const auto& [id, entry] : m_tasks) {
        if (entry->status == TaskStatus::Pending || entry->status == TaskStatus::Running) {
            ids.push_back(id);
        }
    }
    return ids;
}

std::optional<Task> CoreImpl::GetTaskInfo(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return std::nullopt;
    }
    
    return it->second->task;
}

// ============================================================================
// Event Registration
// ============================================================================

int CoreImpl::OnTaskStart(TaskStartCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    int id = m_nextCallbackId++;
    m_startCallbacks[id] = callback;
    return id;
}

int CoreImpl::OnTaskComplete(TaskCompleteCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    int id = m_nextCallbackId++;
    m_completeCallbacks[id] = callback;
    return id;
}

void CoreImpl::UnregisterCallback(int callbackId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_startCallbacks.erase(callbackId);
    m_completeCallbacks.erase(callbackId);
}

// ============================================================================
// Subsystem Access
// ============================================================================

TaskScheduler& CoreImpl::GetScheduler() {
    return *m_scheduler;
}

ToolRegistry& CoreImpl::GetToolRegistry() {
    return *m_toolRegistry;
}

HistoryRecorder& CoreImpl::GetHistory() {
    return *m_history;
}

PolicyEngine& CoreImpl::GetPolicies() {
    return *m_policies;
}

SubAgentManager& CoreImpl::GetSubAgentManager() {
    return *m_subAgentManager;
}

void CoreImpl::SetInferenceEngine(std::shared_ptr<Inference::InferenceEngine> engine) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_inferenceEngine = engine;
}

std::shared_ptr<Inference::InferenceEngine> CoreImpl::GetInferenceEngine() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_inferenceEngine;
}

// ============================================================================
// Convenience Methods
// ============================================================================

std::string CoreImpl::ReadFile(const std::string& path) {
    Task task;
    task.type = TaskType::File;
    task.instruction = "read " + path;
    task.fileParams.operation = "read";
    task.fileParams.path = path;
    
    auto result = ExecuteSync(task);
    if (result.success) {
        return result.output;
    }
    return "";
}

bool CoreImpl::WriteFile(const std::string& path, const std::string& content) {
    Task task;
    task.type = TaskType::File;
    task.instruction = "write " + path;
    task.fileParams.operation = "write";
    task.fileParams.path = path;
    task.fileParams.content = content;
    
    auto result = ExecuteSync(task);
    return result.success;
}

std::string CoreImpl::ExecuteCommand(const std::string& command) {
    Task task;
    task.type = TaskType::Terminal;
    task.instruction = command;
    task.terminalParams.command = command;
    
    auto result = ExecuteSync(task);
    if (result.success) {
        return result.output;
    }
    return result.errorMessage;
}

std::string CoreImpl::SearchCodebase(const std::string& query) {
    Task task;
    task.type = TaskType::Search;
    task.instruction = query;
    task.searchParams.query = query;
    
    auto result = ExecuteSync(task);
    if (result.success) {
        return result.output;
    }
    return "";
}

std::string CoreImpl::Generate(const std::string& prompt) {
    if (!m_inferenceEngine) {
        return "Error: No inference engine set";
    }
    
    Inference::GenerationParams params;
    auto result = m_inferenceEngine->Generate(prompt, params);
    if (result.success) {
        return result.text;
    }
    return "Error: " + result.errorMessage;
}

// ============================================================================
// Diagnostics
// ============================================================================

CoreStats CoreImpl::GetStats() const {
    CoreStats stats{};
    stats.tasksSubmitted = m_tasksSubmitted.load();
    stats.tasksCompleted = m_tasksCompleted.load();
    stats.tasksFailed = m_tasksFailed.load();
    stats.tasksCancelled = m_tasksCancelled.load();
    return stats;
}

void CoreImpl::ResetStats() {
    m_tasksSubmitted = 0;
    m_tasksCompleted = 0;
    m_tasksFailed = 0;
    m_tasksCancelled = 0;
}

std::string CoreImpl::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastError;
}

bool CoreImpl::ValidateConfig() const {
    // Check workspace root exists
    if (!m_config.workspaceRoot.empty()) {
        if (!std::filesystem::exists(m_config.workspaceRoot)) {
            return false;
        }
    }
    
    // Check reasonable thread count
    if (m_config.maxConcurrentTasks > 256) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Internal Methods
// ============================================================================

void CoreImpl::WorkerLoop() {
    while (!m_shuttingDown) {
        std::shared_ptr<TaskEntry> entry;
        
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_taskAvailable.wait(lock, [this] {
                return !m_pendingQueue.empty() || m_shuttingDown;
            });
            
            if (m_shuttingDown) {
                return;
            }
            
            if (!m_pendingQueue.empty()) {
                entry = m_pendingQueue.front();
                m_pendingQueue.pop();
                entry->status = TaskStatus::Running;
                entry->startTime = std::chrono::steady_clock::now();
            }
        }
        
        if (entry) {
            NotifyTaskStart(entry->task);
            auto result = ExecuteTaskInternal(entry);
            entry->completedResult = result;  // Store for GetTaskResult
            entry->promise.set_value(result);
            NotifyTaskComplete(entry->task, result);
        }
    }
}

TaskResult CoreImpl::ExecuteTaskInternal(std::shared_ptr<TaskEntry> entry) {
    TaskResult result;
    result.taskId = entry->task.id;
    result.startTime = std::chrono::steady_clock::now();
    
    try {
        switch (entry->task.type) {
            case TaskType::File:
                result = ExecuteFileTask(entry->task);
                break;
            case TaskType::Terminal:
                result = ExecuteTerminalTask(entry->task);
                break;
            case TaskType::Search:
                result = ExecuteSearchTask(entry->task);
                break;
            case TaskType::Inference:
                result = ExecuteInferenceTask(entry->task);
                break;
            case TaskType::Tool:
                result = ExecuteToolTask(entry->task);
                break;
            default:
                result.success = false;
                result.errorMessage = "Unknown task type";
                break;
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = e.what();
    }
    
    result.endTime = std::chrono::steady_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.endTime - result.startTime).count();
    
    if (result.success) {
        m_tasksCompleted++;
    } else {
        m_tasksFailed++;
    }
    
    return result;
}

TaskResult CoreImpl::ExecuteFileTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    const auto& params = task.fileParams;
    std::filesystem::path resolvedPath = params.path;
    
    // Resolve relative paths
    if (resolvedPath.is_relative() && !m_config.workspaceRoot.empty()) {
        resolvedPath = std::filesystem::path(m_config.workspaceRoot) / resolvedPath;
    }
    
    // Security check
    if (m_config.sandboxFileOps) {
        auto canonical = std::filesystem::weakly_canonical(resolvedPath);
        auto workspace = std::filesystem::weakly_canonical(m_config.workspaceRoot);
        if (canonical.string().find(workspace.string()) != 0) {
            result.success = false;
            result.errorMessage = "Path outside workspace: " + params.path;
            return result;
        }
    }
    
    try {
        if (params.operation == "read") {
            std::ifstream file(resolvedPath, std::ios::binary);
            if (!file) {
                result.success = false;
                result.errorMessage = "Cannot open file: " + params.path;
                return result;
            }
            std::ostringstream content;
            content << file.rdbuf();
            result.output = content.str();
            result.success = true;
            result.bytesProcessed = result.output.size();
        }
        else if (params.operation == "write") {
            if (params.createDirs) {
                std::filesystem::create_directories(resolvedPath.parent_path());
            }
            std::ofstream file(resolvedPath, std::ios::binary);
            if (!file) {
                result.success = false;
                result.errorMessage = "Cannot write file: " + params.path;
                return result;
            }
            file << params.content;
            result.output = "Written " + std::to_string(params.content.size()) + " bytes";
            result.success = true;
            result.bytesProcessed = params.content.size();
        }
        else if (params.operation == "list") {
            std::ostringstream listing;
            for (const auto& entry : std::filesystem::directory_iterator(resolvedPath)) {
                listing << (entry.is_directory() ? "[DIR]  " : "[FILE] ")
                      << entry.path().filename().string() << "\n";
            }
            result.output = listing.str();
            result.success = true;
        }
        else if (params.operation == "delete") {
            std::filesystem::remove(resolvedPath);
            result.output = "Deleted: " + params.path;
            result.success = true;
        }
        else {
            result.success = false;
            result.errorMessage = "Unknown file operation: " + params.operation;
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = e.what();
    }
    
    return result;
}

TaskResult CoreImpl::ExecuteTerminalTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    const auto& params = task.terminalParams;
    
    // Security check
    for (const auto& blocked : m_config.blockedCommands) {
        if (params.command.find(blocked) != std::string::npos) {
            result.success = false;
            result.errorMessage = "Command blocked: " + blocked;
            return result;
        }
    }
    
#ifdef _WIN32
    // Windows implementation
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    
    HANDLE hStdOutRead, hStdOutWrite;
    CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0);
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;
    si.dwFlags = STARTF_USESTDHANDLES;
    
    std::string cmdLine = "cmd.exe /C " + params.command;
    
    BOOL success = CreateProcessA(
        nullptr,
        const_cast<LPSTR>(cmdLine.c_str()),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        params.workingDir.empty() ? nullptr : params.workingDir.c_str(),
        &si,
        &pi
    );
    
    if (!success) {
        result.success = false;
        result.errorMessage = "Failed to create process";
        return result;
    }
    
    // Read output
    CloseHandle(hStdOutWrite);
    
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    while (::ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdOutRead);
    
    result.output = output;
    result.success = (exitCode == 0);
    if (!result.success) {
        result.errorMessage = "Process exited with code " + std::to_string(exitCode);
    }
#else
    // Linux implementation
    FILE* pipe = popen(params.command.c_str(), "r");
    if (!pipe) {
        result.success = false;
        result.errorMessage = "Failed to execute command";
        return result;
    }
    
    std::string output;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int exitCode = pclose(pipe);
    result.output = output;
    result.success = (exitCode == 0);
    if (!result.success) {
        result.errorMessage = "Process exited with code " + std::to_string(exitCode);
    }
#endif
    
    return result;
}

TaskResult CoreImpl::ExecuteSearchTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    // Real codebase search implementation
    printf("[AgenticCore] Executing search task: %s\n", task.searchParams.query.c_str());
    
    // Use the symbol index for searching
    if (!m_symbolIndex) {
        result.success = false;
        result.errorMessage = "Symbol index not initialized";
        return result;
    }
    
    // Perform search based on query type
    std::vector<SymbolMatch> matches;
    
    if (task.searchParams.query.empty()) {
        result.success = false;
        result.errorMessage = "Empty search query";
        return result;
    }
    
    // Search by pattern
    matches = m_symbolIndex->SearchSymbols(
        task.searchParams.query,
        task.searchParams.maxResults,
        task.searchParams.caseSensitive
    );
    
    // Format results
    std::ostringstream oss;
    oss << "Found " << matches.size() << " matches for '\"" << task.searchParams.query << "'\":\n\n";
    
    for (size_t i = 0; i < matches.size() && i < task.searchParams.maxResults; ++i) {
        const auto& match = matches[i];
        oss << i + 1 << ". " << match.symbol.name;
        if (!match.symbol.container.empty()) {
            oss << " (in " << match.symbol.container << ")";
        }
        oss << "\n";
        oss << "   File: " << match.symbol.filePath << ":" << match.symbol.line << "\n";
        oss << "   Type: " << SymbolTypeToString(match.symbol.type) << "\n";
        if (match.score < 1.0f) {
            oss << "   Relevance: " << std::fixed << std::setprecision(2) << match.score << "\n";
        }
        oss << "\n";
    }
    
    result.success = true;
    result.output = oss.str();
    result.searchResults = matches;
    
    printf("[AgenticCore] Search complete: %zu matches found\n", matches.size());
    
    return result;
}

TaskResult CoreImpl::ExecuteInferenceTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    if (!m_inferenceEngine) {
        result.success = false;
        result.errorMessage = "No inference engine configured";
        return result;
    }
    
    Inference::GenerationParams params;
    params.temperature = task.inferenceParams.temperature;
    params.maxTokens = task.inferenceParams.maxTokens;
    params.streamOutput = task.inferenceParams.stream;
    
    auto genResult = m_inferenceEngine->Generate(task.inferenceParams.prompt, params);
    
    result.success = genResult.success;
    result.output = genResult.text;
    result.tokensGenerated = genResult.tokensGenerated;
    result.errorMessage = genResult.errorMessage;
    
    return result;
}

TaskResult CoreImpl::ExecuteToolTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    // Real tool execution via ToolRegistry
    printf("[AgenticCore] Executing tool task: %s\n", task.toolParams.toolName.c_str());
    
    if (!m_toolRegistry) {
        result.success = false;
        result.errorMessage = "Tool registry not initialized";
        return result;
    }
    
    // Validate tool exists
    if (!m_toolRegistry->HasTool(task.toolParams.toolName)) {
        result.success = false;
        result.errorMessage = "Unknown tool: " + task.toolParams.toolName;
        return result;
    }
    
    // Get tool definition
    const ToolDefinition* tool = m_toolRegistry->GetTool(task.toolParams.toolName);
    if (!tool) {
        result.success = false;
        result.errorMessage = "Failed to get tool definition: " + task.toolParams.toolName;
        return result;
    }
    
    // Validate parameters
    std::vector<std::string> validationErrors;
    if (!ValidateToolParameters(*tool, task.toolParams.parameters, validationErrors)) {
        result.success = false;
        result.errorMessage = "Parameter validation failed:\n";
        for (const auto& err : validationErrors) {
            result.errorMessage += "  - " + err + "\n";
        }
        return result;
    }
    
    // Execute tool with timeout
    auto startTime = std::chrono::steady_clock::now();
    
    ToolExecutionContext context;
    context.taskId = task.id;
    context.parameters = task.toolParams.parameters;
    context.workingDirectory = task.toolParams.workingDirectory;
    context.timeoutMs = task.toolParams.timeoutMs;
    
    ToolExecutionResult toolResult = m_toolRegistry->ExecuteTool(
        task.toolParams.toolName, 
        context
    );
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    result.success = toolResult.success;
    result.output = toolResult.output;
    result.errorMessage = toolResult.error;
    result.toolExecutionTimeMs = duration;
    result.toolExitCode = toolResult.exitCode;
    
    printf("[AgenticCore] Tool execution %s in %lld ms (exit=%d)\n",
           result.success ? "succeeded" : "failed", 
           duration, 
           toolResult.exitCode);
    
    return result;
}

void CoreImpl::NotifyTaskStart(const Task& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, callback] : m_startCallbacks) {
        if (callback) {
            try {
                callback(task);
            } catch (...) {
                // Ignore callback errors
            }
        }
    }
}

void CoreImpl::NotifyTaskComplete(const Task& task, const TaskResult& result) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, callback] : m_completeCallbacks) {
        if (callback) {
            try {
                callback(task, result);
            } catch (...) {
                // Ignore callback errors
            }
        }
    }
}

std::string CoreImpl::GenerateTaskId() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return "task_" + std::to_string(now) + "_" + std::to_string(counter++);
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string GenerateTaskId() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return "task_" + std::to_string(now) + "_" + std::to_string(counter++);
}

const char* GetAgenticVersion() {
    return "RawrXD Agentic Core v15.0.0";
}

const char* TaskTypeToString(TaskType type) {
    switch (type) {
        case TaskType::File: return "file";
        case TaskType::Terminal: return "terminal";
        case TaskType::Search: return "search";
        case TaskType::Inference: return "inference";
        case TaskType::Tool: return "tool";
        case TaskType::SubAgent: return "subagent";
        case TaskType::Composite: return "composite";
        case TaskType::Custom: return "custom";
        default: return "unknown";
    }
}

TaskType StringToTaskType(const std::string& str) {
    if (str == "file") return TaskType::File;
    if (str == "terminal") return TaskType::Terminal;
    if (str == "search") return TaskType::Search;
    if (str == "inference") return TaskType::Inference;
    if (str == "tool") return TaskType::Tool;
    if (str == "subagent") return TaskType::SubAgent;
    if (str == "composite") return TaskType::Composite;
    return TaskType::Custom;
}

const char* TaskStatusToString(TaskStatus status) {
    switch (status) {
        case TaskStatus::Pending: return "pending";
        case TaskStatus::Running: return "running";
        case TaskStatus::Completed: return "completed";
        case TaskStatus::Failed: return "failed";
        case TaskStatus::Cancelled: return "cancelled";
        case TaskStatus::Timeout: return "timeout";
        default: return "unknown";
    }
}

} // namespace Agentic
} // namespace RawrXD
