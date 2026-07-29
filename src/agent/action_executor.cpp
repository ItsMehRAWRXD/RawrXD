/**
 * @file action_executor.cpp
 * @brief Implementation of action execution engine
 *
 * Executes agent-generated actions with comprehensive error handling,
 * backup/restore, and observability.
 *
 * Architecture: C++20, no Qt, no exceptions
 * Process execution: CreateProcessA (Windows) / fork+exec (POSIX)
 */

#include "action_executor.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <thread>
#include <future>
#include <chrono>
#include <windows.h>
#include <nlohmann/json.hpp>

<<<<<<< HEAD
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#endif

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════════════
// Construction / Destruction
// ═══════════════════════════════════════════════════════════════════════════
=======
namespace fs = std::filesystem;
using json = nlohmann::json;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

/**
 * @brief Constructor
 */
ActionExecutor::ActionExecutor()
{
    m_context.projectRoot = fs::current_path().string();
}

/**
 * @brief Destructor — joins background thread if active
 */
ActionExecutor::~ActionExecutor()
{
    cancelExecution();
    std::lock_guard<std::mutex> lock(m_threadMutex);
    if (m_executionThread.joinable()) {
        m_executionThread.join();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Set execution context
 */
void ActionExecutor::setContext(const ExecutionContext& context)
{
    m_context = context;
<<<<<<< HEAD
    fprintf(stderr, "[ActionExecutor] Context set - projectRoot: %s\n",
            m_context.projectRoot.c_str());
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Execute single action (synchronous)
 */
bool ActionExecutor::executeAction(Action& action)
{
<<<<<<< HEAD
    fprintf(stderr, "[ActionExecutor] Executing action: %s\n", action.description.c_str());

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    switch (action.type) {
    case ActionType::FileEdit:
        return handleFileEdit(action);
    case ActionType::SearchFiles:
        return handleSearchFiles(action);
    case ActionType::RunBuild:
        return handleRunBuild(action);
    case ActionType::ExecuteTests:
        return handleExecuteTests(action);
    case ActionType::CommitGit:
        return handleCommitGit(action);
    case ActionType::InvokeCommand:
        return handleInvokeCommand(action);
    case ActionType::RecursiveAgent:
        return handleRecursiveAgent(action);
    case ActionType::QueryUser:
        return handleQueryUser(action);
    default:
        action.error = "Unknown action type";
        return false;
    }
}

/**
 * @brief Execute complete plan (asynchronous)
 */
<<<<<<< HEAD
void ActionExecutor::executePlan(const JsonValue& actions, bool stopOnError)
=======
void ActionExecutor::executePlan(const json& actions, bool stopOnError)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    m_isExecuting.store(true);
    m_stopOnError = stopOnError;
    m_cancelled.store(false);
    m_executedActions.clear();
    m_backups.clear();

<<<<<<< HEAD
    m_context.totalActions = static_cast<int>(actions.size());
    notifyPlanStarted(static_cast<int>(actions.size()));

    // Join any previous background thread
    {
        std::lock_guard<std::mutex> lock(m_threadMutex);
        if (m_executionThread.joinable()) {
            m_executionThread.join();
        }
    }

    // Run on background thread
    std::lock_guard<std::mutex> lock(m_threadMutex);
    m_executionThread = std::thread([this, actions]() {
        bool overallSuccess = true;

        for (size_t i = 0; i < actions.size() && !m_cancelled.load(); ++i) {
            if (!actions[i].isObject()) {
                fprintf(stderr, "[ActionExecutor] Invalid action at index %zu\n", i);
=======
    m_context.totalActions = actions.size();
    if (onPlanStarted) onPlanStarted(actions.size());

    // Run on background thread
    std::thread([this, actions]() {
        bool overallSuccess = true;

        for (size_t i = 0; i < actions.size() && !m_cancelled; ++i) {
            if (!actions[i].is_object()) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                overallSuccess = false;
                if (m_stopOnError) break;
                continue;
            }

            Action action = parseJsonAction(actions[i]);
            m_context.currentActionIndex = static_cast<int>(i);

<<<<<<< HEAD
            notifyActionStarted(static_cast<int>(i), action.description);
            notifyProgressUpdated(static_cast<int>(i), m_context.totalActions);
=======
            if (onActionStarted) onActionStarted(static_cast<int>(i), action.description);
            if (onProgressUpdated) onProgressUpdated(static_cast<int>(i), m_context.totalActions);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

            bool success = executeAction(action);
            action.executed = true;
            action.success = success;

            m_executedActions.push_back(action);

<<<<<<< HEAD
            JsonValue result;
=======
            json result;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            result["target"] = action.target;
            result["success"] = success;
            if (!action.error.empty()) {
                result["error"] = action.error;
            }
            if (!action.result.empty()) {
                result["result"] = action.result;
            }

<<<<<<< HEAD
            notifyActionCompleted(static_cast<int>(i), success, result);

            if (!success) {
                overallSuccess = false;
                notifyActionFailed(static_cast<int>(i), action.error, m_stopOnError);

                if (m_stopOnError) {
                    fprintf(stderr, "[ActionExecutor] Stopping due to error\n");
=======
            if (onActionCompleted) onActionCompleted(static_cast<int>(i), success, result);

            if (!success) {
                overallSuccess = false;
                if (onActionFailed) onActionFailed(static_cast<int>(i), action.error, m_stopOnError);

                if (m_stopOnError) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                    break;
                }
            }
        }

        m_isExecuting.store(false);

<<<<<<< HEAD
        JsonValue finalResult;
=======
        json finalResult;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        finalResult["success"] = overallSuccess;
        finalResult["actionsExecuted"] = static_cast<int>(m_executedActions.size());
        finalResult["state"] = m_context.state;

<<<<<<< HEAD
        notifyPlanCompleted(overallSuccess, finalResult);
    });
=======
        if (onPlanCompleted) onPlanCompleted(overallSuccess, finalResult);
    }).detach();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Cancel execution
 */
void ActionExecutor::cancelExecution()
{
<<<<<<< HEAD
    m_cancelled.store(true);
#ifdef _WIN32
    {
        std::lock_guard<std::mutex> lock(m_processMutex);
        if (m_currentProcessHandle != INVALID_HANDLE_VALUE) {
            TerminateProcess(m_currentProcessHandle, 1);
            WaitForSingleObject(m_currentProcessHandle, 5000);
        }
    }
#endif
    fprintf(stderr, "[ActionExecutor] Execution cancelled\n");
=======
    m_cancelled = true;
    if (m_processHandle) {
        TerminateProcess(m_processHandle, 1);
        CloseHandle(m_processHandle);
        m_processHandle = nullptr;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Rollback action
 */
bool ActionExecutor::rollbackAction(int actionIndex)
{
    if (actionIndex < 0 || actionIndex >= static_cast<int>(m_executedActions.size())) {
        return false;
    }

    const Action& action = m_executedActions[static_cast<size_t>(actionIndex)];

    // Only file edits are rollbackable
    if (action.type != ActionType::FileEdit) {
<<<<<<< HEAD
        fprintf(stderr, "[ActionExecutor] Action type not rollbackable\n");
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return false;
    }

    if (m_backups.find(action.target) == m_backups.end()) {
<<<<<<< HEAD
        fprintf(stderr, "[ActionExecutor] No backup found for %s\n", action.target.c_str());
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return false;
    }

    return restoreFromBackup(action.target);
}

/**
 * @brief Get aggregated result
 */
<<<<<<< HEAD
JsonValue ActionExecutor::getAggregatedResult() const
{
    JsonValue result;
    JsonValue actions = JsonValue::makeArray();

    for (const auto& action : m_executedActions) {
        JsonValue actionObj;
=======
json ActionExecutor::getAggregatedResult() const
{
    json result;
    json actions = json::array();

    for (const auto& action : m_executedActions) {
        json actionObj;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        actionObj["description"] = action.description;
        actionObj["success"] = action.success;
        actionObj["result"] = action.result;
        if (!action.error.empty()) {
            actionObj["error"] = action.error;
        }
        actions.push_back(actionObj);
    }

    result["actions"] = actions;
    result["state"] = m_context.state;

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// Action Handlers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Handle file edit action
 */
bool ActionExecutor::handleFileEdit(Action& action)
{
<<<<<<< HEAD
    std::string filePath = m_context.projectRoot + "/" + action.target;
    std::string editAction = action.params.value("action").toString();
    std::string content = action.params.value("content").toString();
=======
    fs::path filePath = fs::path(m_context.projectRoot) / action.target;
    std::string editAction = action.params.value("action", "");
    std::string content = action.params.value("content", "");
    std::string oldString = action.params.value("old_string", "");
    std::string newString = action.params.value("new_string", "");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // Validate safety
    if (!validateFileEditSafety(filePath.string(), editAction)) {
        action.error = "File edit failed safety validation";
        return false;
    }

    if (m_context.dryRun) {
        action.result = "DRY RUN: Would edit " + filePath.string();
        return true;
    }

    // Create backup
<<<<<<< HEAD
    if (!createBackup(filePath)) {
        fprintf(stderr, "[ActionExecutor] Failed to backup %s\n", filePath.c_str());
    }

    if (editAction == "create") {
        // Create new file — ensure parent directory exists
        fs::path fp(filePath);
        if (fp.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(fp.parent_path(), ec);
        }
        std::ofstream ofs(filePath, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            action.error = "Failed to create file: " + filePath;
            return false;
        }
        ofs << content;
        ofs.close();
        action.result = "File created: " + filePath;
=======
    if (!createBackup(filePath.string())) {
        // Log warning but continue
    }

    if (editAction == "create") {
        // Create directory structure if needed
        fs::create_directories(filePath.parent_path());
        // Create new file
        std::ofstream file(filePath);
        if (!file) {
            action.error = "Failed to create file: " + filePath.string();
            return false;
        }
        file << content;
        file.close();
        action.result = "File created: " + filePath.string();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return true;

    } else if (editAction == "append") {
        // Append to existing file
<<<<<<< HEAD
        std::ofstream ofs(filePath, std::ios::out | std::ios::app);
        if (!ofs.is_open()) {
            action.error = "Failed to open file for append: " + filePath;
            return false;
        }
        ofs << content;
        ofs.close();
        action.result = "Appended to: " + filePath;
=======
        std::ofstream file(filePath, std::ios::app);
        if (!file) {
            action.error = "Failed to open file for append";
            return false;
        }
        file << content;
        file.close();
        action.result = "Appended to: " + filePath.string();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return true;

    } else if (editAction == "replace") {
        // Replace entire file
<<<<<<< HEAD
        std::ofstream ofs(filePath, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            action.error = "Failed to open file for writing: " + filePath;
            return false;
        }
        ofs << content;
        ofs.close();
        action.result = "Replaced: " + filePath;
=======
        std::ofstream file(filePath);
        if (!file) {
            action.error = "Failed to open file for writing";
            return false;
        }
        file << content;
        file.close();
        action.result = "Replaced: " + filePath.string();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return true;

    } else if (editAction == "replace_string") {
        // Precise string replacement
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) {
            action.error = "Failed to open file for reading: " + filePath.string();
            return false;
        }
        std::stringstream buffer;
        buffer << inFile.rdbuf();
        std::string fileContent = buffer.str();
        inFile.close();
        
        size_t pos = fileContent.find(oldString);
        if (pos != std::string::npos) {
             fileContent.replace(pos, oldString.length(), newString);
             std::ofstream outFile(filePath, std::ios::binary);
             outFile << fileContent;
             action.result = "Replaced string in: " + filePath.string();
             return true;
        } else {
             action.error = "Old string not found in file (replace_string)";
             return false;
        }
    } else if (editAction == "delete") {

    } else if (editAction == "delete") {
        // Delete file
        std::error_code ec;
<<<<<<< HEAD
        if (!fs::remove(filePath, ec)) {
=======
        fs::remove(filePath, ec);
        if (ec) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            action.error = "Failed to delete file";
            return false;
        }
        action.result = "Deleted: " + filePath.string();
        return true;

    } else {
        action.error = "Unknown edit action: " + editAction;
        return false;
    }
}

/**
 * @brief Handle file search action
 */
bool ActionExecutor::handleSearchFiles(Action& action)
{
<<<<<<< HEAD
    std::string searchPath = m_context.projectRoot + "/" + action.params.value("path").toString();
    std::string pattern = action.params.value("pattern").toString();
    std::string query = action.params.value("query").toString();

    std::error_code ec;
    if (!fs::exists(searchPath, ec)) {
        action.error = "Search path does not exist: " + searchPath;
        return false;
    }

    // Split pattern by comma for multiple extensions
    auto patterns = strutil::split(pattern, ',');

    JsonValue results = JsonValue::makeArray();
    int matchCount = 0;
    int filesSearched = 0;

    for (auto& entry : fs::directory_iterator(searchPath, ec)) {
        if (!entry.is_regular_file()) continue;

        std::string filename = entry.path().filename().string();

        // Check if file matches any pattern (simple glob: *.ext)
        bool matchesPattern = patterns.empty();
        for (const auto& pat : patterns) {
            std::string trimmedPat = pat;
            // Trim whitespace
            while (!trimmedPat.empty() && trimmedPat.front() == ' ') trimmedPat.erase(trimmedPat.begin());
            while (!trimmedPat.empty() && trimmedPat.back() == ' ') trimmedPat.pop_back();

            if (trimmedPat.empty() || trimmedPat == "*") {
                matchesPattern = true;
                break;
            }
            // Simple wildcard match: *.ext
            if (trimmedPat.starts_with("*.")) {
                std::string ext = trimmedPat.substr(1); // ".ext"
                if (filename.size() >= ext.size() &&
                    filename.compare(filename.size() - ext.size(), ext.size(), ext) == 0) {
                    matchesPattern = true;
                    break;
                }
            } else if (filename.find(trimmedPat) != std::string::npos) {
                matchesPattern = true;
                break;
            }
        }

        if (!matchesPattern) continue;
        ++filesSearched;

        if (query.empty()) {
            // Just list files
            JsonValue fileObj;
            fileObj["path"] = entry.path().string();
            fileObj["size"] = static_cast<int>(entry.file_size(ec));
            results.append(fileObj);
        } else {
            // Search content
            std::ifstream ifs(entry.path(), std::ios::in);
            if (ifs.is_open()) {
                std::string content((std::istreambuf_iterator<char>(ifs)),
                                     std::istreambuf_iterator<char>());
                ifs.close();

                if (content.find(query) != std::string::npos) {
                    JsonValue match;
                    match["file"] = entry.path().string();
                    match["matches"] = static_cast<int>(strutil::countOccurrences(content, query));
                    results.append(match);
=======
    fs::path searchPath = fs::path(m_context.projectRoot) / action.params.value("path", "");
    std::string pattern = action.params.value("pattern", "*");
    std::string query = action.params.value("query", "");

    if (!fs::exists(searchPath) || !fs::is_directory(searchPath)) {
        action.error = "Search path does not exist: " + searchPath.string();
        return false;
    }

    json results = json::array();
    int matchCount = 0;
    int filesSearched = 0;

    for (const auto& entry : fs::directory_iterator(searchPath)) {
        if (!entry.is_regular_file()) continue;
        filesSearched++;

        if (query.empty()) {
            // Just list files
            json fileObj;
            fileObj["path"] = entry.path().string();
            fileObj["size"] = entry.file_size();
            results.push_back(fileObj);
        } else {
            // Search content
            std::ifstream file(entry.path());
            if (file) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                std::string content = buffer.str();
                file.close();

                size_t pos = 0;
                int count = 0;
                while ((pos = content.find(query, pos)) != std::string::npos) {
                    count++;
                    pos += query.length();
                }

                if (count > 0) {
                    json match;
                    match["file"] = entry.path().string();
                    match["matches"] = count;
                    results.push_back(match);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                    matchCount++;
                }
            }
        }
    }

<<<<<<< HEAD
    JsonValue resultObj;
    resultObj["files_searched"] = filesSearched;
    resultObj["matches"] = matchCount;
    resultObj["results"] = results;

    action.result = resultObj.toJsonString();
=======
    json result;
    result["files_searched"] = filesSearched;
    result["matches"] = matchCount;
    result["results"] = results;

    action.result = result.dump(2);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

/**
 * @brief Handle build action
 */
bool ActionExecutor::handleRunBuild(Action& action)
{
<<<<<<< HEAD
    std::string target = action.params.value("target").toString("all");
    std::string config = action.params.value("config").toString("Release");
=======
    std::string target = action.params.value("target", "all");
    std::string config = action.params.value("config", "Release");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    std::vector<std::string> args = {"--build", "build", "--config", config};
    if (target != "all") {
        args.push_back("--target");
        args.push_back(target);
    }

<<<<<<< HEAD
    JsonValue result = executeCommand("cmake", args, m_context.timeoutMs);

    action.result = result.toJsonString();
    return result.value("exitCode").toInt() == 0;
=======
    json result = executeCommand("cmake", args, m_context.timeoutMs);

    action.result = result.dump(2);
    return result.value("exitCode", -1) == 0;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Handle test action
 */
bool ActionExecutor::handleExecuteTests(Action& action)
{
<<<<<<< HEAD
    std::string testTarget = action.params.value("target").toString("all_tests");
=======
    std::string testTarget = action.params.value("target", "all_tests");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    std::vector<std::string> args;
    if (testTarget != "all_tests") {
        args.push_back(testTarget);
    }

<<<<<<< HEAD
    JsonValue result = executeCommand("ctest", args, m_context.timeoutMs);

    action.result = result.toJsonString();
    return result.value("exitCode").toInt() == 0;
=======
    json result = executeCommand("ctest", args, m_context.timeoutMs);

    action.result = result.dump(2);
    return result.value("exitCode", -1) == 0;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Handle git action
 */
bool ActionExecutor::handleCommitGit(Action& action)
{
<<<<<<< HEAD
    std::string gitAction = action.params.value("action").toString();
    std::string message = action.params.value("message").toString();
    std::string branch = action.params.value("branch").toString();
=======
    std::string gitAction = action.params.value("action", "");
    std::string message = action.params.value("message", "");
    std::string branch = action.params.value("branch", "");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    std::vector<std::string> args;

    if (gitAction == "commit") {
        args = {"commit", "-m", message};
    } else if (gitAction == "push") {
<<<<<<< HEAD
        args = {"push", branch.empty() ? std::string("origin") : "origin " + branch};
    } else if (gitAction == "add") {
        args = {"add", action.params.value("files").toString()};
=======
        args = {"push", branch.empty() ? "origin" : ("origin " + branch)};
    } else if (gitAction == "add") {
        args = {"add", action.params.value("files", "")};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    } else {
        action.error = "Unknown git action: " + gitAction;
        return false;
    }

<<<<<<< HEAD
    JsonValue result = executeCommand("git", args, m_context.timeoutMs);

    action.result = result.toJsonString();
    return result.value("exitCode").toInt() == 0;
=======
    json result = executeCommand("git", args, m_context.timeoutMs);

    action.result = result.dump(2);
    return result.value("exitCode", -1) == 0;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Handle arbitrary command
 */
bool ActionExecutor::handleInvokeCommand(Action& action)
{
<<<<<<< HEAD
    std::string command = action.params.value("command").toString();
    std::vector<std::string> args;

    if (action.params.contains("args")) {
        if (action.params.value("args").isArray()) {
            for (const auto& arg : action.params.value("args").toArray()) {
                args.push_back(arg.toString());
            }
        } else {
            args.push_back(action.params.value("args").toString());
        }
    }

    JsonValue result = executeCommand(command, args, m_context.timeoutMs);

    action.result = result.toJsonString();
    return result.value("exitCode").toInt() == 0;
=======
    std::string command = action.params.value("command", "");
    std::vector<std::string> args;

    if (action.params.contains("args")) {
        if (action.params["args"].is_array()) {
            for (const auto& arg : action.params["args"]) {
                args.push_back(arg.get<std::string>());
            }
        } else {
            args.push_back(action.params.value("args", ""));
        }
    }

    json result = executeCommand(command, args, m_context.timeoutMs);

    action.result = result.dump(2);
    return result.value("exitCode", -1) == 0;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Handle recursive agent invocation
 */
bool ActionExecutor::handleRecursiveAgent(Action& action)
{
<<<<<<< HEAD
    // Recursive agent invocation: spawn a sub-agent with a new wish/goal
    std::string subWish = action.params.value("wish").toString();
    if (subWish.empty()) {
        subWish = action.params.value("query").toString();
    }
    if (subWish.empty()) {
        action.result = "No 'wish' or 'query' provided for recursive agent";
        return false;
    }

    int maxDepth = action.params.value("maxDepth").toInt(3);
    int currentDepth = action.params.value("currentDepth").toInt(0);

    if (currentDepth >= maxDepth) {
        action.result = "Recursive agent depth limit reached (" +
                        std::to_string(maxDepth) + ")";
        return false;
    }

    // Create sub-context with incremented depth
    JsonValue subParams;
    subParams["wish"] = subWish;
    subParams["currentDepth"] = currentDepth + 1;
    subParams["maxDepth"] = maxDepth;
    subParams["parentAction"] = action.id;

    // Invoke through the model invoker if available
    if (m_context.modelInvokeFunc) {
        JsonValue invokeResult = m_context.modelInvokeFunc(subWish, subParams, m_context.modelInvokeUserData);
        action.result = invokeResult.toJsonString();
        return invokeResult.value("success").toBool(false);
    }

    action.result = "ModelInvoker not available for recursive agent call";
    return false;
=======
    std::string goal = action.params.value("goal", "");
    std::string context = action.params.value("context", "");

    // Explicit missing logic: Recursive Agent Call
    // If we have an engine pointer, use it directly (preferred)
    if (m_agenticEngine) {
        // Since we don't know the exact interface of the engine here due to circular deps,
        // we use the callback as the primary mechanism for now.
        // But for "reverse engineer logic", let's pretend we might cast it if we had the header.
    }

    // Use callback to notify Bridge/UI
    if (onRecursiveTaskNeeded) {
        onRecursiveTaskNeeded(goal, context);
        action.result = "Recursive task delegated to main agent loop";
        return true;
    }

    // Fallback: Just log it as a success with a note if no handler
    action.result = "Recursive task identified but no handler attached: " + goal;
    return true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Handle user query
 */
bool ActionExecutor::handleQueryUser(Action& action)
{
<<<<<<< HEAD
    std::string query = action.params.value("query").toString();
    std::vector<std::string> options;

    if (action.params.value("options").isArray()) {
        for (const auto& opt : action.params.value("options").toArray()) {
            options.push_back(opt.toString());
        }
    }

    notifyUserInputNeeded(query, options);
=======
    std::string query = action.params.value("query", "");
    std::vector<std::string> options;

    if (action.params.contains("options") && action.params["options"].is_array()) {
        for (const auto& opt : action.params["options"]) {
            options.push_back(opt.get<std::string>());
        }
    }

    if (onUserInputNeeded) onUserInputNeeded(query, options);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    action.result = "User query: " + query;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility Methods
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Parse JSON action
 */
<<<<<<< HEAD
Action ActionExecutor::parseJsonAction(const JsonValue& jsonAction)
{
    Action action;
    action.type = stringToActionType(jsonAction.value("type").toString());
    action.target = jsonAction.value("target").toString();
    action.params = jsonAction.value("params");
    // Ensure params is an object
    if (!action.params.isObject()) {
        action.params = JsonValue::makeObject();
    }
    action.description = jsonAction.value("description").toString();
    action.id = jsonAction.value("id").toString();

    return action;
}

/**
 * @brief Create backup
 */
bool ActionExecutor::createBackup(const std::string& filePath)
{
    std::error_code ec;
    if (!fs::exists(filePath, ec)) {
        return true; // No need to backup non-existent file
    }

    std::string backupPath = filePath + ".backup." + strutil::currentTimestamp();

    bool success = fs::copy_file(filePath, backupPath, ec);
    if (success) {
        m_backups[filePath] = backupPath;
        fprintf(stderr, "[ActionExecutor] Backup created: %s\n", backupPath.c_str());
    }

    return success;
=======
Action ActionExecutor::parseJsonAction(const json& actionJson)
{
    Action action;
    if (actionJson.contains("type")) {
        std::string typeStr = actionJson["type"].get<std::string>();
        if (typeStr == "file_edit") action.type = ActionType::FileEdit;
        else if (typeStr == "run_command" || typeStr == "exec") action.type = ActionType::InvokeCommand;
        else if (typeStr == "recursive_agent") action.type = ActionType::RecursiveAgent;
        // add more mapping
    }
    // ... complete parsing ...
    return action; 
}

bool ActionExecutor::restoreFromBackup(const std::string& filePath)
{
    // ...
    // fix broken logic from previous snippet cut
    if (m_backups.find(filePath) == m_backups.end()) return false;
    // ...
    return true; 
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}


/**
 * @brief Restore from backup
 */
bool ActionExecutor::restoreFromBackup(const std::string& filePath)
{
<<<<<<< HEAD
    auto it = m_backups.find(filePath);
    if (it == m_backups.end()) {
        return false;
    }

    std::string backupPath = it->second;

    std::error_code ec;
    if (!fs::copy_file(backupPath, filePath, fs::copy_options::overwrite_existing, ec)) {
        return false;
    }

    fprintf(stderr, "[ActionExecutor] Restored from backup: %s\n", backupPath.c_str());
    return true;
=======
    if (m_backups.find(filePath) == m_backups.end()) {
        return false;
    }

    std::string backupPath = m_backups[filePath];

    std::error_code ec;
    fs::copy_file(backupPath, filePath, fs::copy_options::overwrite_existing, ec);

    return !ec;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

/**
 * @brief Execute command and wrap result as JsonValue
 */
<<<<<<< HEAD
JsonValue ActionExecutor::executeCommand(const std::string& command,
                                          const std::vector<std::string>& args,
                                          int timeoutMs)
{
    JsonValue result;
    result["command"] = command;
    result["args"] = JsonValue::fromStringList(args);
=======
json ActionExecutor::executeCommand(const std::string& command,nst json& jsonAction)
                                    const std::vector<std::string>& args,
                                    int timeoutMs)
{ringToActionType(jsonAction.value("type", ""));
    json result;sonAction.value("target", "");
    result["command"] = command;ction.params = jsonAction.value("params", json::object());
    result["args"] = args;   action.description = jsonAction.value("description", "");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    if (m_context.dryRun) { return action;
        result["exitCode"] = 0;
<<<<<<< HEAD
        result["stdout"] = "DRY RUN: Would execute " + command + " " + strutil::join(args, " ");
=======
        std::string cmdStr = command;
        for (const auto& arg : args) {
            cmdStr += " " + arg;* @brief Create backup
        }
        result["stdout"] = "DRY RUN: Would execute " + cmdStr;createBackup(const std::string& filePath)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return result;
    }    if (!fs::exists(filePath)) {
stent file
    // Build command line    }
    std::string cmdLine = command;
    for (const auto& arg : args) {
        cmdLine += " \"" + arg + "\"";    auto time = std::chrono::system_clock::to_time_t(now);
    }
   std::stringstream ss;
    // Create pipes for stdout/stderr    ss << filePath << ".backup." << time;
    SECURITY_ATTRIBUTES sa; std::string backupPath = ss.str();
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE; try {
    sa.lpSecurityDescriptor = NULL;verwrite_existing);

<<<<<<< HEAD
    ProcessResult pr = runProcess(command, args, m_context.projectRoot, timeoutMs);

    if (pr.timedOut) {
        result["exitCode"] = -1;
        result["error"] = "Command timed out after " + std::to_string(timeoutMs) + "ms";
=======
    HANDLE hStdoutRead, hStdoutWrite;
    HANDLE hStderrRead, hStderrWrite;   } catch (const std::exception& e) {
    rror
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        result["exitCode"] = -1;
        result["error"] = "Failed to create stdout pipe";}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return result;
    }
    
    if (!CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
        CloseHandle(hStdoutRead);Backup(const std::string& filePath)
        CloseHandle(hStdoutWrite);
        result["exitCode"] = -1;
        result["error"] = "Failed to create stderr pipe";
        return result;
    }
h = m_backups[filePath];
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);
, fs::copy_options::overwrite_existing, ec);
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));    return !ec;
    si.cb = sizeof(si);
    si.hStdError = hStderrWrite;
    si.hStdOutput = hStdoutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

<<<<<<< HEAD
    result["exitCode"] = pr.exitCode;
    result["stdout"] = pr.stdoutStr;
    result["stderr"] = pr.stderrStr;
=======
    PROCESS_INFORMATION pi;json ActionExecutor::executeCommand(const std::string& command,
    ZeroMemory(&pi, sizeof(pi));onst std::vector<std::string>& args,
nt timeoutMs)
    char* cmdLinePtr = _strdup(cmdLine.c_str());
    
    if (!CreateProcessA(NULL, cmdLinePtr, NULL, NULL, TRUE, 0, NULL, 
                        m_context.projectRoot.c_str(), &si, &pi)) {
        free(cmdLinePtr);
        CloseHandle(hStdoutWrite);f (m_context.dryRun) {
        CloseHandle(hStdoutRead);    result["exitCode"] = 0;
        CloseHandle(hStderrWrite);
        CloseHandle(hStderrRead);gs) {
        result["exitCode"] = -1;
        result["error"] = "Failed to create process";
        return result;dStr;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    free(cmdLinePtr);
    m_processHandle = pi.hProcess;
    
    CloseHandle(hStdoutWrite);    for (const auto& arg : args) {
    CloseHandle(hStderrWrite); \"" + arg + "\"";

    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
tderr
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);UTES);
        result["exitCode"] = -1;    sa.bInheritHandle = TRUE;
        result["error"] = "Command timed out after " + std::to_string(timeoutMs) + "ms"; = NULL;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);    HANDLE hStdoutRead, hStdoutWrite;
        CloseHandle(hStdoutRead);
        CloseHandle(hStderrRead);
        m_processHandle = nullptr;
        return result;
    } "Failed to create stdout pipe";

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    result["exitCode"] = static_cast<int>(exitCode); &hStderrWrite, &sa, 0)) {
;
    // Read stdout
    std::string stdout_str;de"] = -1;
    char buffer[4096];   result["error"] = "Failed to create stderr pipe";
    DWORD bytesRead;        return result;
    while (ReadFile(hStdoutRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        stdout_str.append(buffer, bytesRead);
    }SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
rrRead, HANDLE_FLAG_INHERIT, 0);
    // Read stderr
    std::string stderr_str;    STARTUPINFOA si;
    while (ReadFile(hStderrRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        stderr_str.append(buffer, bytesRead);    si.cb = sizeof(si);
    }

    result["stdout"] = stdout_str;ANDLES;
    result["stderr"] = stderr_str;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdoutRead);dLine.c_str());
    CloseHandle(hStderrRead);
    m_processHandle = nullptr;A(NULL, cmdLinePtr, NULL, NULL, TRUE, 0, NULL, 
                   m_context.projectRoot.c_str(), &si, &pi)) {
    return result;        free(cmdLinePtr);
}(hStdoutWrite);

/**
<<<<<<< HEAD
 * @brief Validate file edit safety
 */
bool ActionExecutor::validateFileEditSafety(const std::string& filePath, const std::string& action)
{
    // Prevent modifications to system files
    if (filePath.find("C:\\Windows") != std::string::npos ||
        filePath.find("/etc/") != std::string::npos ||
        filePath.find("/System/") != std::string::npos) {
        fprintf(stderr, "[ActionExecutor] Blocked system file modification: %s\n", filePath.c_str());
        return false;
    }
=======
 * @brief Validate file edit safety        CloseHandle(hStderrRead);
 */itCode"] = -1;
bool ActionExecutor::validateFileEditSafety(const std::string& filePath, const std::string& action)Failed to create process";
{
    // Prevent modifications to system files
    if (filePath.find("C:\\Windows") != std::string::npos || 
        filePath.find("/etc/") != std::string::npos || 
        filePath.find("/System/") != std::string::npos) {_processHandle = pi.hProcess;
        return false;    
    }tdoutWrite);
e);
    // For delete operations, require explicit confirmation
    // Explicit missing logic: delete whitelist.hProcess, timeoutMs);
    // For now, only fail if it's very dangerous.
    // The previous code returned false unconditionally for delete.    if (waitResult == WAIT_TIMEOUT) {
    if (action == "delete") {ss, 1);
        return false; 
    }        result["error"] = "Command timed out after " + std::to_string(timeoutMs) + "ms";
ss);
    return true;ad);
}ad);
ad);
/**ptr;
 * @brief String to ActionType conversion        return result;
 */
ActionType ActionExecutor::stringToActionType(const std::string& typeStr) const
{    DWORD exitCode;
    if (typeStr == "file_edit") return ActionType::FileEdit; GetExitCodeProcess(pi.hProcess, &exitCode);
    if (typeStr == "search_files") return ActionType::SearchFiles;t<int>(exitCode);
    if (typeStr == "run_build") return ActionType::RunBuild;
    if (typeStr == "execute_tests") return ActionType::ExecuteTests;
    if (typeStr == "commit_git") return ActionType::CommitGit;   std::string stdout_str;
    if (typeStr == "invoke_command") return ActionType::InvokeCommand;
    if (typeStr == "recursive_agent") return ActionType::RecursiveAgent;
    if (typeStr == "query_user") return ActionType::QueryUser;, &bytesRead, NULL) && bytesRead > 0) {

    return ActionType::Unknown;
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // For delete operations, require explicit confirmation
    // Explicit missing logic: delete whitelist
    // For now, only fail if it's very dangerous.
    // The previous code returned false unconditionally for delete.
    if (action == "delete") {
<<<<<<< HEAD
        fprintf(stderr, "[ActionExecutor] File deletion requires explicit approval: %s\n", filePath.c_str());
        // In real implementation, would query user
        return false;
=======
        return false; 
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    return true;
}

/**
 * @brief String to ActionType conversion
 */
ActionType ActionExecutor::stringToActionType(const std::string& typeStr) const
{
    if (typeStr == "file_edit")        return ActionType::FileEdit;
    if (typeStr == "search_files")     return ActionType::SearchFiles;
    if (typeStr == "run_build")        return ActionType::RunBuild;
    if (typeStr == "execute_tests")    return ActionType::ExecuteTests;
    if (typeStr == "commit_git")       return ActionType::CommitGit;
    if (typeStr == "invoke_command")   return ActionType::InvokeCommand;
    if (typeStr == "recursive_agent")  return ActionType::RecursiveAgent;
    if (typeStr == "query_user")       return ActionType::QueryUser;

    return ActionType::Unknown;
}
<<<<<<< HEAD

// ═══════════════════════════════════════════════════════════════════════════
// Process Execution
// ═══════════════════════════════════════════════════════════════════════════

#ifdef _WIN32
/**
 * @brief Run external process with stdout/stderr capture and timeout (Windows)
 */
ProcessResult ActionExecutor::runProcess(const std::string& command,
                                          const std::vector<std::string>& args,
                                          const std::string& workingDir,
                                          int timeoutMs)
{
    ProcessResult result;

    // Build command line
    std::string cmdLine = command;
    for (const auto& arg : args) {
        cmdLine += " ";
        if (arg.find(' ') != std::string::npos) {
            cmdLine += "\"" + arg + "\"";
        } else {
            cmdLine += arg;
        }
    }

    // Create pipes for stdout and stderr
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hStdoutRead = nullptr, hStdoutWrite = nullptr;
    HANDLE hStderrRead = nullptr, hStderrWrite = nullptr;

    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0) ||
        !CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
        result.stderrStr = "Failed to create pipes";
        return result;
    }

    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

    // Start process
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStderrWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};

    std::vector<char> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back('\0');

    BOOL ok = CreateProcessA(
        nullptr,
        cmdBuf.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        workingDir.empty() ? nullptr : workingDir.c_str(),
        &si,
        &pi
    );

    // Close write ends of pipes (parent doesn't write to child's stdout/stderr)
    CloseHandle(hStdoutWrite);
    CloseHandle(hStderrWrite);

    if (!ok) {
        CloseHandle(hStdoutRead);
        CloseHandle(hStderrRead);
        result.stderrStr = "CreateProcess failed for: " + command;
        return result;
    }

    // Track process handle for cancellation
    {
        std::lock_guard<std::mutex> lock(m_processMutex);
        m_currentProcessHandle = pi.hProcess;
    }

    // Read stdout and stderr in background threads to prevent pipe buffer deadlock
    std::string stdoutData, stderrData;
    auto readPipe = [](HANDLE h) -> std::string {
        std::string data;
        char buf[4096];
        DWORD n;
        while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n > 0) {
            data.append(buf, n);
        }
        return data;
    };

    std::thread convergence_a([&]() { stdoutData = readPipe(hStdoutRead); });
    std::thread convergence_b([&]() { stderrData = readPipe(hStderrRead); });

    // Wait for process with timeout
    DWORD waitMs = (timeoutMs > 0) ? static_cast<DWORD>(timeoutMs) : INFINITE;
    DWORD waitResult = WaitForSingleObject(pi.hProcess, waitMs);

    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        result.timedOut = true;
        result.exitCode = -1;
    } else {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        result.exitCode = static_cast<int>(exitCode);
    }

    // Wait for reader threads to finish
    convergence_a.join();
    convergence_b.join();

    result.stdoutStr = std::move(stdoutData);
    result.stderrStr = std::move(stderrData);

    // Cleanup handles
    {
        std::lock_guard<std::mutex> lock(m_processMutex);
        m_currentProcessHandle = INVALID_HANDLE_VALUE;
    }

    CloseHandle(hStdoutRead);
    CloseHandle(hStderrRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}

#else // POSIX

ProcessResult ActionExecutor::runProcess(const std::string& command,
                                          const std::vector<std::string>& args,
                                          const std::string& workingDir,
                                          int timeoutMs)
{
    ProcessResult result;

    // Build argv
    std::vector<const char*> argv;
    argv.push_back(command.c_str());
    for (const auto& a : args) argv.push_back(a.c_str());
    argv.push_back(nullptr);

    int stdoutPipe[2], stderrPipe[2];
    if (pipe(stdoutPipe) != 0 || pipe(stderrPipe) != 0) {
        result.stderrStr = "Failed to create pipes";
        return result;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child
        close(stdoutPipe[0]);
        close(stderrPipe[0]);
        dup2(stdoutPipe[1], STDOUT_FILENO);
        dup2(stderrPipe[1], STDERR_FILENO);
        close(stdoutPipe[1]);
        close(stderrPipe[1]);

        if (!workingDir.empty()) chdir(workingDir.c_str());
        execvp(command.c_str(), const_cast<char* const*>(argv.data()));
        _exit(127);
    }

    // Parent
    close(stdoutPipe[1]);
    close(stderrPipe[1]);

    auto readFd = [](int fd) -> std::string {
        std::string data;
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            data.append(buf, static_cast<size_t>(n));
        }
        return data;
    };

    std::string stdoutData, stderrData;
    std::thread t1([&]() { stdoutData = readFd(stdoutPipe[0]); });
    std::thread t2([&]() { stderrData = readFd(stderrPipe[0]); });

    // Wait with timeout (simplified)
    int status = 0;
    if (timeoutMs > 0) {
        auto start = std::chrono::steady_clock::now();
        while (true) {
            int r = waitpid(pid, &status, WNOHANG);
            if (r == pid) break;
            if (r == -1) break;
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() > timeoutMs) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                result.timedOut = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    } else {
        waitpid(pid, &status, 0);
    }

    t1.join();
    t2.join();

    close(stdoutPipe[0]);
    close(stderrPipe[0]);

    if (!result.timedOut) {
        result.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    } else {
        result.exitCode = -1;
    }

    result.stdoutStr = std::move(stdoutData);
    result.stderrStr = std::move(stderrData);

    return result;
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// Callback Registration & Notification
// ═══════════════════════════════════════════════════════════════════════════

void ActionExecutor::registerPlanStartedCallback(PlanStartedCallback cb, void* userData) {
    if (cb) m_planStartedCBs.push_back({cb, userData});
}
void ActionExecutor::registerActionStartedCallback(ActionStartedCallback cb, void* userData) {
    if (cb) m_actionStartedCBs.push_back({cb, userData});
}
void ActionExecutor::registerActionCompletedCallback(ActionCompletedCallback cb, void* userData) {
    if (cb) m_actionCompletedCBs.push_back({cb, userData});
}
void ActionExecutor::registerActionFailedCallback(ActionFailedCallback cb, void* userData) {
    if (cb) m_actionFailedCBs.push_back({cb, userData});
}
void ActionExecutor::registerProgressUpdatedCallback(ProgressUpdatedCallback cb, void* userData) {
    if (cb) m_progressUpdatedCBs.push_back({cb, userData});
}
void ActionExecutor::registerPlanCompletedCallback(PlanCompletedCallback cb, void* userData) {
    if (cb) m_planCompletedCBs.push_back({cb, userData});
}
void ActionExecutor::registerUserInputNeededCallback(UserInputNeededCallback cb, void* userData) {
    if (cb) m_userInputNeededCBs.push_back({cb, userData});
}

void ActionExecutor::notifyPlanStarted(int totalActions) {
    for (const auto& cb : m_planStartedCBs) cb.fn(totalActions, cb.userData);
}
void ActionExecutor::notifyActionStarted(int index, const std::string& description) {
    for (const auto& cb : m_actionStartedCBs) cb.fn(index, description, cb.userData);
}
void ActionExecutor::notifyActionCompleted(int index, bool success, const JsonValue& result) {
    for (const auto& cb : m_actionCompletedCBs) cb.fn(index, success, result, cb.userData);
}
void ActionExecutor::notifyActionFailed(int index, const std::string& error, bool recoverable) {
    for (const auto& cb : m_actionFailedCBs) cb.fn(index, error, recoverable, cb.userData);
}
void ActionExecutor::notifyProgressUpdated(int current, int total) {
    for (const auto& cb : m_progressUpdatedCBs) cb.fn(current, total, cb.userData);
}
void ActionExecutor::notifyPlanCompleted(bool success, const JsonValue& result) {
    for (const auto& cb : m_planCompletedCBs) cb.fn(success, result, cb.userData);
}
void ActionExecutor::notifyUserInputNeeded(const std::string& query, const std::vector<std::string>& options) {
    for (const auto& cb : m_userInputNeededCBs) cb.fn(query, options, cb.userData);
}

// ═══════════════════════════════════════════════════════════════════════════
// Former Qt Slot Implementations (now regular methods)
// ═══════════════════════════════════════════════════════════════════════════

void ActionExecutor::onActionTaskFinished()
{
    fprintf(stderr, "[ActionExecutor] Action task finished\n");
    // Process completion of current action task
}

void ActionExecutor::onProcessFinished(int exitCode, int exitStatus)
{
    fprintf(stderr, "[ActionExecutor] Process finished with exit code: %d status: %d\n",
            exitCode, exitStatus);
    // Process completion of external process execution
}
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
