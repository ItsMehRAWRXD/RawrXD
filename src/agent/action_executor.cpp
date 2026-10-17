/**
 * @file action_executor.cpp
 * @brief Implementation of action execution engine
 *
 * Executes agent-generated actions with comprehensive error handling,
 * backup/restore, and observability.
 */

#include "action_executor.hpp"
#include "model_invoker.hpp"
#include "qt_block.h"

#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QDateTime>
#include <QDebug>
#include <QtConcurrent>
#include <QFuture>

/**
 * @brief Constructor
 */
ActionExecutor::ActionExecutor(QObject* parent)
    : QObject(parent)
    , m_process(std::make_unique<NativeProcess>())
{
    m_context.projectRoot = QDir::currentPath();
}

/**
 * @brief Destructor
 */
ActionExecutor::~ActionExecutor() = default;

/**
 * @brief Set execution context
 */
void ActionExecutor::setContext(const ExecutionContext& context)
{
    m_context = context;
    qInfo() << "[ActionExecutor] Context set - projectRoot:" << m_context.projectRoot;
}

/**
 * @brief Execute single action (synchronous)
 */
bool ActionExecutor::executeAction(Action& action)
{
    qInfo() << "[ActionExecutor] Executing action:" << action.description;

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
void ActionExecutor::executePlan(const QJsonArray& actions, bool stopOnError)
{
    m_isExecuting = true;
    m_stopOnError = stopOnError;
    m_cancelled = false;
    m_executedActions.clear();
    m_backups.clear();

    m_context.totalActions = actions.size();
    emit planStarted(actions.size());

    // Run on background thread
    QtConcurrent::run([this, actions]() {
        bool overallSuccess = true;

        for (int i = 0; i < actions.size() && !m_cancelled; ++i) {
            if (!actions[i].isObject()) {
                qWarning() << "[ActionExecutor] Invalid action at index" << i;
                overallSuccess = false;
                if (m_stopOnError) break;
                continue;
            }

            Action action = parseJsonAction(actions[i].toObject());
            m_context.currentActionIndex = i;

            emit actionStarted(i, action.description);
            emit progressUpdated(i, m_context.totalActions);

            bool success = executeAction(action);
            action.executed = true;
            action.success = success;

            m_executedActions.append(action);

            QJsonObject result;
            result["target"] = action.target;
            result["success"] = success;
            if (!action.error.isEmpty()) {
                result["error"] = action.error;
            }
            if (!action.result.isEmpty()) {
                result["result"] = action.result;
            }

            emit actionCompleted(i, success, result);

            if (!success) {
                overallSuccess = false;
                emit actionFailed(i, action.error, m_stopOnError);

                if (m_stopOnError) {
                    qWarning() << "[ActionExecutor] Stopping due to error";
                    break;
                }
            }
        }

        m_isExecuting = false;

        QJsonObject finalResult;
        finalResult["success"] = overallSuccess;
        finalResult["actionsExecuted"] = m_executedActions.size();
        finalResult["state"] = m_context.state;

        emit planCompleted(overallSuccess, finalResult);
    });
}

/**
 * @brief Cancel execution
 */
void ActionExecutor::cancelExecution()
{
    m_cancelled = true;
    // NativeProcess is synchronous - no running process to terminate
    qInfo() << "[ActionExecutor] Execution cancelled";
}

/**
 * @brief Rollback action
 */
bool ActionExecutor::rollbackAction(int actionIndex)
{
    if (actionIndex < 0 || actionIndex >= m_executedActions.size()) {
        return false;
    }

    const Action& action = m_executedActions[actionIndex];

    // Only file edits are rollbackable
    if (action.type != ActionType::FileEdit) {
        qWarning() << "[ActionExecutor] Action type not rollbackable";
        return false;
    }

    if (!m_backups.contains(action.target)) {
        qWarning() << "[ActionExecutor] No backup found for" << action.target;
        return false;
    }

    return restoreFromBackup(action.target);
}

/**
 * @brief Get aggregated result
 */
QJsonObject ActionExecutor::getAggregatedResult() const
{
    QJsonObject result;
    QJsonArray actions;

    for (const auto& action : m_executedActions) {
        QJsonObject actionObj;
        actionObj["description"] = action.description;
        actionObj["success"] = action.success;
        actionObj["result"] = action.result;
        if (!action.error.isEmpty()) {
            actionObj["error"] = action.error;
        }
        actions.append(actionObj);
    }

    result["actions"] = actions;
    result["state"] = m_context.state;

    return result;
}

// ─────────────────────────────────────────────────────────────────────────
// Action Handlers
// ─────────────────────────────────────────────────────────────────────────

/**
 * @brief Handle file edit action
 */
bool ActionExecutor::handleFileEdit(Action& action)
{
    QString filePath = m_context.projectRoot + "/" + action.target;
    QString editAction = action.params.value("action").toString();
    QString content = action.params.value("content").toString();

    // Validate safety
    if (!validateFileEditSafety(filePath, editAction)) {
        action.error = "File edit failed safety validation";
        return false;
    }

    if (m_context.dryRun) {
        action.result = "DRY RUN: Would edit " + filePath;
        return true;
    }

    // Create backup
    if (!createBackup(filePath)) {
        qWarning() << "[ActionExecutor] Failed to backup" << filePath;
    }

    QFile file(filePath);

    if (editAction == "create") {
        // Create new file
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            action.error = "Failed to create file: " + file.errorString();
            return false;
        }
        file.write(content.toUtf8());
        file.close();
        action.result = "File created: " + filePath;
        return true;

    } else if (editAction == "append") {
        // Append to existing file
        if (!file.open(QIODevice::Append | QIODevice::Text)) {
            action.error = "Failed to open file for append: " + file.errorString();
            return false;
        }
        file.write(content.toUtf8());
        file.close();
        action.result = "Appended to: " + filePath;
        return true;

    } else if (editAction == "replace") {
        // Replace entire file
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            action.error = "Failed to open file for writing: " + file.errorString();
            return false;
        }
        file.write(content.toUtf8());
        file.close();
        action.result = "Replaced: " + filePath;
        return true;

    } else if (editAction == "delete") {
        // Delete file
        if (!QFile::remove(filePath)) {
            action.error = "Failed to delete file";
            return false;
        }
        action.result = "Deleted: " + filePath;
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
    QString searchPath = m_context.projectRoot + "/" + action.params.value("path").toString();
    QString pattern = action.params.value("pattern").toString();
    QString query = action.params.value("query").toString();

    QDir dir(searchPath);
    if (!dir.exists()) {
        action.error = "Search path does not exist: " + searchPath;
        return false;
    }

    QFileInfoList files = dir.entryInfoList(pattern.split(","), QDir::Files, QDir::Name);

    QJsonArray results;
    int matchCount = 0;

    for (const QFileInfo& fileInfo : files) {
        if (query.isEmpty()) {
            // Just list files
            QJsonObject fileObj;
            fileObj["path"] = fileInfo.absoluteFilePath();
            fileObj["size"] = (int)fileInfo.size();
            results.append(fileObj);
        } else {
            // Search content
            QFile file(fileInfo.absoluteFilePath());
            if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QString content = file.readAll();
                file.close();

                if (content.contains(query)) {
                    QJsonObject match;
                    match["file"] = fileInfo.absoluteFilePath();
                    match["matches"] = content.count(query);
                    results.append(match);
                    matchCount++;
                }
            }
        }
    }

    QJsonObject result;
    result["files_searched"] = files.size();
    result["matches"] = matchCount;
    result["results"] = results;

    action.result = QString::fromStdString(NativeJson::toJson(result));
    return true;
}

/**
 * @brief Handle build action
 */
bool ActionExecutor::handleRunBuild(Action& action)
{
    QString target = action.params.value("target").toString("all");
    QString config = action.params.value("config").toString("Release");

    QStringList args = {"--build", "build", "--config", config};
    if (target != "all") {
        args << "--target" << target;
    }

    QJsonObject result = executeCommand("cmake", args, m_context.timeoutMs);

    action.result = QString::fromStdString(NativeJson::toJson(result));
    return result.value("exitCode").toInt() == 0;
}

/**
 * @brief Handle test action
 */
bool ActionExecutor::handleExecuteTests(Action& action)
{
    QString testTarget = action.params.value("target").toString("all_tests");

    QStringList args;
    if (testTarget != "all_tests") {
        args << testTarget;
    }

    QJsonObject result = executeCommand("ctest", args, m_context.timeoutMs);

    action.result = QString::fromStdString(NativeJson::toJson(result));
    return result.value("exitCode").toInt() == 0;
}

/**
 * @brief Handle git action
 */
bool ActionExecutor::handleCommitGit(Action& action)
{
    QString gitAction = action.params.value("action").toString();
    QString message = action.params.value("message").toString();
    QString branch = action.params.value("branch").toString();

    QStringList args;

    if (gitAction == "commit") {
        args << "commit" << "-m" << message;
    } else if (gitAction == "push") {
        args << "push" << (branch.isEmpty() ? "origin" : "origin " + branch);
    } else if (gitAction == "add") {
        args << "add" << action.params.value("files").toString();
    } else {
        action.error = "Unknown git action: " + gitAction;
        return false;
    }

    QJsonObject result = executeCommand("git", args, m_context.timeoutMs);

    action.result = QString::fromStdString(NativeJson::toJson(result));
    return result.value("exitCode").toInt() == 0;
}

/**
 * @brief Handle arbitrary command
 */
bool ActionExecutor::handleInvokeCommand(Action& action)
{
    QString command = action.params.value("command").toString();
    QStringList args;

    if (action.params.contains("args")) {
        if (action.params.value("args").isArray()) {
            for (const QJsonValue& arg : action.params.value("args").toArray()) {
                args << arg.toString();
            }
        } else {
            args << action.params.value("args").toString();
        }
    }

    QJsonObject result = executeCommand(command, args, m_context.timeoutMs);

    action.result = QString::fromStdString(NativeJson::toJson(result));
    return result.value("exitCode").toInt() == 0;
}

/**
 * @brief Handle recursive agent invocation
 */
bool ActionExecutor::handleRecursiveAgent(Action& action)
{
    // Extract the wish/prompt from action parameters
    QString wish;
    if (action.params.contains("wish")) {
        wish = action.params["wish"].toString();
    } else if (action.params.contains("prompt")) {
        wish = action.params["prompt"].toString();
    } else if (action.params.contains("query")) {
        wish = action.params["query"].toString();
    } else if (action.params.contains("message")) {
        wish = action.params["message"].toString();
    } else {
        action.result = "Recursive agent invocation: no wish/prompt provided";
        return false;
    }

    if (wish.isEmpty()) {
        action.result = "Recursive agent invocation: empty wish";
        return false;
    }

    try {
        // Create ModelInvoker for recursive agent invocation
        ModelInvoker invoker;

        // Build invocation parameters
        InvocationParams params;
        params.wish = wish;

        // Add context from action params if available
        if (action.params.contains("context")) {
            params.context = action.params["context"].toString();
        }
        if (action.params.contains("codebase")) {
            params.codebase = action.params["codebase"].toString();
        }

        // Invoke the model to get a structured plan
        LLMResponse response = invoker.invoke(params);

        if (response.rawOutput.isEmpty() && response.parsedPlan.isEmpty()) {
            action.result = "Recursive agent invocation: model returned empty response";
            return false;
        }

        // Store the structured plan as result
        QJsonObject resultObj;
        resultObj["wish"] = wish;
        resultObj["rawOutput"] = response.rawOutput;
        resultObj["parsedPlan"] = response.parsedPlan;
        resultObj["invoked"] = true;

        action.result = QString::fromStdString(NativeJson::toJson(resultObj));
        qInfo() << "[ActionExecutor] Recursive agent invocation completed for:" << wish;
        return true;

    } catch (const std::exception& e) {
        action.result = QString("Recursive agent invocation error: %1").arg(e.what());
        return false;
    }
}

/**
 * @brief Handle user query
 */
bool ActionExecutor::handleQueryUser(Action& action)
{
    QString query = action.params.value("query").toString();
    QStringList options;

    if (action.params.value("options").isArray()) {
        for (const QJsonValue& opt : action.params.value("options").toArray()) {
            options << opt.toString();
        }
    }

    emit userInputNeeded(query, options);

    // Wait for user response (would be connected externally)
    action.result = "User query: " + query;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────
// Utility Methods
// ─────────────────────────────────────────────────────────────────────────

/**
 * @brief Parse JSON action
 */
Action ActionExecutor::parseJsonAction(const QJsonObject& jsonAction)
{
    Action action;
    action.type = stringToActionType(jsonAction.value("type").toString());
    action.target = jsonAction.value("target").toString();
    action.params = jsonAction.value("params").toObject();
    action.description = jsonAction.value("description").toString();

    return action;
}

/**
 * @brief Create backup
 */
bool ActionExecutor::createBackup(const QString& filePath)
{
    if (!QFileInfo::exists(filePath)) {
        return true; // No need to backup non-existent file
    }

    QString backupPath = filePath + ".backup." + QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");

    bool success = QFile::copy(filePath, backupPath);
    if (success) {
        m_backups[filePath] = backupPath;
        qDebug() << "[ActionExecutor] Backup created:" << backupPath;
    }

    return success;
}

/**
 * @brief Restore from backup
 */
bool ActionExecutor::restoreFromBackup(const QString& filePath)
{
    if (!m_backups.contains(filePath)) {
        return false;
    }

    QString backupPath = m_backups[filePath];

    if (!QFile::copy(backupPath, filePath)) {
        return false;
    }

    qDebug() << "[ActionExecutor] Restored from backup:" << backupPath;
    return true;
}

/**
 * @brief Execute command
 */
QJsonObject ActionExecutor::executeCommand(const QString& command,
                                            const QStringList& args,
                                            int timeoutMs)
{
    QJsonObject result;
    result["command"] = command;
    
    // Convert QStringList to JSON array
    QJsonArray argsArray;
    for (const auto& arg : args) {
        argsArray.append(arg);
    }
    result["args"] = argsArray;

    if (m_context.dryRun) {
        result["exitCode"] = 0;
        result["stdout"] = "DRY RUN: Would execute " + command + " " + args.join(" ");
        return result;
    }

    // Convert QStringList to vector<string> for NativeProcess
    std::vector<std::string> nativeArgs;
    for (const auto& arg : args) {
        nativeArgs.push_back(arg.toStdString());
    }

    // Execute using NativeProcess (real CreateProcessW, not QProcess stub)
    NativeProcessResult procResult = NativeProcess::execute(
        command.toStdString(),
        nativeArgs,
        m_context.projectRoot.toStdString(),
        timeoutMs
    );

    result["exitCode"] = procResult.exitCode;
    result["success"] = procResult.success;
    result["stdout"] = QString::fromStdString(procResult.stdoutOutput);
    result["stderr"] = QString::fromStdString(procResult.stderrOutput);
    if (!procResult.success) {
        result["error"] = "Command failed with exit code " + QString::number(procResult.exitCode);
    }

    return result;
}

/**
 * @brief Validate file edit safety
 */
bool ActionExecutor::validateFileEditSafety(const QString& filePath, const QString& action)
{
    // Prevent modifications to system files
    if (filePath.contains("C:\\Windows") || filePath.contains("/etc/") || 
        filePath.contains("/System/")) {
        qWarning() << "[ActionExecutor] Blocked system file modification:" << filePath;
        return false;
    }

    // For delete operations, require explicit confirmation
    if (action == "delete") {
        qWarning() << "[ActionExecutor] File deletion requires explicit approval:" << filePath;
        // In real implementation, would query user
        return false;
    }

    return true;
}

/**
 * @brief String to ActionType conversion
 */
ActionType ActionExecutor::stringToActionType(const QString& typeStr) const
{
    if (typeStr == "file_edit") return ActionType::FileEdit;
    if (typeStr == "search_files") return ActionType::SearchFiles;
    if (typeStr == "run_build") return ActionType::RunBuild;
    if (typeStr == "execute_tests") return ActionType::ExecuteTests;
    if (typeStr == "commit_git") return ActionType::CommitGit;
    if (typeStr == "invoke_command") return ActionType::InvokeCommand;
    if (typeStr == "recursive_agent") return ActionType::RecursiveAgent;
    if (typeStr == "query_user") return ActionType::QueryUser;

    return ActionType::Unknown;
}

// Private slot implementations - called by Qt signal/slot mechanism
void ActionExecutor::onActionTaskFinished()
{
    qDebug() << "[ActionExecutor] Action task finished";
    // Process completion of current action task
}

void ActionExecutor::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    qDebug() << "[ActionExecutor] Process finished with exit code:" << exitCode
             << "status:" << static_cast<int>(exitStatus);
    // Process completion of external process execution
}

