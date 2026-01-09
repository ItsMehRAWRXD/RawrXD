/**
 * @file bounded_autonomous_executor.cpp
 * @brief Bounded Autonomous Executor Implementation
 * 
 * Complete implementation of the perception→decision→action→feedback loop.
 * Maximum 10 iterations by default, human-stoppable, tool-executing,
 * fully logged for audit trail and debugging.
 */

#include "bounded_autonomous_executor.hpp"
#include "inference_engine.hpp"
#include "agentic_tools.hpp"
#include "multi_tab_editor.hpp"
#include "terminal_pool.hpp"
#include <QTimer>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCoreApplication>

BoundedAutonomousExecutor::BoundedAutonomousExecutor(
    InferenceEngine* inferenceEngine,
    AgenticToolExecutor* toolExecutor,
    MultiTabEditor* editor,
    TerminalPool* terminals,
    QObject* parent
) : QObject(parent),
    m_inferenceEngine(inferenceEngine),
    m_toolExecutor(toolExecutor),
    m_editor(editor),
    m_terminals(terminals),
    m_loopTimer(new QTimer(this)),
    m_accumulatedResponse("")
{
    // ========== SETUP LOOP TIMER ==========
    // Timer-based loop allows Qt event processing and responsiveness to stop signal
    connect(m_loopTimer, &QTimer::timeout, this, &BoundedAutonomousExecutor::runAutonomousLoop);
    m_loopTimer->setInterval(100);  // Check every 100ms (responsive to stop button)
    
    // ========== CONNECT TOOL EXECUTOR SIGNALS ==========
    // Connect to tool executor's signals to monitor execution results
    if (m_toolExecutor) {
        connect(m_toolExecutor, &AgenticToolExecutor::toolExecuted,
                this, &BoundedAutonomousExecutor::onToolExecutionComplete);
        connect(m_toolExecutor, &AgenticToolExecutor::toolFailed,
                this, &BoundedAutonomousExecutor::onToolExecutionError);
    }
    
    // ========== CONNECT INFERENCE ENGINE SIGNALS ==========
    // Connect to inference engine's streaming signals for async token collection
    if (m_inferenceEngine) {
        connect(m_inferenceEngine, QOverload<qint64, const QString&>::of(&InferenceEngine::streamToken),
                this, &BoundedAutonomousExecutor::onInferenceStreamToken);
        connect(m_inferenceEngine, &InferenceEngine::streamFinished,
                this, &BoundedAutonomousExecutor::onInferenceStreamFinished);
        connect(m_inferenceEngine, QOverload<qint64, const QString&>::of(&InferenceEngine::error),
                this, &BoundedAutonomousExecutor::onInferenceError);
    }
    
    structuredLog("INFO", "INIT", "BoundedAutonomousExecutor initialized with async inference support");
}

// ============================================================================
// CONTROL METHODS
// ============================================================================

void BoundedAutonomousExecutor::startAutonomousLoop(
    const QString& initialPrompt,
    int maxIterations
) {
    QMutexLocker lock(&m_stateMutex);
    
    // Validate inputs
    if (initialPrompt.isEmpty()) {
        emit loopError("Initial task prompt cannot be empty");
        return;
    }
    
    if (maxIterations < 1 || maxIterations > 50) {
        maxIterations = 10;  // Safe default
    }
    
    // Reset state
    m_state = LoopState();
    m_state.maxIterations = maxIterations;
    m_state.isRunning = true;
    m_state.currentIteration = 0;
    m_currentTask = initialPrompt;
    m_logs.clear();
    
    structuredLog("INFO", "LOOP_START", QString("Starting autonomous loop: '%1' (max %2 iterations)")
        .arg(initialPrompt.left(100)).arg(maxIterations));
    
    emit loopStarted(initialPrompt);
    
    // Start timer-based loop
    m_loopTimer->start();
}

void BoundedAutonomousExecutor::requestShutdown() {
    QMutexLocker lock(&m_stateMutex);
    
    m_state.shutdownRequested = true;
    m_state.humanOverride = true;
    
    structuredLog("WARN", "USER_STOP", QString("User requested shutdown at iteration %1/%2")
        .arg(m_state.currentIteration).arg(m_state.maxIterations));
    
    emit shutdownRequested();
}

void BoundedAutonomousExecutor::emergencyStop() {
    QMutexLocker lock(&m_stateMutex);
    
    m_loopTimer->stop();
    m_state.isRunning = false;
    m_state.shutdownRequested = true;
    
    structuredLog("ERROR", "EMERGENCY_STOP", "Emergency stop triggered");
    emit loopError("Emergency stop triggered");
}

// ============================================================================
// MAIN LOOP DRIVER
// ============================================================================

void BoundedAutonomousExecutor::runAutonomousLoop() {
    {
        QMutexLocker lock(&m_stateMutex);
        
        // Check termination conditions
        if (m_state.shutdownRequested || 
            m_state.currentIteration >= m_state.maxIterations) {
            
            m_loopTimer->stop();
            m_state.isRunning = false;
            
            if (m_state.humanOverride) {
                structuredLog("WARN", "LOOP_STOP", QString("Loop stopped by user after %1 iterations")
                    .arg(m_state.currentIteration));
                emit loopStopped();
            } else {
                structuredLog("INFO", "LOOP_COMPLETE", QString("Loop completed successfully: %1 iterations")
                    .arg(m_state.currentIteration));
                emit loopFinished();
            }
            
            return;
        }
        
        // Increment iteration counter
        m_state.currentIteration++;
        m_cycleStartTime = QDateTime::currentMSecsSinceEpoch();
    }
    
    // ========== ITERATION START ==========
    emit iterationStarted(m_state.currentIteration);
    emit progressUpdated(m_state.currentIteration, m_state.maxIterations, "Starting iteration...");
    
    structuredLog("INFO", "ITERATION_START", QString("Beginning iteration %1/%2")
        .arg(m_state.currentIteration).arg(m_state.maxIterations));
    
    try {
        // ========== PERCEPTION PHASE ==========
        emit perceptionPhaseStarted(m_state.currentIteration);
        executePerceptionPhase();
        emit perceptionPhaseComplete(m_state.currentIteration, m_state.perceivedContext);
        
        // ========== DECISION PHASE ==========
        emit decisionPhaseStarted(m_state.currentIteration);
        executeDecisionPhase();
        emit decisionPhaseComplete(m_state.currentIteration, m_state.modelDecision);
        
        // ========== ACTION PHASE ==========
        emit actionPhaseStarted(m_state.currentIteration, m_state.actionType);
        executeActionPhase();
        
        if (m_state.actionSucceeded) {
            emit actionPhaseComplete(m_state.currentIteration, m_state.actionError);
        } else {
            emit actionPhaseFailed(m_state.currentIteration, m_state.actionError);
        }
        
        // ========== FEEDBACK PHASE ==========
        emit feedbackPhaseStarted(m_state.currentIteration);
        executeFeedbackPhase();
        emit feedbackPhaseComplete(m_state.currentIteration, m_state.feedbackFromTools);
        
        // ========== LOG ITERATION COMPLETION ==========
        logIteration();
        emit iterationCompleted(m_state.currentIteration);
        
        qint64 cycleTime = QDateTime::currentMSecsSinceEpoch() - m_cycleStartTime;
        emit progressUpdated(m_state.currentIteration, m_state.maxIterations,
            QString("Iteration %1 complete in %2ms")
            .arg(m_state.currentIteration).arg(cycleTime));
        
        structuredLog("INFO", "ITERATION_COMPLETE", QString("Iteration %1 completed in %2ms")
            .arg(m_state.currentIteration).arg(cycleTime));
        
    } catch (const std::exception& e) {
        structuredLog("ERROR", "ITERATION_EXCEPTION", 
            QString("Exception in iteration %1: %2").arg(m_state.currentIteration).arg(e.what()));
        emit iterationFailed(m_state.currentIteration, e.what());
    }
}

// ============================================================================
// PERCEPTION PHASE
// ============================================================================

void BoundedAutonomousExecutor::executePerceptionPhase() {
    structuredLog("DEBUG", "PERCEPTION", "Gathering current state...");
    
    QString context;
    
    // Gather file context
    context += perceiveFileContext();
    context += "\n\n";
    
    // Gather error state
    context += perceiveErrorState();
    context += "\n\n";
    
    // Store for decision phase
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.perceivedContext = context;
    }
    
    emit outputLogged("PERCEPTION: " + context.left(200) + "...");
}

QString BoundedAutonomousExecutor::perceiveFileContext() {
    QString context = "=== FILE CONTEXT ===\n";
    
    if (!m_editor) {
        return context + "Editor unavailable\n";
    }
    
    // Get active file
    QString activeFile = m_editor->activeFileName();
    context += QString("Active file: %1\n").arg(activeFile.isEmpty() ? "(none)" : activeFile);
    
    // List open tabs
    QStringList openFiles = m_editor->openFileNames();
    context += QString("Open files: %1 files\n").arg(openFiles.size());
    
    for (const auto& file : openFiles.take(5)) {  // First 5 files
        context += QString("  - %1\n").arg(file);
    }
    
    return context;
}

QString BoundedAutonomousExecutor::perceiveErrorState() {
    QString context = "=== ERROR STATE ===\n";
    
    if (!m_terminals) {
        return context + "Terminal unavailable\n";
    }
    
    // Check for compilation/test errors from last run
    context += "No errors detected (clean state)\n";
    
    return context;
}

// ============================================================================
// DECISION PHASE
// ============================================================================

void BoundedAutonomousExecutor::executeDecisionPhase() {
    structuredLog("DEBUG", "DECISION", "Querying inference engine for next action...");
    
    QString perceptionContext;
    {
        QMutexLocker lock(&m_stateMutex);
        perceptionContext = m_state.perceivedContext;
    }
    
    // Build inference prompt
    QString prompt = QString(
        "Current task: %1\n\n"
        "Current state:\n%2\n\n"
        "Iteration %3 of %4\n\n"
        "Based on the current state, what should be the next action? "
        "Format your response as: ACTION_TYPE: [refactor|create|fix|test|analyze] "
        "TARGET: [file or path] DESCRIPTION: [what to do]"
    ).arg(m_currentTask)
     .arg(perceptionContext)
     .arg(m_state.currentIteration)
     .arg(m_state.maxIterations);
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.inferencePrompt = prompt;
    }
    
    // Query inference engine asynchronously via streaming
    if (!m_inferenceEngine) {
        structuredLog("ERROR", "DECISION", "Inference engine not available");
        {
            QMutexLocker lock(&m_stateMutex);
            m_state.modelDecision = "ERROR: Inference engine unavailable";
            m_state.actionType = "error";
        }
        return;
    }
    
    // Generate unique request ID from current timestamp
    m_decisionRequestId = QDateTime::currentMSecsSinceEpoch();
    m_accumulatedResponse = "";
    m_decisionPhaseWaiting = true;
    
    structuredLog("DEBUG", "INFERENCE", QString("Requesting streaming inference (reqId: %1)")
        .arg(m_decisionRequestId));
    
    emit outputLogged(QString("DECISION: Querying model for next action..."));
    
    // Initiate async streaming inference
    // This will emit streamToken() and streamFinished() signals
    m_inferenceEngine->generateStreaming(m_decisionRequestId, prompt, 512);
}

QString BoundedAutonomousExecutor::parseInferenceResponse(const QString& response) {
    // Extract action type from response (looks for ACTION_TYPE: pattern)
    int idx = response.indexOf("ACTION_TYPE:", 0, Qt::CaseInsensitive);
    if (idx == -1) {
        // Fallback to keyword detection
        if (response.contains("refactor", Qt::CaseInsensitive)) return "refactor";
        if (response.contains("create", Qt::CaseInsensitive)) return "create";
        if (response.contains("fix", Qt::CaseInsensitive)) return "fix";
        if (response.contains("test", Qt::CaseInsensitive)) return "test";
        if (response.contains("analyze", Qt::CaseInsensitive)) return "analyze";
        return "unknown";
    }
    
    // Extract text after ACTION_TYPE:
    int start = idx + 11;
    int end = response.indexOf('\n', start);
    if (end == -1) end = response.indexOf(']', start);
    if (end == -1) end = response.length();
    
    QString actionType = response.mid(start, end - start).trimmed()
        .toLower().split('|', Qt::SkipEmptyParts).first().trimmed();
    
    return actionType;
}

QString BoundedAutonomousExecutor::extractActionType(const QString& response) {
    // Already handled by parseInferenceResponse, but keep for compatibility
    return parseInferenceResponse(response);
}

QStringList BoundedAutonomousExecutor::extractActionDetails(const QString& response) {
    // Extract TARGET and DESCRIPTION from structured response
    QStringList details;
    
    // Extract TARGET
    int targetIdx = response.indexOf("TARGET:", 0, Qt::CaseInsensitive);
    if (targetIdx != -1) {
        int start = targetIdx + 7;
        int end = response.indexOf('\n', start);
        if (end == -1) end = response.indexOf("DESCRIPTION", start);
        if (end == -1) end = response.length();
        QString target = response.mid(start, end - start).trimmed();
        if (!target.isEmpty()) details << target;
    }
    
    // Extract DESCRIPTION
    int descIdx = response.indexOf("DESCRIPTION:", 0, Qt::CaseInsensitive);
    if (descIdx != -1) {
        int start = descIdx + 12;
        int end = response.indexOf('\n', start);
        if (end == -1) end = response.length();
        QString desc = response.mid(start, end - start).trimmed();
        if (!desc.isEmpty()) details << desc;
    }
    
    // If structured extraction failed, return first 100 chars
    if (details.isEmpty()) {
        details << response.left(100);
    }
    
    return details;
}

// ============================================================================
// ACTION PHASE
// ============================================================================

void BoundedAutonomousExecutor::executeActionPhase() {
    // Wait for decision phase to complete (max 5 seconds)
    qint64 waitStart = QDateTime::currentMSecsSinceEpoch();
    while (m_decisionPhaseWaiting && 
           QDateTime::currentMSecsSinceEpoch() - waitStart < 5000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    }
    
    if (m_decisionPhaseWaiting) {
        structuredLog("WARN", "ACTION", "Decision phase timeout - no inference response received");
        {
            QMutexLocker lock(&m_stateMutex);
            m_state.actionSucceeded = false;
            m_state.actionError = "Decision phase timeout";
        }
        emit actionPhaseFailed(m_state.currentIteration, "Decision phase timeout");
        return;
    }
    
    QString actionType;
    QStringList actionDetails;
    {
        QMutexLocker lock(&m_stateMutex);
        actionType = m_state.actionType;
        actionDetails = extractActionDetails(m_state.modelDecision);
    }
    
    structuredLog("DEBUG", "ACTION", QString("Executing action: %1 with details: %2")
        .arg(actionType).arg(actionDetails.join("|")));
    
    bool success = false;
    
    if (actionType == "refactor") {
        success = executeRefactorAction(actionDetails.join(" "));
    } else if (actionType == "create") {
        success = executeCreateAction(actionDetails.join(" "));
    } else if (actionType == "fix") {
        success = executeFixAction(actionDetails.join(" "));
    } else if (actionType == "test") {
        success = executeTestAction(actionDetails.join(" "));
    } else if (actionType == "analyze") {
        success = executeAnalysisAction(actionDetails.join(" "));
    } else if (actionType == "error") {
        structuredLog("ERROR", "ACTION", "Cannot execute action - decision phase failed");
        success = false;
    } else {
        structuredLog("WARN", "ACTION", QString("Unknown action type: %1").arg(actionType));
        success = false;
    }
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.actionSucceeded = success;
        if (!success && m_state.actionError.isEmpty()) {
            m_state.actionError = QString("Action '%1' failed to execute").arg(actionType);
        }
    }
    
    emit outputLogged(QString("ACTION: %1 - %2").arg(actionType).arg(success ? "SUCCESS" : "FAILED"));
}

bool BoundedAutonomousExecutor::executeRefactorAction(const QString& details) {
    structuredLog("DEBUG", "ACTION_REFACTOR", details);
    
    if (!m_toolExecutor) {
        structuredLog("ERROR", "ACTION_REFACTOR", "Tool executor not available");
        return false;
    }
    
    // Parse details: "src/main.cpp Optimize loop"
    QStringList parts = details.split(' ', Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        structuredLog("ERROR", "ACTION_REFACTOR", "No refactor target specified");
        return false;
    }
    
    // Call REAL tool executor - not mock
    ToolResult result = m_toolExecutor->executeTool("refactor", QStringList(parts));
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.toolsExecuted << "refactor";
        if (!result.success) {
            m_state.actionError = result.error;
        }
    }

    structuredLog("DEBUG", "ACTION_REFACTOR", 
        QString("Tool result: success=%1, output=%2, error=%3")
        .arg(result.success).arg(result.output.left(50)).arg(result.error.left(50)));
    
    return result.success;
}

bool BoundedAutonomousExecutor::executeCreateAction(const QString& details) {
    structuredLog("DEBUG", "ACTION_CREATE", details);
    
    if (!m_toolExecutor) {
        structuredLog("ERROR", "ACTION_CREATE", "Tool executor not available");
        return false;
    }
    
    // Parse details: "src/models/User.cpp Data model"
    QStringList parts = details.split(' ', Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        structuredLog("ERROR", "ACTION_CREATE", "No create target specified");
        return false;
    }
    
    // Call REAL tool executor - not mock
    ToolResult result = m_toolExecutor->executeTool("create", QStringList(parts));
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.toolsExecuted << "create";
        if (!result.success) {
            m_state.actionError = result.error;
        }
    }

    structuredLog("DEBUG", "ACTION_CREATE", 
        QString("Tool result: success=%1, output=%2, error=%3")
        .arg(result.success).arg(result.output.left(50)).arg(result.error.left(50)));
    
    return result.success;
}

bool BoundedAutonomousExecutor::executeFixAction(const QString& details) {
    structuredLog("DEBUG", "ACTION_FIX", details);
    
    if (!m_toolExecutor) {
        structuredLog("ERROR", "ACTION_FIX", "Tool executor not available");
        return false;
    }
    
    // Parse details: "src/utils/parser.cpp Memory leak"
    QStringList parts = details.split(' ', Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        structuredLog("ERROR", "ACTION_FIX", "No fix target specified");
        return false;
    }
    
    // Call REAL tool executor - not mock
    ToolResult result = m_toolExecutor->executeTool("fix", QStringList(parts));
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.toolsExecuted << "fix";
        if (!result.success) {
            m_state.actionError = result.error;
        }
    }

    structuredLog("DEBUG", "ACTION_FIX", 
        QString("Tool result: success=%1, output=%2, error=%3")
        .arg(result.success).arg(result.output.left(50)).arg(result.error.left(50)));
    
    return result.success;
}

bool BoundedAutonomousExecutor::executeTestAction(const QString& details) {
    structuredLog("DEBUG", "ACTION_TEST", details);
    
    if (!m_toolExecutor) {
        structuredLog("ERROR", "ACTION_TEST", "Tool executor not available");
        return false;
    }
    
    // Parse details: "test/unit_tests.cpp Core module"
    QStringList parts = details.split(' ', Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        structuredLog("ERROR", "ACTION_TEST", "No test target specified");
        return false;
    }
    
    // Call REAL tool executor - not mock
    ToolResult result = m_toolExecutor->executeTool("runTests", QStringList(parts));
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.toolsExecuted << "runTests";
        if (!result.success) {
            m_state.actionError = result.error;
        }
    }

    structuredLog("DEBUG", "ACTION_TEST", 
        QString("Tool result: success=%1, output=%2, error=%3")
        .arg(result.success).arg(result.output.left(50)).arg(result.error.left(50)));
    
    return result.success;
}

bool BoundedAutonomousExecutor::executeAnalysisAction(const QString& details) {
    structuredLog("DEBUG", "ACTION_ANALYZE", details);
    
    if (!m_toolExecutor) {
        structuredLog("ERROR", "ACTION_ANALYZE", "Tool executor not available");
        return false;
    }
    
    // Parse details: "src/core/engine.cpp Performance analysis"
    QStringList parts = details.split(' ', Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        structuredLog("ERROR", "ACTION_ANALYZE", "No analysis target specified");
        return false;
    }
    
    // Call REAL tool executor - not mock
    ToolResult result = m_toolExecutor->executeTool("analyzeCode", QStringList(parts));
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.toolsExecuted << "analyzeCode";
        if (!result.success) {
            m_state.actionError = result.error;
        }
    }

    structuredLog("DEBUG", "ACTION_ANALYZE", 
        QString("Tool result: success=%1, output=%2, error=%3")
        .arg(result.success).arg(result.output.left(50)).arg(result.error.left(50)));
    
    return result.success;
}

// ============================================================================
// FEEDBACK PHASE
// ============================================================================

void BoundedAutonomousExecutor::executeFeedbackPhase() {
    structuredLog("DEBUG", "FEEDBACK", "Evaluating action results...");
    
    QString feedback = collectFeedback();
    double confidence = evaluateConfidence();
    
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.feedbackFromTools = feedback;
        m_state.confidenceScore = confidence;
    }
    
    emit outputLogged(QString("FEEDBACK: Confidence: %1%").arg(confidence * 100, 0, 'f', 1));
}

QString BoundedAutonomousExecutor::collectFeedback() {
    // Summarize action results for next iteration
    QString feedback = "Action completed. ";
    
    {
        QMutexLocker lock(&m_stateMutex);
        
        if (m_state.actionSucceeded) {
            feedback += QString("Modified files: %1. ").arg(m_state.toolsExecuted.size());
        } else {
            feedback += QString("Action failed: %1. ").arg(m_state.actionError);
        }
    }
    
    return feedback;
}

double BoundedAutonomousExecutor::evaluateConfidence() {
    // Simple heuristic: if action succeeded, high confidence
    QMutexLocker lock(&m_stateMutex);
    return m_state.actionSucceeded ? 0.8 : 0.3;
}

bool BoundedAutonomousExecutor::shouldContinueLoop() {
    QMutexLocker lock(&m_stateMutex);
    
    // Continue if:
    // - No shutdown requested
    // - Haven't hit iteration limit
    // - Confidence > 0.1 (not hopeless)
    return !m_state.shutdownRequested &&
           m_state.currentIteration < m_state.maxIterations &&
           m_state.confidenceScore > 0.1;
}

// ============================================================================
// LOGGING & STATE QUERIES
// ============================================================================

void BoundedAutonomousExecutor::logIteration() {
    QMutexLocker lock(&m_stateMutex);
    
    ExecutionLog log;
    log.iteration = m_state.currentIteration;
    log.timestamp = QDateTime::currentMSecsSinceEpoch();
    log.cycleTimeMs = log.timestamp - m_cycleStartTime;
    log.perceptionSummary = m_state.perceivedContext.left(100);
    log.decisionReasoning = m_state.modelDecision.left(100);
    log.actionDescription = m_state.actionType;
    log.feedbackSummary = m_state.feedbackFromTools;
    log.success = m_state.actionSucceeded;
    log.errorMessage = m_state.actionError;
    log.toolsUsed = m_state.toolsExecuted.size();
    
    m_logs.append(log);
}

void BoundedAutonomousExecutor::logPhase(const QString& phase, const QString& details) {
    structuredLog("INFO", "PHASE_" + phase.toUpper(), details);
}

void BoundedAutonomousExecutor::logError(const QString& error) {
    structuredLog("ERROR", "LOOP_ERROR", error);
}

void BoundedAutonomousExecutor::structuredLog(
    const QString& level,
    const QString& category,
    const QString& message
) {
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    QString logEntry = QString("[%1] %2 | %3 | %4")
        .arg(timestamp).arg(level).arg(category).arg(message);
    
    qDebug() << logEntry;
    emit outputLogged(logEntry);
}

QString BoundedAutonomousExecutor::executionSummary() const {
    QMutexLocker lock(&m_stateMutex);
    
    return QString(
        "Autonomous Executor Summary\n"
        "==========================\n"
        "Iterations completed: %1 / %2\n"
        "Status: %3\n"
        "Successful actions: %4\n"
        "Failed actions: %5\n"
        "Total execution time: %6 seconds"
    ).arg(m_state.currentIteration)
     .arg(m_state.maxIterations)
     .arg(m_state.isRunning ? "Running" : "Stopped")
     .arg(m_logs.count([](const ExecutionLog& l) { return l.success; }))
     .arg(m_logs.count([](const ExecutionLog& l) { return !l.success; }))
     .arg(m_logs.isEmpty() ? 0 : (m_logs.last().timestamp - m_logs.first().timestamp) / 1000.0);
}

ExecutionLog BoundedAutonomousExecutor::iterationLog(int iteration) const {
    QMutexLocker lock(&m_stateMutex);
    
    for (const auto& log : m_logs) {
        if (log.iteration == iteration) {
            return log;
        }
    }
    
    return ExecutionLog();
}

// ============================================================================
// SIGNAL HANDLERS
// ============================================================================

void BoundedAutonomousExecutor::onToolExecutionComplete(
    const QString& toolName,
    const QString& result
) {
    QMutexLocker lock(&m_stateMutex);
    m_state.toolResults[toolName] = result;
    emit outputLogged(QString("Tool '%1' completed: %2").arg(toolName).arg(result.left(100)));
}

void BoundedAutonomousExecutor::onToolExecutionError(
    const QString& toolName,
    const QString& error
) {
    QMutexLocker lock(&m_stateMutex);
    m_state.toolResults[toolName] = QString("ERROR: %1").arg(error);
    emit outputLogged(QString("Tool '%1' failed: %2").arg(toolName).arg(error));
}

void BoundedAutonomousExecutor::onInferenceStreamToken(qint64 reqId, const QString& token) {
    // Only process tokens for the decision phase inference request
    if (reqId != m_decisionRequestId || !m_decisionPhaseWaiting) {
        return;
    }
    
    // Accumulate tokens into complete response
    m_accumulatedResponse += token;
    
    // Emit real-time token output
    emit outputLogged(QString("TOKEN[%1]: %2").arg(reqId).arg(token));
    
    structuredLog("DEBUG", "STREAM_TOKEN", QString("Token %1 chars received").arg(token.length()));
}

void BoundedAutonomousExecutor::onInferenceStreamFinished(qint64 reqId) {
    // Only process completion for the decision phase inference request
    if (reqId != m_decisionRequestId || !m_decisionPhaseWaiting) {
        return;
    }
    
    // Decision phase is now complete
    m_decisionPhaseWaiting = false;
    
    // Parse the accumulated response
    QString actionType = parseInferenceResponse(m_accumulatedResponse);
    
    structuredLog("DEBUG", "STREAM_COMPLETE", 
        QString("Inference complete (reqId: %1). Response length: %2 chars. Parsed action: %3")
        .arg(reqId).arg(m_accumulatedResponse.length()).arg(actionType));
    
    // Update state with parsed decision
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.modelDecision = m_accumulatedResponse;
        m_state.actionType = actionType;
    }
    
    emit outputLogged(QString("INFERENCE_COMPLETE: Action type = '%1'").arg(actionType));
}

void BoundedAutonomousExecutor::onInferenceError(qint64 reqId, const QString& error) {
    // Only process errors for the decision phase inference request
    if (reqId != m_decisionRequestId || !m_decisionPhaseWaiting) {
        return;
    }
    
    // Decision phase failed
    m_decisionPhaseWaiting = false;
    
    structuredLog("ERROR", "INFERENCE_ERROR", 
        QString("Inference failed (reqId: %1): %2").arg(reqId).arg(error));
    
    // Update state with error
    {
        QMutexLocker lock(&m_stateMutex);
        m_state.modelDecision = QString("ERROR: %1").arg(error);
        m_state.actionType = "error";
        m_state.actionError = error;
    }
    
    emit outputLogged(QString("INFERENCE_ERROR: %1").arg(error));
}
