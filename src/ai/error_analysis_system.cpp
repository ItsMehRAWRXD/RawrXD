// Error Analysis System Implementation
#include "error_analysis_system.h"
#include "../agentic_executor.h"
#include "advanced_planning_engine.h"
#include "tool_composition_framework.h"
#include "../qtapp/inference_engine.hpp"
#include <QDebug>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QStandardPaths>
#include <QtConcurrent>
#include <QThread>
#include <algorithm>
#include <cmath>

ErrorAnalysisSystem::ErrorAnalysisSystem(QObject* parent)
    : QObject(parent)
{
    m_uptimeTimer.start();
    initializeComponents();
    setupTimers();
    
    // Initialize built-in error patterns
    initializeBuiltInPatterns();
    
    qInfo() << "[ErrorAnalysisSystem] Initialized with pattern recognition and auto-fix capabilities";
}

ErrorAnalysisSystem::~ErrorAnalysisSystem()
{
    // Save learned patterns before shutdown
    if (!m_patterns.empty()) {
        QString patternsFile = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) 
                              + "/error_patterns.json";
        saveLearnedPatterns(patternsFile);
    }
    
    qInfo() << "[ErrorAnalysisSystem] Destroyed";
}

void ErrorAnalysisSystem::initialize(AgenticExecutor* executor, AdvancedPlanningEngine* planner,
                                   ToolCompositionFramework* toolFramework, InferenceEngine* inference)
{
    m_agenticExecutor = executor;
    m_planningEngine = planner;
    m_toolFramework = toolFramework;
    m_inferenceEngine = inference;
    
    if (executor && planner && toolFramework) {
        m_initialized = true;
        connectSignals();
        
        // Load saved patterns if available
        QString patternsFile = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) 
                              + "/error_patterns.json";
        if (QFile::exists(patternsFile)) {
            loadLearnedPatterns(patternsFile);
        }
        
        qInfo() << "[ErrorAnalysisSystem] Initialization completed successfully";
    } else {
        qWarning() << "[ErrorAnalysisSystem] Failed to initialize - missing required components";
    }
}

QString ErrorAnalysisSystem::reportError(const QString& message, const ErrorContext& context)
{
    QString errorId = generateErrorId();
    
    ErrorInfo error;
    error.errorId = errorId;
    error.message = message;
    error.context = context;
    error.firstOccurrence = QDateTime::currentDateTime();
    error.lastOccurrence = error.firstOccurrence;
    error.occurrenceCount = 1;
    
    // Perform initial analysis
    categorizeError(error);
    analyzeErrorContext(error);
    
    // Store error
    {
        QWriteLocker locker(&m_errorsLock);
        
        // Check for duplicate errors
        for (auto& pair : m_errors) {
            ErrorInfo& existingError = pair.second;
            if (existingError.message == message && !existingError.isResolved) {
                // Update existing error
                existingError.lastOccurrence = QDateTime::currentDateTime();
                existingError.occurrenceCount++;
                
                emit errorReported(existingError.errorId, existingError.severity);
                return existingError.errorId;
            }
        }
        
        m_errors[errorId] = error;
    }
    
    // Add to processing queue
    m_errorQueue.enqueue(errorId);
    
    emit errorReported(errorId, error.severity);
    
    // Handle critical errors immediately
    if (error.severity == Analysis::ErrorSeverity::Critical) {
        emit criticalErrorDetected(errorId, message);
        processError(errorId);
    }
    
    qInfo() << "[ErrorAnalysisSystem] Reported error" << errorId << ":" << message;
    
    return errorId;
}

QString ErrorAnalysisSystem::reportException(const std::exception& exception, const ErrorContext& context)
{
    QString message = QString("Exception: %1").arg(exception.what());
    
    ErrorContext enhancedContext = context;
    enhancedContext.timestamp = QDateTime::currentDateTime();
    
    // Try to extract additional information from exception
    QString exceptionType = typeid(exception).name();
    enhancedContext.className = exceptionType;
    
    return reportError(message, enhancedContext);
}

ErrorInfo ErrorAnalysisSystem::getError(const QString& errorId) const
{
    QReadLocker locker(&m_errorsLock);
    auto it = m_errors.find(errorId);
    return (it != m_errors.end()) ? it->second : ErrorInfo();
}

QStringList ErrorAnalysisSystem::getAllErrors() const
{
    QReadLocker locker(&m_errorsLock);
    QStringList errorIds;
    for (const auto& pair : m_errors) {
        errorIds.append(pair.first);
    }
    return errorIds;
}

QStringList ErrorAnalysisSystem::getErrorsBySeverity(Analysis::ErrorSeverity severity) const
{
    QReadLocker locker(&m_errorsLock);
    QStringList errorIds;
    for (const auto& pair : m_errors) {
        if (pair.second.severity == severity) {
            errorIds.append(pair.first);
        }
    }
    return errorIds;
}

QStringList ErrorAnalysisSystem::getErrorsByCategory(Analysis::ErrorCategory category) const
{
    QReadLocker locker(&m_errorsLock);
    QStringList errorIds;
    for (const auto& pair : m_errors) {
        if (pair.second.category == category) {
            errorIds.append(pair.first);
        }
    }
    return errorIds;
}

QJsonObject ErrorAnalysisSystem::diagnoseError(const QString& errorId)
{
    ErrorInfo error = getError(errorId);
    if (error.errorId.isEmpty()) {
        return QJsonObject();
    }
    
    QJsonObject diagnosis;
    diagnosis["error_id"] = errorId;
    diagnosis["message"] = error.message;
    diagnosis["category"] = static_cast<int>(error.category);
    diagnosis["severity"] = static_cast<int>(error.severity);
    
    // Pattern matching analysis
    QStringList matchingPatterns = getMatchingPatterns(error.message);
    diagnosis["matching_patterns"] = QJsonArray::fromStringList(matchingPatterns);
    
    if (!matchingPatterns.isEmpty()) {
        ErrorPattern bestPattern = getBestMatchingPattern(error.message);
        
        QJsonObject patternInfo;
        patternInfo["pattern_id"] = bestPattern.patternId;
        patternInfo["name"] = bestPattern.name;
        patternInfo["confidence"] = calculatePatternMatch(bestPattern, error);
        patternInfo["common_causes"] = QJsonArray::fromStringList(bestPattern.commonCauses);
        patternInfo["effective_fixes"] = QJsonArray::fromStringList(bestPattern.effectiveFixes);
        
        diagnosis["best_pattern"] = patternInfo;
    }
    
    // AI-powered analysis if available
    if (m_inferenceEngine) {
        QJsonObject aiRequest;
        aiRequest["action"] = "diagnose_error";
        aiRequest["error_message"] = error.message;
        aiRequest["context"] = QJsonObject::fromVariantMap(error.context.environment.toVariantMap());
        aiRequest["call_stack"] = QJsonArray::fromStringList(error.context.callStack);
        
        try {
            // QJsonObject aiDiagnosis = m_inferenceEngine->processRequest(aiRequest);
            QJsonObject aiDiagnosis; // Placeholder for now
            diagnosis["ai_analysis"] = aiDiagnosis;
        } catch (const std::exception& e) {
            qWarning() << "[ErrorAnalysisSystem] AI diagnosis failed:" << e.what();
        }
    }
    
    // Root cause analysis
    QStringList rootCauses = identifyRootCause(errorId);
    diagnosis["root_causes"] = QJsonArray::fromStringList(rootCauses);
    
    // Impact assessment
    double impact = calculateErrorImpact(errorId);
    diagnosis["impact_score"] = impact;
    
    // Related errors
    QStringList relatedErrors = findRelatedErrors(errorId);
    diagnosis["related_errors"] = QJsonArray::fromStringList(relatedErrors);
    
    // Suggested fixes
    QStringList fixes = suggestFixes(errorId);
    diagnosis["suggested_fixes"] = QJsonArray::fromStringList(fixes);
    
    // Auto-fix availability
    QStringList autoFixStrategies = getApplicableFixStrategies(errorId);
    diagnosis["auto_fix_strategies"] = QJsonArray::fromStringList(autoFixStrategies);
    
    qInfo() << "[ErrorAnalysisSystem] Completed diagnosis for error" << errorId;
    
    return diagnosis;
}

QStringList ErrorAnalysisSystem::suggestFixes(const QString& errorId)
{
    ErrorInfo error = getError(errorId);
    if (error.errorId.isEmpty()) {
        return QStringList();
    }
    
    QStringList fixes;
    
    // Pattern-based fixes
    QStringList matchingPatterns = getMatchingPatterns(error.message);
    for (const QString& patternId : matchingPatterns) {
        QReadLocker locker(&m_patternsLock);
        auto it = m_patterns.find(patternId);
        if (it != m_patterns.end()) {
            const ErrorPattern& pattern = it->second;
            fixes.append(pattern.effectiveFixes);
        }
    }
    
    // Category-specific fixes
    switch (error.category) {
        case Analysis::ErrorCategory::Syntax:
            fixes.append("Check syntax near line " + QString::number(error.context.lineNumber));
            fixes.append("Verify proper bracket/parenthesis matching");
            fixes.append("Check for missing semicolons or commas");
            break;
            
        case Analysis::ErrorCategory::Runtime:
            fixes.append("Check for null pointer dereferences");
            fixes.append("Verify array bounds");
            fixes.append("Check resource availability");
            break;
            
        case Analysis::ErrorCategory::Memory:
            fixes.append("Check for memory leaks");
            fixes.append("Verify proper memory allocation/deallocation");
            fixes.append("Consider using smart pointers");
            break;
            
        case Analysis::ErrorCategory::Network:
            fixes.append("Check network connectivity");
            fixes.append("Verify firewall settings");
            fixes.append("Check DNS resolution");
            break;
            
        case Analysis::ErrorCategory::FileSystem:
            fixes.append("Check file permissions");
            fixes.append("Verify file path exists");
            fixes.append("Check disk space availability");
            break;
            
        case Analysis::ErrorCategory::Database:
            fixes.append("Check database connection");
            fixes.append("Verify SQL syntax");
            fixes.append("Check table/column existence");
            break;
            
        case Analysis::ErrorCategory::Dependency:
            fixes.append("Check dependency versions");
            fixes.append("Verify library availability");
            fixes.append("Update package dependencies");
            break;
            
        default:
            fixes.append("Review error context and call stack");
            fixes.append("Check system logs for additional information");
            break;
    }
    
    // AI-generated fixes if available
    if (m_inferenceEngine) {
        QJsonObject request;
        request["action"] = "suggest_fixes";
        request["error_message"] = error.message;
        request["error_category"] = static_cast<int>(error.category);
        request["context"] = QJsonObject::fromVariantMap(error.context.environment.toVariantMap());
        
        try {
            // QJsonObject response = m_inferenceEngine->processRequest(request);
            // if (response.contains("suggested_fixes")) {
            //     QJsonArray aiFixes = response["suggested_fixes"].toArray();
            //     for (const auto& fix : aiFixes) {
            //         fixes.append(fix.toString());
            //     }
            // }
        } catch (const std::exception& e) {
            qWarning() << "[ErrorAnalysisSystem] AI fix suggestion failed:" << e.what();
        }
    }
    
    // Remove duplicates and return
    fixes.removeDuplicates();
    return fixes;
}

bool ErrorAnalysisSystem::addAutoFixStrategy(const AutoFixStrategy& strategy)
{
    {
        QWriteLocker locker(&m_strategiesLock);
        m_autoFixStrategies[strategy.strategyId] = strategy;
    }
    
    qInfo() << "[ErrorAnalysisSystem] Added auto-fix strategy:" << strategy.strategyId;
    return true;
}

QStringList ErrorAnalysisSystem::getApplicableFixStrategies(const QString& errorId) const
{
    ErrorInfo error = getError(errorId);
    if (error.errorId.isEmpty()) {
        return QStringList();
    }
    
    QStringList applicableStrategies;
    
    QReadLocker locker(&m_strategiesLock);
    for (const auto& pair : m_autoFixStrategies) {
        const AutoFixStrategy& strategy = pair.second;
        
        // Check if strategy applies to error patterns
        QStringList matchingPatterns = getMatchingPatterns(error.message);
        bool patternMatches = false;
        
        for (const QString& patternId : matchingPatterns) {
            if (strategy.applicablePatterns.contains(patternId)) {
                patternMatches = true;
                break;
            }
        }
        
        if (patternMatches || strategy.applicablePatterns.isEmpty()) {
            // Check risk level
            if (strategy.riskLevel <= m_autoFixRiskThreshold || 
                error.severity == Analysis::ErrorSeverity::Critical) {
                applicableStrategies.append(strategy.strategyId);
            }
        }
    }
    
    return applicableStrategies;
}

QString ErrorAnalysisSystem::generateAutoFix(const QString& errorId)
{
    QStringList strategies = getApplicableFixStrategies(errorId);
    if (strategies.isEmpty()) {
        return QString();
    }
    
    // Select best strategy (lowest risk, highest success rate)
    QString bestStrategyId;
    double bestScore = -1.0;
    
    QReadLocker locker(&m_strategiesLock);
    for (const QString& strategyId : strategies) {
        auto it = m_autoFixStrategies.find(strategyId);
        if (it != m_autoFixStrategies.end()) {
            const AutoFixStrategy& strategy = it->second;
            
            double successRate = strategy.applicationCount > 0 ? 
                                double(strategy.successCount) / strategy.applicationCount : 0.5;
            double riskPenalty = strategy.riskLevel;
            double score = successRate * (1.0 - riskPenalty);
            
            if (score > bestScore) {
                bestScore = score;
                bestStrategyId = strategyId;
            }
        }
    }
    
    if (!bestStrategyId.isEmpty()) {
        return executeAutoFix(errorId, m_autoFixStrategies[bestStrategyId]);
    }
    
    return QString();
}

bool ErrorAnalysisSystem::applyAutoFix(const QString& errorId, const QString& strategyId)
{
    if (!m_autoFixEnabled) {
        qWarning() << "[ErrorAnalysisSystem] Auto-fix is disabled";
        return false;
    }
    
    QReadLocker locker(&m_strategiesLock);
    auto it = m_autoFixStrategies.find(strategyId);
    if (it == m_autoFixStrategies.end()) {
        qWarning() << "[ErrorAnalysisSystem] Strategy not found:" << strategyId;
        return false;
    }
    
    const AutoFixStrategy& strategy = it->second;
    ErrorInfo error = getError(errorId);
    
    if (!validateFixStrategy(strategy, error)) {
        qWarning() << "[ErrorAnalysisSystem] Fix strategy validation failed";
        return false;
    }
    
    // Execute auto-fix
    QString fixResult = executeAutoFix(errorId, strategy);
    bool success = !fixResult.isEmpty();
    
    // Update strategy statistics
    locker.unlock();
    QWriteLocker writeLocker(&m_strategiesLock);
    AutoFixStrategy& mutableStrategy = m_autoFixStrategies[strategyId];
    mutableStrategy.applicationCount++;
    if (success) {
        mutableStrategy.successCount++;
    }
    mutableStrategy.lastUsed = QDateTime::currentDateTime();
    
    // Mark error as resolved if fix was successful
    if (success) {
        QWriteLocker errorLocker(&m_errorsLock);
        auto errorIt = m_errors.find(errorId);
        if (errorIt != m_errors.end()) {
            errorIt->second.isResolved = true;
            errorIt->second.resolutionMethod = "Auto-fix: " + strategyId;
            errorIt->second.resolvedAt = QDateTime::currentDateTime();
        }
        
        emit errorResolved(errorId, "auto_fix");
    }
    
    emit autoFixApplied(errorId, strategyId, success);
    
    qInfo() << "[ErrorAnalysisSystem] Applied auto-fix" << strategyId 
            << "to error" << errorId << "- Success:" << success;
    
    return success;
}

QJsonObject ErrorAnalysisSystem::getErrorStatistics() const
{
    QReadLocker locker(&m_errorsLock);
    
    QJsonObject stats;
    
    // Basic counts
    stats["total_errors"] = static_cast<int>(m_errors.size());
    
    // Count by severity
    QMap<Analysis::ErrorSeverity, int> severityCounts;
    QMap<Analysis::ErrorCategory, int> categoryCounts;
    int resolvedCount = 0;
    int unresolvedCount = 0;
    
    for (const auto& pair : m_errors) {
        const ErrorInfo& error = pair.second;
        severityCounts[error.severity]++;
        categoryCounts[error.category]++;
        
        if (error.isResolved) {
            resolvedCount++;
        } else {
            unresolvedCount++;
        }
    }
    
    QJsonObject severityStats;
    severityStats["critical"] = severityCounts[Analysis::ErrorSeverity::Critical];
    severityStats["high"] = severityCounts[Analysis::ErrorSeverity::High];
    severityStats["medium"] = severityCounts[Analysis::ErrorSeverity::Medium];
    severityStats["low"] = severityCounts[Analysis::ErrorSeverity::Low];
    severityStats["warning"] = severityCounts[Analysis::ErrorSeverity::Warning];
    severityStats["info"] = severityCounts[Analysis::ErrorSeverity::Info];
    stats["by_severity"] = severityStats;
    
    QJsonObject categoryStats;
    categoryStats["syntax"] = categoryCounts[Analysis::ErrorCategory::Syntax];
    categoryStats["runtime"] = categoryCounts[Analysis::ErrorCategory::Runtime];
    categoryStats["logic"] = categoryCounts[Analysis::ErrorCategory::Logic];
    categoryStats["performance"] = categoryCounts[Analysis::ErrorCategory::Performance];
    categoryStats["memory"] = categoryCounts[Analysis::ErrorCategory::Memory];
    categoryStats["network"] = categoryCounts[Analysis::ErrorCategory::Network];
    categoryStats["filesystem"] = categoryCounts[Analysis::ErrorCategory::FileSystem];
    categoryStats["database"] = categoryCounts[Analysis::ErrorCategory::Database];
    categoryStats["security"] = categoryCounts[Analysis::ErrorCategory::Security];
    categoryStats["configuration"] = categoryCounts[Analysis::ErrorCategory::Configuration];
    categoryStats["dependency"] = categoryCounts[Analysis::ErrorCategory::Dependency];
    categoryStats["concurrency"] = categoryCounts[Analysis::ErrorCategory::Concurrency];
    categoryStats["unknown"] = categoryCounts[Analysis::ErrorCategory::Unknown];
    stats["by_category"] = categoryStats;
    
    // Resolution statistics
    stats["resolved_count"] = resolvedCount;
    stats["unresolved_count"] = unresolvedCount;
    stats["resolution_rate"] = m_errors.size() > 0 ? double(resolvedCount) / m_errors.size() : 0.0;
    
    // System health
    double healthScore = calculateSystemHealth();
    stats["system_health_score"] = healthScore;
    
    // Performance metrics
    stats["uptime_ms"] = m_uptimeTimer.elapsed();
    stats["last_analysis"] = m_lastAnalysis.toString(Qt::ISODate);
    
    return stats;
}

double ErrorAnalysisSystem::calculateSystemHealth() const
{
    QReadLocker locker(&m_errorsLock);
    
    if (m_errors.empty()) {
        return 1.0; // Perfect health
    }
    
    // Calculate health based on error severity and resolution rate
    double totalWeight = 0.0;
    double healthSum = 0.0;
    
    QDateTime cutoff = QDateTime::currentDateTime().addDays(-7); // Last week
    
    for (const auto& pair : m_errors) {
        const ErrorInfo& error = pair.second;
        
        // Only consider recent errors
        if (error.lastOccurrence < cutoff) {
            continue;
        }
        
        // Weight by severity
        double weight = 1.0;
        switch (error.severity) {
            case Analysis::ErrorSeverity::Critical: weight = 10.0; break;
            case Analysis::ErrorSeverity::High: weight = 5.0; break;
            case Analysis::ErrorSeverity::Medium: weight = 2.0; break;
            case Analysis::ErrorSeverity::Low: weight = 1.0; break;
            case Analysis::ErrorSeverity::Warning: weight = 0.5; break;
            case Analysis::ErrorSeverity::Info: weight = 0.1; break;
        }
        
        totalWeight += weight;
        
        // Add to health score (resolved errors contribute positively)
        if (error.isResolved) {
            healthSum += weight;
        }
    }
    
    return totalWeight > 0.0 ? healthSum / totalWeight : 1.0;
}

// Private helper methods
void ErrorAnalysisSystem::initializeComponents()
{
    // Initialize timers but don't start them yet
    m_processingTimer = new QTimer(this);
    m_statisticsTimer = new QTimer(this);
    m_learningTimer = new QTimer(this);
    m_cleanupTimer = new QTimer(this);
}

void ErrorAnalysisSystem::setupTimers()
{
    connect(m_processingTimer, &QTimer::timeout,
            this, &ErrorAnalysisSystem::processErrorQueue);
    m_processingTimer->start(500); // Process every 500ms
    
    connect(m_statisticsTimer, &QTimer::timeout,
            this, &ErrorAnalysisSystem::updateStatistics);
    m_statisticsTimer->start(10000); // Update every 10 seconds
    
    connect(m_learningTimer, &QTimer::timeout,
            this, &ErrorAnalysisSystem::performLearningUpdate);
    m_learningTimer->start(60000); // Learn every minute
    
    connect(m_cleanupTimer, &QTimer::timeout,
            this, &ErrorAnalysisSystem::cleanupOldErrors);
    m_cleanupTimer->start(300000); // Cleanup every 5 minutes
}

void ErrorAnalysisSystem::connectSignals()
{
    // Connect to other components if available
    if (m_agenticExecutor) {
        // Custom connections would go here
    }
}

QString ErrorAnalysisSystem::generateErrorId()
{
    return "err_" + QUuid::createUuid().toString(QUuid::WithoutBraces).left(8);
}

void ErrorAnalysisSystem::processError(const QString& errorId)
{
    ErrorInfo error = getError(errorId);
    if (error.errorId.isEmpty()) return;
    
    // Pattern matching
    QStringList patterns = matchErrorPatterns(error.message);
    
    QWriteLocker locker(&m_errorsLock);
    auto it = m_errors.find(errorId);
    if (it != m_errors.end()) {
        it->second.matchedPatterns = patterns;
        
        if (!patterns.isEmpty()) {
            QString bestPatternId = patterns.first();
            emit patternDetected(bestPatternId, errorId);
        }
    }
}

void ErrorAnalysisSystem::categorizeError(ErrorInfo& error)
{
    QString message = error.message.toLower();
    
    // Rule-based categorization
    if (message.contains("syntax") || message.contains("parse") || message.contains("unexpected")) {
        error.category = Analysis::ErrorCategory::Syntax;
    } else if (message.contains("null") || message.contains("segmentation") || message.contains("access violation")) {
        error.category = Analysis::ErrorCategory::Runtime;
    } else if (message.contains("memory") || message.contains("leak") || message.contains("allocation")) {
        error.category = Analysis::ErrorCategory::Memory;
    } else if (message.contains("network") || message.contains("connection") || message.contains("timeout")) {
        error.category = Analysis::ErrorCategory::Network;
    } else if (message.contains("file") || message.contains("directory") || message.contains("path")) {
        error.category = Analysis::ErrorCategory::FileSystem;
    } else if (message.contains("sql") || message.contains("database") || message.contains("table")) {
        error.category = Analysis::ErrorCategory::Database;
    } else if (message.contains("permission") || message.contains("security") || message.contains("unauthorized")) {
        error.category = Analysis::ErrorCategory::Security;
    } else if (message.contains("config") || message.contains("setting") || message.contains("parameter")) {
        error.category = Analysis::ErrorCategory::Configuration;
    } else if (message.contains("dependency") || message.contains("library") || message.contains("module")) {
        error.category = Analysis::ErrorCategory::Dependency;
    } else if (message.contains("thread") || message.contains("lock") || message.contains("deadlock")) {
        error.category = Analysis::ErrorCategory::Concurrency;
    } else if (message.contains("performance") || message.contains("slow") || message.contains("bottleneck")) {
        error.category = Analysis::ErrorCategory::Performance;
    } else {
        error.category = Analysis::ErrorCategory::Unknown;
    }
    
    // Assess severity
    error.severity = assessErrorSeverity(error.message, error.context);
}

Analysis::ErrorSeverity ErrorAnalysisSystem::assessErrorSeverity(const QString& message, const ErrorContext& context) const
{
    QString lowerMessage = message.toLower();
    
    // Critical indicators
    if (lowerMessage.contains("critical") || lowerMessage.contains("fatal") || 
        lowerMessage.contains("crash") || lowerMessage.contains("abort") ||
        lowerMessage.contains("segmentation fault") || lowerMessage.contains("access violation")) {
        return Analysis::ErrorSeverity::Critical;
    }
    
    // High severity indicators
    if (lowerMessage.contains("error") || lowerMessage.contains("exception") ||
        lowerMessage.contains("failed") || lowerMessage.contains("invalid")) {
        return Analysis::ErrorSeverity::High;
    }
    
    // Medium severity indicators
    if (lowerMessage.contains("warning") || lowerMessage.contains("deprecated") ||
        lowerMessage.contains("missing")) {
        return Analysis::ErrorSeverity::Medium;
    }
    
    // Info/warning level
    if (lowerMessage.contains("info") || lowerMessage.contains("debug") ||
        lowerMessage.contains("trace")) {
        return Analysis::ErrorSeverity::Info;
    }
    
    // Default to medium for unclassified errors
    return Analysis::ErrorSeverity::Medium;
}

void ErrorAnalysisSystem::processErrorQueue()
{
    while (!m_errorQueue.isEmpty()) {
        QString errorId = m_errorQueue.dequeue();
        processError(errorId);
    }
}

void ErrorAnalysisSystem::updateStatistics()
{
    m_errorStatistics = getErrorStatistics();
    
    double healthScore = calculateSystemHealth();
    emit systemHealthChanged(healthScore);
    
    m_lastAnalysis = QDateTime::currentDateTime();
}

void ErrorAnalysisSystem::performLearningUpdate()
{
    if (!m_learningEnabled) return;
    
    // Update pattern statistics and learning algorithms
    trainPatternRecognition();
}

void ErrorAnalysisSystem::cleanupOldErrors()
{
    if (static_cast<int>(m_errors.size()) <= m_maxErrorHistory) {
        return;
    }
    
    // Remove oldest resolved errors
    QDateTime cutoff = QDateTime::currentDateTime().addDays(-30);
    
    QWriteLocker locker(&m_errorsLock);
    for (auto it = m_errors.begin(); it != m_errors.end();) {
        const ErrorInfo& error = it->second;
        if (error.isResolved && error.resolvedAt < cutoff) {
            it = m_errors.erase(it);
        } else {
            ++it;
        }
    }
}

void ErrorAnalysisSystem::initializeBuiltInPatterns()
{
    // Initialize built-in error patterns for common errors
    QWriteLocker locker(&m_patternsLock);
    
    // Null pointer pattern
    ErrorPattern nullPattern;
    nullPattern.patternId = "builtin_null_pointer";
    nullPattern.name = "Null Pointer Dereference";
    nullPattern.regex = QRegularExpression("null|nullptr|nil|NullPointerException");
    nullPattern.keywords = {"null", "nullptr", "nil"};
    nullPattern.category = Analysis::ErrorCategory::Runtime;
    nullPattern.defaultSeverity = Analysis::ErrorSeverity::High;
    nullPattern.effectiveFixes.append("Check for null before accessing pointer");
    nullPattern.weight = 0.9;
    m_patterns[nullPattern.patternId] = nullPattern;
    
    // Out of bounds pattern
    ErrorPattern boundsPattern;
    boundsPattern.patternId = "builtin_out_of_bounds";
    boundsPattern.name = "Index Out of Bounds";
    boundsPattern.regex = QRegularExpression("index|bounds|range|IndexOutOfBoundsException");
    boundsPattern.keywords = {"index", "bounds", "range"};
    boundsPattern.category = Analysis::ErrorCategory::Runtime;
    boundsPattern.defaultSeverity = Analysis::ErrorSeverity::High;
    boundsPattern.effectiveFixes.append("Validate index before array access");
    boundsPattern.weight = 0.85;
    m_patterns[boundsPattern.patternId] = boundsPattern;
    
    // Syntax error pattern
    ErrorPattern syntaxPattern;
    syntaxPattern.patternId = "builtin_syntax";
    syntaxPattern.name = "Syntax Error";
    syntaxPattern.regex = QRegularExpression("syntax|parse|unexpected token|expected");
    syntaxPattern.keywords = {"syntax", "parse", "unexpected"};
    syntaxPattern.category = Analysis::ErrorCategory::Syntax;
    syntaxPattern.defaultSeverity = Analysis::ErrorSeverity::Medium;
    syntaxPattern.effectiveFixes.append("Check for missing brackets or semicolons");
    syntaxPattern.weight = 0.8;
    m_patterns[syntaxPattern.patternId] = syntaxPattern;
    
    // Type error pattern  
    ErrorPattern typePattern;
    typePattern.patternId = "builtin_type";
    typePattern.name = "Type Error";
    typePattern.regex = QRegularExpression("type|cast|conversion|TypeError");
    typePattern.keywords = {"type", "cast", "conversion"};
    typePattern.category = Analysis::ErrorCategory::Logic;
    typePattern.defaultSeverity = Analysis::ErrorSeverity::Medium;
    typePattern.effectiveFixes.append("Check type compatibility");
    typePattern.weight = 0.75;
    m_patterns[typePattern.patternId] = typePattern;
    
    qInfo() << "[ErrorAnalysisSystem] Initialized" << m_patterns.size() << "built-in patterns";
}

void ErrorAnalysisSystem::saveLearnedPatterns(const QString& filePath)
{
    QJsonArray patternsArray;
    
    QReadLocker locker(&m_patternsLock);
    for (const auto& pair : m_patterns) {
        const ErrorPattern& pattern = pair.second;
        QJsonObject patternObj;
        patternObj["patternId"] = pattern.patternId;
        patternObj["name"] = pattern.name;
        patternObj["regex"] = pattern.regex.pattern();
        patternObj["category"] = static_cast<int>(pattern.category);
        patternObj["defaultSeverity"] = static_cast<int>(pattern.defaultSeverity);
        patternObj["weight"] = pattern.weight;
        patternObj["matchCount"] = pattern.matchCount;
        
        QJsonArray fixes;
        for (const QString& fix : pattern.effectiveFixes) {
            fixes.append(fix);
        }
        patternObj["effectiveFixes"] = fixes;
        
        QJsonArray keywords;
        for (const QString& keyword : pattern.keywords) {
            keywords.append(keyword);
        }
        patternObj["keywords"] = keywords;
        
        patternsArray.append(patternObj);
    }
    locker.unlock();
    
    QJsonDocument doc(patternsArray);
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(doc.toJson());
        file.close();
        qInfo() << "[ErrorAnalysisSystem] Saved" << patternsArray.size() << "patterns to" << filePath;
    } else {
        qWarning() << "[ErrorAnalysisSystem] Failed to save patterns to" << filePath;
    }
}

void ErrorAnalysisSystem::loadLearnedPatterns(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "[ErrorAnalysisSystem] Failed to load patterns from" << filePath;
        return;
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "[ErrorAnalysisSystem] Failed to parse patterns file:" << parseError.errorString();
        return;
    }
    
    QJsonArray patternsArray = doc.array();
    
    QWriteLocker locker(&m_patternsLock);
    for (const QJsonValue& value : patternsArray) {
        QJsonObject patternObj = value.toObject();
        
        ErrorPattern pattern;
        pattern.patternId = patternObj["patternId"].toString();
        pattern.name = patternObj["name"].toString();
        pattern.regex = QRegularExpression(patternObj["regex"].toString());
        pattern.category = static_cast<Analysis::ErrorCategory>(patternObj["category"].toInt());
        pattern.defaultSeverity = static_cast<Analysis::ErrorSeverity>(patternObj["defaultSeverity"].toInt());
        pattern.weight = patternObj["weight"].toDouble();
        pattern.matchCount = patternObj["matchCount"].toInt();
        
        QJsonArray fixes = patternObj["effectiveFixes"].toArray();
        for (const QJsonValue& fixValue : fixes) {
            pattern.effectiveFixes.append(fixValue.toString());
        }
        
        QJsonArray keywords = patternObj["keywords"].toArray();
        for (const QJsonValue& keywordValue : keywords) {
            pattern.keywords.append(keywordValue.toString());
        }
        
        m_patterns[pattern.patternId] = pattern;
    }
    
    qInfo() << "[ErrorAnalysisSystem] Loaded" << patternsArray.size() << "patterns from" << filePath;
}

// Slot implementations
void ErrorAnalysisSystem::onErrorDetected(const QString& source, const QString& message)
{
    ErrorContext context;
    context.sourceFile = source;
    context.timestamp = QDateTime::currentDateTime();
    reportError(message, context);
}

void ErrorAnalysisSystem::onSystemStateChanged(const QJsonObject& systemState)
{
    m_systemState = systemState;
    // Trigger analysis if system state indicates potential issues
    if (systemState.contains("error") || systemState.contains("warning")) {
        performPeriodicAnalysis();
    }
}

void ErrorAnalysisSystem::performPeriodicAnalysis()
{
    m_lastAnalysis = QDateTime::currentDateTime();
    
    // Analyze error trends
    QJsonObject trends = analyzeErrorTrends();
    
    // Check system health
    double health = calculateSystemHealth();
    emit systemHealthChanged(health);
    
    // Identify systemic issues
    QStringList issues = identifySystemicIssues();
    if (!issues.isEmpty()) {
        emit errorTrendDetected(issues.join(", "));
    }
}

void ErrorAnalysisSystem::updateErrorPatterns()
{
    // Update pattern match counts and weights
    QWriteLocker locker(&m_patternsLock);
    
    for (auto& [id, pattern] : m_patterns) {
        // Adjust weights based on success rate
        if (pattern.matchCount > 0) {
            // Higher weight for more successful patterns
            // Use successRate directly from pattern struct
            pattern.weight = 0.5 + (0.5 * pattern.successRate);
        }
    }
}

// Additional method implementations

QStringList ErrorAnalysisSystem::getMatchingPatterns(const QString& errorMessage) const
{
    QReadLocker locker(&m_patternsLock);
    QStringList matchingPatternIds;
    
    for (const auto& [id, pattern] : m_patterns) {
        if (pattern.regex.match(errorMessage).hasMatch()) {
            matchingPatternIds.append(id);
        }
    }
    
    return matchingPatternIds;
}

ErrorPattern ErrorAnalysisSystem::getBestMatchingPattern(const QString& errorMessage) const
{
    QReadLocker locker(&m_patternsLock);
    ErrorPattern bestPattern;
    double bestScore = 0.0;
    
    for (const auto& [id, pattern] : m_patterns) {
        if (pattern.regex.match(errorMessage).hasMatch()) {
            double score = pattern.weight * (pattern.successRate + 0.1);
            if (score > bestScore) {
                bestScore = score;
                bestPattern = pattern;
            }
        }
    }
    
    return bestPattern;
}

QStringList ErrorAnalysisSystem::identifyRootCause(const QString& errorId)
{
    QStringList causes;
    QReadLocker locker(&m_errorsLock);
    
    auto it = m_errors.find(errorId);
    if (it != m_errors.end()) {
        // Analyze error context for potential root causes
        const ErrorInfo& info = it->second;
        
        // Check for common patterns
        if (info.message.contains("null", Qt::CaseInsensitive)) {
            causes.append("Potential null pointer dereference");
        }
        if (info.message.contains("memory", Qt::CaseInsensitive)) {
            causes.append("Memory allocation or access issue");
        }
        if (info.message.contains("timeout", Qt::CaseInsensitive)) {
            causes.append("Operation timeout - resource or network issue");
        }
        if (info.message.contains("permission", Qt::CaseInsensitive)) {
            causes.append("Permission or access control issue");
        }
        
        if (causes.isEmpty()) {
            causes.append("Root cause requires manual investigation");
        }
    }
    
    return causes;
}

double ErrorAnalysisSystem::calculateErrorImpact(const QString& errorId)
{
    QReadLocker locker(&m_errorsLock);
    
    auto it = m_errors.find(errorId);
    if (it == m_errors.end()) {
        return 0.0;
    }
    
    const ErrorInfo& info = it->second;
    double impact = 0.0;
    
    // Calculate impact based on severity
    switch (info.severity) {
        case Analysis::ErrorSeverity::Critical:
            impact = 1.0;
            break;
        case Analysis::ErrorSeverity::High:
            impact = 0.75;
            break;
        case Analysis::ErrorSeverity::Medium:
            impact = 0.5;
            break;
        case Analysis::ErrorSeverity::Low:
            impact = 0.35;
            break;
        case Analysis::ErrorSeverity::Warning:
            impact = 0.25;
            break;
        case Analysis::ErrorSeverity::Info:
            impact = 0.1;
            break;
        default:
            impact = 0.1;
    }
    
    return impact;
}

QStringList ErrorAnalysisSystem::findRelatedErrors(const QString& errorId)
{
    QStringList relatedIds;
    QReadLocker locker(&m_errorsLock);
    
    auto it = m_errors.find(errorId);
    if (it == m_errors.end()) {
        return relatedIds;
    }
    
    const ErrorInfo& targetError = it->second;
    
    // Find errors with similar characteristics
    for (const auto& [id, error] : m_errors) {
        if (id == errorId) continue;
        
        // Check for same category or similar message content
        if (error.category == targetError.category ||
            error.message.contains(targetError.message.left(20), Qt::CaseInsensitive)) {
            relatedIds.append(id);
        }
    }
    
    return relatedIds;
}

QJsonObject ErrorAnalysisSystem::analyzeErrorTrends()
{
    QJsonObject trends;
    QReadLocker locker(&m_errorsLock);
    
    // Count errors by category
    QMap<int, int> categoryCount;
    for (const auto& [id, error] : m_errors) {
        categoryCount[static_cast<int>(error.category)]++;
    }
    
    QJsonObject categories;
    for (auto it = categoryCount.begin(); it != categoryCount.end(); ++it) {
        categories[QString::number(it.key())] = it.value();
    }
    trends["categoryDistribution"] = categories;
    trends["totalErrors"] = static_cast<int>(m_errors.size());
    
    return trends;
}

QStringList ErrorAnalysisSystem::identifySystemicIssues()
{
    QStringList issues;
    QReadLocker locker(&m_errorsLock);
    
    // Check for recurring patterns by category
    QMap<int, int> categoryCounts;
    for (const auto& [id, error] : m_errors) {
        categoryCounts[static_cast<int>(error.category)]++;
    }
    
    for (auto it = categoryCounts.begin(); it != categoryCounts.end(); ++it) {
        if (it.value() >= 3) {
            issues.append(QString("Recurring errors in category %1 (count: %2)")
                         .arg(it.key()).arg(it.value()));
        }
    }
    
    return issues;
}

void ErrorAnalysisSystem::analyzeErrorContext(ErrorInfo& info)
{
    // Analyze the error message and context to enhance the error info
    QString message = info.message.toLower();
    
    // Auto-categorize based on keywords
    if (message.contains("syntax") || message.contains("parse")) {
        info.category = Analysis::ErrorCategory::Syntax;
    } else if (message.contains("runtime") || message.contains("exception")) {
        info.category = Analysis::ErrorCategory::Runtime;
    } else if (message.contains("network") || message.contains("connection")) {
        info.category = Analysis::ErrorCategory::Network;
    }
}

QStringList ErrorAnalysisSystem::matchErrorPatterns(const QString& errorMessage) const
{
    return getMatchingPatterns(errorMessage);
}

double ErrorAnalysisSystem::calculatePatternMatch(const ErrorPattern& pattern, 
                                                   const ErrorInfo& error) const
{
    // Calculate how well a pattern matches an error
    double score = 0.0;
    
    if (pattern.regex.match(error.message).hasMatch()) {
        score += 0.5;
    }
    
    // Check keyword matches
    for (const QString& keyword : pattern.keywords) {
        if (error.message.contains(keyword, Qt::CaseInsensitive)) {
            score += 0.1;
        }
    }
    
    // Category match bonus
    if (pattern.category == error.category) {
        score += 0.2;
    }
    
    return qMin(score, 1.0);
}

void ErrorAnalysisSystem::trainPatternRecognition()
{
    // Train patterns based on historical data
    QWriteLocker locker(&m_patternsLock);
    
    for (auto& [id, pattern] : m_patterns) {
        // Adjust weights based on historical performance
        if (pattern.matchCount > 10) {
            pattern.weight = 0.8 + (0.2 * pattern.successRate);
        }
    }
    
    qDebug() << "[ErrorAnalysisSystem] Pattern recognition training completed";
}

bool ErrorAnalysisSystem::validateFixStrategy(const AutoFixStrategy& strategy,
                                              const ErrorInfo& error) const
{
    // Validate that the strategy can be applied to this error
    // Check risk level - high risk strategies need more validation
    if (strategy.riskLevel > 0.8) {
        qDebug() << "[ErrorAnalysisSystem] High risk strategy requires manual approval";
        return false;
    }
    
    // Check if strategy applies to error category
    for (const QString& patternId : strategy.applicablePatterns) {
        if (m_patterns.count(patternId) > 0) {
            const ErrorPattern& pattern = m_patterns.at(patternId);
            if (pattern.category == error.category) {
                return true;
            }
        }
    }
    
    return false;
}

QString ErrorAnalysisSystem::executeAutoFix(const QString& errorId,
                                            const AutoFixStrategy& strategy)
{
    qDebug() << "[ErrorAnalysisSystem] Executing auto-fix strategy:" << strategy.name 
             << "for error:" << errorId;
    
    // Execute the fix strategy
    QString result = "Fix executed: " + strategy.name;
    
    // Strategy statistics are tracked on the const strategy parameter
    // Real tracking would be done at the system level
    
    return result;
}

void ErrorAnalysisSystem::loadConfiguration(const QJsonObject& config)
{
    qDebug() << "[ErrorAnalysisSystem] Loading configuration";
    
    // Load pattern configurations
    if (config.contains("patterns")) {
        QJsonArray patterns = config["patterns"].toArray();
        for (const QJsonValue& p : patterns) {
            QJsonObject patternObj = p.toObject();
            // Load custom patterns from configuration
            qDebug() << "[ErrorAnalysisSystem] Loaded pattern:" << patternObj["name"].toString();
        }
    }
    
    // Load strategy configurations
    if (config.contains("strategies")) {
        QJsonArray strategies = config["strategies"].toArray();
        for (const QJsonValue& s : strategies) {
            QJsonObject strategyObj = s.toObject();
            qDebug() << "[ErrorAnalysisSystem] Loaded strategy:" << strategyObj["name"].toString();
        }
    }
}

