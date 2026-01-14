#pragma once

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QMap>
#include <QTimer>
#include <memory>

/**
 * @class RealTimeRefactoring
 * @brief Provides automatic code improvement and intelligent refactoring
 * 
 * Features:
 * - Real-time code analysis and improvement suggestions
 * - Automatic refactoring with safety checks
 * - Pattern-based code optimization
 * - Performance improvement suggestions
 * - Code style consistency enforcement
 * - Refactoring history and rollback support
 */
class RealTimeRefactoring : public QObject {
    Q_OBJECT
public:
    explicit RealTimeRefactoring(QObject* parent = nullptr);
    virtual ~RealTimeRefactoring();

    // Core refactoring operations
    QJsonArray analyzeCodeForImprovements(const QString& code, const QString& language = "cpp");
    QJsonObject generateRefactoringSuggestion(const QString& code, const QString& pattern);
    QJsonObject applyRefactoring(const QString& originalCode, const QJsonObject& suggestion);
    QJsonObject validateRefactoring(const QString& original, const QString& refactored);
    
    // Pattern-based refactoring
    QJsonArray detectCodeSmells(const QString& code);
    QJsonArray suggestOptimizations(const QString& code);
    QJsonArray enforceCodeStyle(const QString& code, const QString& styleGuide = "cpp");
    
    // Performance refactoring
    QJsonObject analyzePerformanceBottlenecks(const QString& code);
    QJsonArray generatePerformanceImprovements(const QString& code);
    
    // Safety and validation
    bool isRefactoringSafe(const QJsonObject& suggestion);
    QJsonObject createRollbackPoint(const QString& code);
    void rollbackToPoint(const QJsonObject& rollbackPoint);

public slots:
    void processCodeChange(const QString& filePath, const QString& oldCode, const QString& newCode);
    void requestRefactoring(const QString& filePath, const QString& refactoringType);
    void enableRealTimeAnalysis(bool enable);
    void setRefactoringAggressiveness(int level); // 1-5 scale

signals:
    void refactoringSuggested(const QString& filePath, const QJsonObject& suggestion);
    void refactoringApplied(const QString& filePath, const QJsonObject& result);
    void performanceIssueDetected(const QString& filePath, const QJsonObject& issue);
    void codeSmellDetected(const QString& filePath, const QJsonObject& smell);
    void refactoringComplete(const QString& filePath, bool success, const QString& details);

private:
    // Analysis helpers
    QJsonObject analyzeCodeStructure(const QString& code);
    QJsonObject detectPerformanceIssues(const QString& code);
    QJsonObject generateSuggestion(const QString& issueType, const QJsonObject& analysis);
    
    // Refactoring helpers
    QString applyPatternRefactoring(const QString& code, const QJsonObject& suggestion);
    QString applyPerformanceOptimization(const QString& code, const QJsonObject& optimization);
    QString applyStyleImprovements(const QString& code, const QJsonObject& styleGuide);
    
    // Validation helpers
    bool validateSyntax(const QString& code, const QString& language);
    bool validateLogic(const QString& original, const QString& refactored);
    bool validatePerformance(const QString& original, const QString& refactored);
    
    // Code patterns and rules
    struct RefactoringRule {
        QString name;
        QString pattern;
        QString replacement;
        QString description;
        QString category;
        double confidence;
        QString safety;
    };
    
    QMap<QString, RefactoringRule> m_refactoringRules;
    QMap<QString, QJsonObject> m_codePatterns;
    QJsonObject m_styleGuides;
    
    // Analysis state
    struct AnalysisSession {
        QString filePath;
        QString language;
        QJsonObject lastAnalysis;
        QTimer* analysisTimer;
        bool realTimeEnabled;
        int aggressivenessLevel;
    };
    
    QMap<QString, std::shared_ptr<AnalysisSession>> m_activeSessions;
    
    // History and rollback
    struct RefactoringHistory {
        QString filePath;
        QString timestamp;
        QString originalCode;
        QString refactoredCode;
        QJsonObject suggestion;
        bool successful;
    };
    
    QList<RefactoringHistory> m_refactoringHistory;
    QList<QJsonObject> m_rollbackPoints;
    
    // Configuration
    bool m_enableRealTimeAnalysis = true;
    int m_aggressivenessLevel = 3;
    QString m_defaultLanguage = "cpp";
    int m_analysisDelayMs = 1000;
};
