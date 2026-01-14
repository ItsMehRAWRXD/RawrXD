#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonObject>
#include "../agentic/agentic_engine.h"

class GitHubCopilotIntegration : public QObject {
    Q_OBJECT
public:
    GitHubCopilotIntegration(AgenticEngine* engine, QObject* parent = nullptr);
    
    // GitHub Copilot Enterprise features
    void reviewPullRequest(const QString& prUrl);
    void generateCodeFromIssue(const QString& issueUrl);
    void scanForSecurityVulnerabilities(const QString& repoPath);
    void generateCommitMessage(const QStringList& changedFiles);
    
    // Real-time collaboration
    void startCollaborativeSession(const QString& sessionId);
    void shareAIContext(const QString& context, const QStringList& collaborators);
    void syncAIState(const QJsonObject& state);
    
    // Enterprise security
    void enableEnterpriseMode(const QString& orgToken);
    void auditAIUsage();
    QJsonObject getComplianceReport();
    
signals:
    void prReviewReady(const QString& review);
    void codeGenerated(const QString& code, const QString& issueId);
    void securityIssuesFound(const QJsonArray& issues);
    void collaborationUpdate(const QJsonObject& update);
    
private slots:
    void handleGitHubResponse();
    void processWebhook(const QJsonObject& payload);
    
private:
    AgenticEngine* m_agenticEngine;
    QNetworkAccessManager* m_networkManager;
    QString m_enterpriseToken;
    
    // GitHub API integration
    void makeGitHubRequest(const QString& endpoint, const QJsonObject& data);
    QJsonObject parseGitHubResponse(const QByteArray& response);
    
    // Security and compliance
    void logAIInteraction(const QString& action, const QJsonObject& metadata);
    bool validateEnterprisePermissions(const QString& action);
};
