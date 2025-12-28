#pragma once
#include <QObject>
#include <QWebSocket>
#include <QJsonObject>
#include "../agentic/agentic_engine.h"

class CollaborativeAIEngine : public QObject {
    Q_OBJECT
public:
    CollaborativeAIEngine(AgenticEngine* engine, QObject* parent = nullptr);
    
    // Real-time collaboration
    void joinSession(const QString& sessionId, const QString& userId);
    void leaveSession();
    void shareContext(const QString& context, const QString& type);
    void requestAIAssistance(const QString& query, const QStringList& collaborators);
    
    // Shared AI state
    void syncAIModel(const QString& modelPath);
    void shareCompletions(const std::vector<CodeCompletion>& completions);
    void broadcastRefactoring(const QString& original, const QString& refactored);
    
    // Team AI features
    void enablePairProgramming(const QString& partnerId);
    void startCodeReview(const QString& prId, const QStringList& reviewers);
    void createSharedWorkspace(const QString& workspaceName);
    
    // Conflict resolution
    void resolveAIConflicts(const QJsonArray& conflicts);
    void mergeAIContexts(const QJsonArray& contexts);
    
signals:
    void collaboratorJoined(const QString& userId);
    void collaboratorLeft(const QString& userId);
    void contextShared(const QString& userId, const QJsonObject& context);
    void aiResponseShared(const QString& userId, const QString& response);
    void conflictDetected(const QJsonObject& conflict);
    
private slots:
    void onWebSocketConnected();
    void onWebSocketDisconnected();
    void onMessageReceived(const QString& message);
    void handleCollaborativeEvent(const QJsonObject& event);
    
private:
    AgenticEngine* m_agenticEngine;
    QWebSocket* m_webSocket;
    QString m_sessionId;
    QString m_userId;
    QStringList m_collaborators;
    
    // Collaborative state
    QJsonObject m_sharedContext;
    QMap<QString, QJsonObject> m_collaboratorStates;
    
    // Real-time sync
    void sendMessage(const QJsonObject& message);
    void handleContextSync(const QJsonObject& context);
    void handleAIResponse(const QJsonObject& response);
    
    // Conflict detection
    bool detectContextConflict(const QJsonObject& newContext);
    QJsonObject resolveConflict(const QJsonObject& conflict1, const QJsonObject& conflict2);
};