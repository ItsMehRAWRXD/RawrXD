#include "AgentAPIService.h"
#include "../orchestrator/AgentOrchestrator.h"
#include <QTcpServer>
#include <QWebSocketServer>
#include <QWebSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>

// ----------------------------------------------------------------------
// Constructor & Destructor
// ----------------------------------------------------------------------

AgentAPIService::AgentAPIService(QSharedPointer<AgentOrchestrator> orchestrator, int port, QObject* parent)
    : QObject(parent), orchestrator_(orchestrator), apiPort_(port), wsPort_(port + 1)
{
    qDebug() << "[AgentAPIService] Initialized with REST port:" << apiPort_ << "WebSocket port:" << wsPort_;
    
    // Connect orchestrator signals for real-time forwarding
    if (orchestrator_) {
        connect(orchestrator_.data(), &AgentOrchestrator::taskStatusUpdated,
                this, &AgentAPIService::forwardTaskStatus);
        connect(orchestrator_.data(), &AgentOrchestrator::taskChunk,
                this, &AgentAPIService::forwardTaskChunk);
        connect(orchestrator_.data(), &AgentOrchestrator::orchestrationFinished,
                this, &AgentAPIService::forwardOrchestrationFinished);
    }
}

AgentAPIService::~AgentAPIService()
{
    stopServer();
}

// ----------------------------------------------------------------------
// Server Control
// ----------------------------------------------------------------------

bool AgentAPIService::startServer()
{
    // --- 1. REST Server Setup (Conceptual - uses QTcpServer as placeholder) ---
    restServer_ = new QTcpServer(this);
    if (!restServer_->listen(QHostAddress::LocalHost, apiPort_)) {
        QString errorMsg = tr("Failed to start REST server on port %1: %2")
                          .arg(apiPort_)
                          .arg(restServer_->errorString());
        emit logMessage(errorMsg);
        qCritical() << errorMsg;
        delete restServer_;
        restServer_ = nullptr;
        return false;
    }
    
    emit logMessage(tr("API Gateway (REST) listening on http://localhost:%1").arg(apiPort_));
    qDebug() << "[AgentAPIService] REST endpoint ready on port:" << apiPort_;
    
    // --- 2. WebSocket Server Setup (Real-time Streaming) ---
    wsServer_ = new QWebSocketServer(QStringLiteral("AgentStreamer"), 
                                     QWebSocketServer::NonSecureMode, 
                                     this);
    if (!wsServer_->listen(QHostAddress::LocalHost, wsPort_)) {
        QString errorMsg = tr("Failed to start WebSocket server on port %1").arg(wsPort_);
        emit logMessage(errorMsg);
        qCritical() << errorMsg;
        
        // Clean up REST server
        restServer_->close();
        delete restServer_;
        restServer_ = nullptr;
        delete wsServer_;
        wsServer_ = nullptr;
        return false;
    }

    connect(wsServer_, &QWebSocketServer::newConnection, 
            this, &AgentAPIService::handleWebSocketConnection);

    emit logMessage(tr("API Gateway (WebSocket) listening on ws://localhost:%1").arg(wsPort_));
    qDebug() << "[AgentAPIService] WebSocket server ready on port:" << wsPort_;
    
    emit serverStarted(apiPort_, wsPort_);
    return true;
}

void AgentAPIService::stopServer()
{
    // Close all WebSocket connections
    for (QWebSocket* client : wsClients_) {
        client->close();
        client->deleteLater();
    }
    wsClients_.clear();
    
    if (restServer_) {
        restServer_->close();
        delete restServer_;
        restServer_ = nullptr;
        emit logMessage(tr("REST server stopped."));
    }
    
    if (wsServer_) {
        wsServer_->close();
        delete wsServer_;
        wsServer_ = nullptr;
        emit logMessage(tr("WebSocket server stopped."));
    }
    
    emit serverStopped();
}

// ----------------------------------------------------------------------
// WebSocket Connection Management
// ----------------------------------------------------------------------

void AgentAPIService::handleWebSocketConnection()
{
    QWebSocket* client = wsServer_->nextPendingConnection();
    if (!client) return;
    
    wsClients_.append(client);
    
    connect(client, &QWebSocket::textMessageReceived, 
            this, &AgentAPIService::handleWebSocketMessage);
    connect(client, &QWebSocket::disconnected, 
            this, &AgentAPIService::handleWebSocketDisconnection);
    
    QString clientInfo = tr("%1:%2").arg(client->peerAddress().toString()).arg(client->peerPort());
    emit clientConnected(clientInfo);
    emit logMessage(tr("WebSocket client connected: %1").arg(clientInfo));
    qDebug() << "[AgentAPIService] New WebSocket client:" << clientInfo;
    
    // Send welcome message with API version
    QJsonObject welcome;
    welcome["type"] = "welcome";
    welcome["api_version"] = "1.0";
    welcome["message"] = "Connected to RawrXD Agent API Gateway";
    client->sendTextMessage(QJsonDocument(welcome).toJson(QJsonDocument::Compact));
}

void AgentAPIService::handleWebSocketDisconnection()
{
    QWebSocket* client = qobject_cast<QWebSocket*>(sender());
    if (!client) return;
    
    QString clientInfo = tr("%1:%2").arg(client->peerAddress().toString()).arg(client->peerPort());
    wsClients_.removeAll(client);
    client->deleteLater();
    
    emit clientDisconnected(clientInfo);
    emit logMessage(tr("WebSocket client disconnected: %1").arg(clientInfo));
    qDebug() << "[AgentAPIService] Client disconnected:" << clientInfo;
}

void AgentAPIService::handleWebSocketMessage(const QString& message)
{
    QJsonDocument doc = QJsonDocument::fromJson(message.toUtf8());
    if (!doc.isObject()) {
        emit logMessage(tr("Invalid WebSocket message (not JSON): %1").arg(message.left(50)));
        return;
    }
    
    QJsonObject obj = doc.object();
    QString type = obj["type"].toString();
    
    // Route WebSocket commands
    if (type == "orchestrate") {
        handlePostOrchestrate(doc.toJson());
    } else if (type == "persist_save") {
        handlePostPersist(doc.toJson(), "save");
    } else if (type == "persist_load") {
        handlePostPersist(doc.toJson(), "load");
    } else {
        emit logMessage(tr("Unknown WebSocket command type: %1").arg(type));
    }
}

// ----------------------------------------------------------------------
// Orchestrator Signal Forwarding (Real-time Broadcast)
// ----------------------------------------------------------------------

void AgentAPIService::forwardTaskStatus(const QString& taskId, const QString& status, const QString& agentType)
{
    QJsonObject msg;
    msg["type"] = "task_status";
    msg["task_id"] = taskId;
    msg["status"] = status;
    msg["agent_type"] = agentType;
    msg["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    
    broadcastToClients(QJsonDocument(msg).toJson(QJsonDocument::Compact));
}

void AgentAPIService::forwardTaskChunk(const QString& taskId, const QString& chunk, const QString& agentType)
{
    QJsonObject msg;
    msg["type"] = "task_chunk";
    msg["task_id"] = taskId;
    msg["chunk"] = chunk;
    msg["agent_type"] = agentType;
    
    broadcastToClients(QJsonDocument(msg).toJson(QJsonDocument::Compact));
}

void AgentAPIService::forwardOrchestrationFinished(bool success)
{
    QJsonObject msg;
    msg["type"] = "orchestration_finished";
    msg["success"] = success;
    msg["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    
    broadcastToClients(QJsonDocument(msg).toJson(QJsonDocument::Compact));
}

void AgentAPIService::broadcastToClients(const QString& message)
{
    for (QWebSocket* client : wsClients_) {
        if (client && client->isValid()) {
            client->sendTextMessage(message);
        }
    }
}

// ----------------------------------------------------------------------
// REST API Handlers (Conceptual Routing)
// ----------------------------------------------------------------------

void AgentAPIService::handleRestRequest(const QByteArray& requestPayload, const QString& endpoint)
{
    // Example routing logic for future cpp-httplib/Pistache integration
    if (endpoint.startsWith("/api/v1/orchestrate")) {
        handlePostOrchestrate(requestPayload);
    } else if (endpoint.startsWith("/api/v1/persist")) {
        QStringList parts = endpoint.split('/');
        QString action = parts.count() >= 5 ? parts.at(4) : QString();
        handlePostPersist(requestPayload, action);
    } else if (endpoint.startsWith("/api/v1/control")) {
        QStringList parts = endpoint.split('/');
        QString action = parts.count() >= 5 ? parts.at(4) : QString();
        handlePostControl(requestPayload, action);
    } else {
        emit logMessage(tr("API: 404 Not Found for endpoint: %1").arg(endpoint));
    }
}

void AgentAPIService::handlePostOrchestrate(const QByteArray& payload)
{
    QJsonDocument doc = QJsonDocument::fromJson(payload);
    if (!doc.isObject()) {
        emit logMessage(tr("Orchestrate: Invalid JSON payload"));
        return;
    }
    
    QString goal = doc.object()["goal"].toString();
    if (goal.isEmpty()) {
        emit logMessage(tr("Orchestrate: Missing 'goal' field"));
        return;
    }
    
    if (orchestrator_) {
        orchestrator_->startWorkflow(goal);
        emit logMessage(tr("Orchestration started for goal: '%1'").arg(goal));
    } else {
        emit logMessage(tr("Orchestrate: Orchestrator not available"));
    }
}

void AgentAPIService::handlePostPersist(const QByteArray& payload, const QString& action)
{
    QJsonDocument doc = QJsonDocument::fromJson(payload);
    if (!doc.isObject()) {
        emit logMessage(tr("Persist: Invalid JSON payload"));
        return;
    }
    
    QString filePath = doc.object()["filePath"].toString();
    if (filePath.isEmpty()) {
        emit logMessage(tr("Persist: Missing 'filePath' field"));
        return;
    }
    
    bool success = false;
    if (orchestrator_) {
        if (action == "save") {
            success = orchestrator_->saveOrchestrationState(filePath);
            emit logMessage(tr("Persistence SAVE: %1 (Success: %2)").arg(filePath).arg(success));
        } else if (action == "load") {
            success = orchestrator_->loadOrchestrationState(filePath);
            emit logMessage(tr("Persistence LOAD: %1 (Success: %2)").arg(filePath).arg(success));
        } else {
            emit logMessage(tr("Persist: Unknown action '%1'").arg(action));
        }
    } else {
        emit logMessage(tr("Persist: Orchestrator not available"));
    }
}

void AgentAPIService::handlePostControl(const QByteArray& payload, const QString& action)
{
    Q_UNUSED(payload);
    
    if (action == "stop") {
        emit logMessage(tr("Control: STOP command received (not yet implemented)"));
        // TODO: Implement orchestrator_->stopOrchestration();
    } else {
        emit logMessage(tr("Control: Unknown action '%1'").arg(action));
    }
}
