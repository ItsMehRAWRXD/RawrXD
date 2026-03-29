// Scalar Server - Lightweight inference server for scalar operations

#include "scalar_server.h"
#include "qtapp/inference_engine.hpp"
#include "transformer_block_scalar.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QThread>
#include <QDebug>
#include <QElapsedTimer>
#include <QStringList>
#include <algorithm>
#include <vector>

ScalarServer::ScalarServer(QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
    , m_transformerBlock(new TransformerBlockScalar(this))
    , m_inferenceEngine(new InferenceEngine(this))
{
    connect(m_server, &QTcpServer::newConnection, this, &ScalarServer::handleNewConnection);
}

ScalarServer::~ScalarServer()
{
    stopServer();
}

bool ScalarServer::startServer(quint16 port)
{
    if (m_server->isListening()) {
        qWarning() << "Server already running on port" << m_server->serverPort();
        return true;
    }
    
    if (!m_server->listen(QHostAddress::Any, port)) {
        qCritical() << "Failed to start server on port" << port << ":" << m_server->errorString();
        return false;
    }
    
    qInfo() << "Scalar server started on port" << port;
    return true;
}

void ScalarServer::stopServer()
{
    if (m_server->isListening()) {
        m_server->close();
        qInfo() << "Scalar server stopped";
    }
}

void ScalarServer::handleNewConnection()
{
    QTcpSocket *clientSocket = m_server->nextPendingConnection();
    
    connect(clientSocket, &QTcpSocket::readyRead, this, [this, clientSocket]() {
        handleClientData(clientSocket);
    });
    
    connect(clientSocket, &QTcpSocket::disconnected, clientSocket, &QTcpSocket::deleteLater);
    
    qDebug() << "New client connected:" << clientSocket->peerAddress().toString();
}

void ScalarServer::handleClientData(QTcpSocket *clientSocket)
{
    QByteArray data = clientSocket->readAll();
    
    // Parse JSON request
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        sendErrorResponse(clientSocket, "Invalid JSON");
        return;
    }
    
    QJsonObject request = doc.object();
    QString method = request.value("method").toString().trimmed().toLower();
    
    if (method == "inference") {
        handleInferenceRequest(clientSocket, request);
    } else if (method == "chat" || method == "chat_route") {
        handleChatRequest(clientSocket, request);
    } else if (method == "analyze") {
        handleAnalyzeRequest(clientSocket, request);
    } else {
        sendErrorResponse(clientSocket, "Unknown method: " + method);
    }
}

void ScalarServer::handleInferenceRequest(QTcpSocket *clientSocket, const QJsonObject &request)
{
    QJsonArray inputArray = request.value("input").toArray();
    uint32_t layerIdx = request.value("layer").toInt();
    uint32_t seqLen = request.value("seq_len").toInt();
    
    // Convert input to float array
    std::vector<float> input(inputArray.size());
    for (int i = 0; i < inputArray.size(); ++i) {
        input[i] = inputArray[i].toDouble();
    }
    
    // Perform inference
    std::vector<float> output(input.size());
    bool success = m_transformerBlock->forwardPass(input.data(), output.data(), layerIdx, seqLen);
    
    // Prepare response
    QJsonObject response;
    response["success"] = success;
    
    if (success) {
        QJsonArray outputArray;
        for (float val : output) {
            outputArray.append(val);
        }
        response["output"] = outputArray;
    } else {
        response["error"] = "Inference failed";
    }
    
    sendJsonResponse(clientSocket, response);
}

void ScalarServer::handleChatRequest(QTcpSocket *clientSocket, const QJsonObject &request)
{
    const QString requestId = request.value("request_id").toString();
    const QString message = request.value("message").toString();
    if (message.trimmed().isEmpty()) {
        sendErrorResponse(clientSocket, "chat message is empty");
        return;
    }
    if (message.size() > 8192) {
        sendErrorResponse(clientSocket, "chat message exceeds 8192 characters");
        return;
    }

    QString preferredBackend = request.value("backend").toString().trimmed().toLower();
    if (preferredBackend.isEmpty()) {
        preferredBackend = "inference";
    }

    QStringList routeBackends;
    routeBackends << preferredBackend;
    const QJsonArray route = request.value("route").toArray();
    for (const auto& item : route) {
        const QString backend = item.toString().trimmed().toLower();
        if (!backend.isEmpty() && !routeBackends.contains(backend)) {
            routeBackends << backend;
        }
    }

    QElapsedTimer timer;
    timer.start();

    const auto tryBackend = [&](const QString& backend, QString& outResponse, QString& outError) -> bool {
        if (backend == "inference") {
            outResponse = m_inferenceEngine->processChat(message);
            if (outResponse.trimmed().isEmpty()) {
                outError = "inference backend produced empty response";
                return false;
            }
            return true;
        }

        if (backend == "analyze") {
            outResponse = m_inferenceEngine->analyzeCode(message);
            if (outResponse.trimmed().isEmpty()) {
                outError = "analyze backend produced empty response";
                return false;
            }
            return true;
        }

        if (backend == "echo") {
            outResponse = QString("[echo] %1").arg(message);
            return true;
        }

        if (backend == "scalar") {
            std::vector<float> input(static_cast<size_t>(message.size()));
            const QByteArray bytes = message.toUtf8();
            for (int i = 0; i < bytes.size(); ++i) {
                input[static_cast<size_t>(i)] = static_cast<unsigned char>(bytes[i]) / 255.0f;
            }

            std::vector<float> output(input.size());
            const bool ok = m_transformerBlock->forwardPass(input.data(), output.data(), 0, 1);
            if (!ok) {
                outError = "scalar backend forward pass failed";
                return false;
            }

            const int preview = std::min<int>(8, static_cast<int>(output.size()));
            QStringList vals;
            for (int i = 0; i < preview; ++i) {
                vals << QString::number(output[static_cast<size_t>(i)], 'f', 4);
            }
            outResponse = QString("[scalar] preview=%1").arg(vals.join(","));
            return true;
        }

        outError = QString("unknown backend '%1'").arg(backend);
        return false;
    };

    QString selectedBackend;
    QString response;
    QString routingError;
    bool fallbackUsed = false;
    bool success = false;

    for (int i = 0; i < routeBackends.size(); ++i) {
        const QString backend = routeBackends[i];
        QString attemptResponse;
        QString attemptError;
        if (tryBackend(backend, attemptResponse, attemptError)) {
            selectedBackend = backend;
            response = attemptResponse;
            success = true;
            fallbackUsed = (i > 0);
            break;
        }
        routingError = attemptError;
    }

    if (!success) {
        sendErrorResponse(clientSocket, "chat routing failed: " + routingError);
        return;
    }

    QJsonObject jsonResponse;
    jsonResponse["success"] = true;
    jsonResponse["response"] = response;
    jsonResponse["backend"] = selectedBackend;
    jsonResponse["fallback_used"] = fallbackUsed;
    jsonResponse["latency_ms"] = static_cast<qint64>(timer.elapsed());
    jsonResponse["method"] = "chat";
    jsonResponse["handler_symbol"] = "ScalarServer::handleChatRequest";
    jsonResponse["handler_path"] = "src/scalar_server.cpp";
    jsonResponse["route_backends"] = QJsonArray::fromStringList(routeBackends);
    if (!requestId.isEmpty()) {
        jsonResponse["request_id"] = requestId;
    }
    
    sendJsonResponse(clientSocket, jsonResponse);
}

void ScalarServer::handleAnalyzeRequest(QTcpSocket *clientSocket, const QJsonObject &request)
{
    QString code = request.value("code").toString();
    
    // Analyze code through inference engine
    QString analysis = m_inferenceEngine->analyzeCode(code);
    
    QJsonObject jsonResponse;
    jsonResponse["success"] = true;
    jsonResponse["analysis"] = analysis;
    
    sendJsonResponse(clientSocket, jsonResponse);
}

void ScalarServer::sendJsonResponse(QTcpSocket *clientSocket, const QJsonObject &response)
{
    QJsonDocument doc(response);
    QByteArray data = doc.toJson(QJsonDocument::Compact);
    
    clientSocket->write(data);
    clientSocket->flush();
}

void ScalarServer::sendErrorResponse(QTcpSocket *clientSocket, const QString &error)
{
    QJsonObject response;
    response["success"] = false;
    response["error"] = error;
    
    sendJsonResponse(clientSocket, response);
}

bool ScalarServer::loadModel(const QString &modelPath)
{
    // Load model weights into transformer block
    // This would typically involve GGUF loader integration
    qInfo() << "Loading model from:" << modelPath;
    
    // For now, initialize with default parameters
    return m_transformerBlock->initialize(32, 32, 128, 4096);
}

quint16 ScalarServer::getPort() const
{
    return m_server->serverPort();
}

bool ScalarServer::isRunning() const
{
    return m_server->isListening();
}