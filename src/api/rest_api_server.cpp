// D:\temp\RawrXD-agentic-ide-production\RawrXD-ModelLoader\src\api\rest_api_server.cpp
// Production-grade REST API Server with OpenAPI 3.0 compliance
// Integrated with Qt Network framework for cross-platform HTTP handling

#include "rest_api_server.h"
#include "metrics_emitter.h"
#include "oauth2_manager.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrl>
#include <QUrlQuery>
#include <QDebug>
#include <QMutex>
#include <QThread>
#include <QTimer>
#include <QUuid>

#include <map>
#include <functional>
#include <iostream>
#include <chrono>

namespace RawrXD {
namespace API {

class RESTAPIServer::Impl {
public:
    QHttpServer server;
    uint16_t port = 8080;
    bool isRunning = false;
    QMutex mutex;
    
    // OpenAPI specification
    QJsonObject openAPISpec;
    
    // Route handlers: method -> path -> handler function
    std::map<QString, std::map<QString, std::function<QJsonObject(const RESTRequest&)>>> routes;
    
    // OpenAPI route handlers
    std::map<QString, std::map<QString, QJsonObject>> openAPIRoutes;
    
    // Middleware pipeline
    std::vector<std::function<bool(RESTRequest&, RESTResponse&)>> middlewares;
    
    // Rate limiter: client IP -> request count in current window
    std::map<QString, int> rateLimitMap;
    int rateLimitPerMinute = 1000;
    
    // Request/Response logging
    bool enableLogging = true;

    // Metrics and auth
    bool metricsEnabled = true;
    std::shared_ptr<RawrXD::Monitoring::MetricsEmitter> metrics;
    std::function<bool(const RESTRequest&)> authValidator;
};

RESTAPIServer::RESTAPIServer() 
    : impl(std::make_unique<Impl>())
{
    impl->metrics = std::make_shared<RawrXD::Monitoring::MetricsEmitter>();
}

RESTAPIServer::~RESTAPIServer() = default;

bool RESTAPIServer::start(uint16_t port) {
    QMutexLocker lock(&impl->mutex);
    
    impl->port = port;
    
    // Start HTTP server
    if (!impl->server.listen(QHostAddress::Any, impl->port)) {
        qCritical() << "Failed to start REST API server on port" << impl->port;
        return false;
    }
    
    impl->isRunning = true;
    qInfo() << "REST API Server started on port" << impl->port;
    
    // Register middleware handler
    impl->server.beforeRequest([](const QHttpServerRequest &request) {
        // Global middleware processing
        return std::nullopt;
    });
    
    return true;
}

void RESTAPIServer::stop() {
    QMutexLocker lock(&impl->mutex);
    impl->server.close();
    impl->isRunning = false;
    qInfo() << "REST API Server stopped";
}

bool RESTAPIServer::isRunning() const {
    return impl->isRunning;
}

void RESTAPIServer::registerOpenAPIRoute(const QString& method, const QString& path, 
                                          const QJsonObject& openAPISpec, RouteHandler handler) {
    QMutexLocker lock(&impl->mutex);
    
    QString upperMethod = method.toUpper();
    impl->routes[upperMethod][path] = handler;
    impl->openAPIRoutes[upperMethod][path] = openAPISpec;
    
    // Register with QHttpServer
    if (upperMethod == "GET") {
        impl->server.route(path, [this, handler](const QHttpServerRequest &request) {
            return handleHttpRequest(request, handler);
        });
    } else if (upperMethod == "POST") {
        impl->server.route(path, QHttpServerRequest::Method::Post, 
                              [this, handler](const QHttpServerRequest &request) {
            return handleHttpRequest(request, handler);
        });
    } else if (upperMethod == "PUT") {
        impl->server.route(path, QHttpServerRequest::Method::Put, 
                              [this, handler](const QHttpServerRequest &request) {
            return handleHttpRequest(request, handler);
        });
    } else if (upperMethod == "DELETE") {
        impl->server.route(path, QHttpServerRequest::Method::Delete, 
                              [this, handler](const QHttpServerRequest &request) {
            return handleHttpRequest(request, handler);
        });
    }
    
    qDebug() << "Registered OpenAPI route:" << method << path;
}

QHttpServerResponse RESTAPIServer::handleHttpRequest(const QHttpServerRequest &request, 
                                                       RouteHandler handler) {
    RESTRequest restRequest(request);
    RESTResponse restResponse;
    
    // Apply middleware chain
    for (auto &middleware : impl->middlewares) {
        if (!middleware(restRequest, restResponse)) {
            // Middleware rejected request
            return restResponse.toHttpResponse();
        }
    }
    
    // Apply rate limiting
    if (!checkRateLimit(restRequest.clientIP)) {
        restResponse.statusCode = 429;
        restResponse.body = {{"error", "Rate limit exceeded"}};
        return restResponse.toHttpResponse();
    }
    
    // Apply auth validation
    if (impl->authValidator && !impl->authValidator(restRequest)) {
        restResponse.statusCode = 401;
        restResponse.body = {{"error", "Unauthorized"}};
        return restResponse.toHttpResponse();
    }
    
    // Execute route handler
    try {
        QJsonObject result = handler(restRequest);
        restResponse.body = result;
        restResponse.statusCode = 200;
    } catch (const std::exception &e) {
        restResponse.statusCode = 500;
        restResponse.body = {{"error", QString::fromStdString(e.what())}};
    }
    
    // Emit metrics
    if (impl->metricsEnabled && impl->metrics) {
        impl->metrics->emitCounter("api_requests_total", 1, 
            {{"method", restRequest.method}, {"path", restRequest.path}, 
             {"status", QString::number(restResponse.statusCode)}});
    }
    
    return restResponse.toHttpResponse();
}

void RESTAPIServer::setRateLimit(int requestsPerMinute) {
    impl->rateLimitPerMinute = requestsPerMinute;
}

void RESTAPIServer::enableMetrics(bool enabled) {
    impl->metricsEnabled = enabled;
}

void RESTAPIServer::setAuthValidator(const std::function<bool(const RESTRequest&)>& validator) {
    impl->authValidator = validator;
}

void RESTAPIServer::setOpenAPISpec(const QJsonObject &spec) {
    QMutexLocker lock(&impl->mutex);
    impl->openAPISpec = spec;
    qDebug() << "OpenAPI specification set";
}

QJsonObject RESTAPIServer::getOpenAPISpec() const {
    QMutexLocker lock(&impl->mutex);
    return impl->openAPISpec;
}

void RESTAPIServer::registerRoute(const QString &method, const QString &path, 
                                   RouteHandler handler) {
    registerOpenAPIRoute(method, path, QJsonObject(), handler);
}

void RESTAPIServer::registerMiddleware(MiddlewareHandler middleware) {
    QMutexLocker lock(&impl->mutex);
    impl->middlewares.push_back(middleware);
    qDebug() << "Registered middleware";
}   path = request.url().path();
    
    // Parse headers
    for (const auto &header : request.headers()) {
        headers[QString::fromStdString(header.first)] = QString::fromStdString(header.second);
    }
    
    // Parse query parameters
    QUrlQuery query(request.url());
    for (const auto &param : query.queryItems()) {
        queryParams.append(param);
    }
    
    // Parse body
    if (!request.body().isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromJson(request.body());
        if (doc.isObject()) {
            body = doc.object();
        }
    }
    
    clientIP = request.remoteAddress().toString();
    timestamp = QDateTime::currentDateTime();
    
    // Generate trace/span IDs if not present
    if (headers.contains("X-Trace-ID")) {
        traceId = headers["X-Trace-ID"];
    } else {
        traceId = QUuid::createUuid().toString();
    }
    
    if (headers.contains("X-Span-ID")) {
        spanId = headers["X-Span-ID"];
    } else {
        spanId = QUuid::createUuid().toString();
    }
}

// RESTResponse toHttpResponse implementation
QHttpServerResponse RESTResponse::toHttpResponse() const {
    QJsonDocument doc(body);
    QByteArray responseBody = doc.toJson(QJsonDocument::Compact);
    
    QHttpServerResponse response(responseBody);
    response.setStatusCode(static_cast<QHttpServerResponse::StatusCode>(statusCode));
    
    // Set headers
    for (auto it = headers.begin(); it != headers.end(); ++it) {
        response.setHeader(it.key().toStdString(), it.value().toStdString());
    }
    
    // Ensure content-type header
    if (!headers.contains("Content-Type")) {
        response.setHeader("Content-Type", "application/json");
    }
    
    return response;
}

// Rate limiting check implementation
bool RESTAPIServer::checkRateLimit(const QString &clientIP) {
    QMutexLocker lock(&impl->mutex);
    
    auto currentTime = QDateTime::currentDateTime();
    static QDateTime lastCleanup = currentTime;
    
    // Cleanup old entries every minute
    if (lastCleanup.secsTo(currentTime) > 60) {
        for (auto it = impl->rateLimitMap.begin(); it != impl->rateLimitMap.end();) {
            if (it->second <= 0) {
                it = impl->rateLimitMap.erase(it);
            } else {
                ++it;
            }
        }
        lastCleanup = currentTime;
    }
    
    int &count = impl->rateLimitMap[clientIP];
    if (count >= impl->rateLimitPerMinute) {
        return false;
    }
    
    count++;
    return true;
}

ConnectionHandler::ConnectionHandler(QTcpSocket* socket, RESTAPIServer* server)
    : QObject(), socket(socket), server(server)
{
    connect(socket, &QTcpSocket::readyRead, this, &ConnectionHandler::onReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &ConnectionHandler::onDisconnected);
    
    // Set connection timeouts
    QTimer::singleShot(30000, this, [this]() {
        if (socket && socket->state() == QTcpSocket::ConnectedState) {
            socket->close();
        }
    });
}

void ConnectionHandler::onReadyRead() {
    if (!socket) return;
    
    QByteArray data = socket->readAll();
    QString requestStr = QString::fromUtf8(data);
    
    // Parse HTTP request
    QStringList lines = requestStr.split("\r\n");
    if (lines.isEmpty()) return;
    
    QStringList requestLine = lines[0].split(" ");
    if (requestLine.size() < 3) return;
    
    QString method = requestLine[0].toUpper();
    QString pathWithQuery = requestLine[1];
    
    // Parse URL and query parameters
    QUrl url("http://localhost" + pathWithQuery);
    QString path = url.path();
    QUrlQuery query(url);
    
    // Parse request body
    QJsonObject bodyJson;
    int emptyLineIndex = -1;
    for (int i = 0; i < lines.size(); ++i) {
        if (lines[i].isEmpty()) {
            emptyLineIndex = i;
            break;
        }
    }
    
    if (emptyLineIndex >= 0 && emptyLineIndex + 1 < lines.size()) {
        QString bodyStr = lines.mid(emptyLineIndex + 1).join("\r\n");
        QJsonDocument doc = QJsonDocument::fromJson(bodyStr.toUtf8());
        if (doc.isObject()) {
            bodyJson = doc.object();
        }
    }
    
    // Create request object
    RESTRequest request;
    request.method = method;
    request.path = path;
    request.queryParams = query.queryItems();
    request.body = bodyJson;
    request.clientIP = socket->peerAddress().toString();
    request.timestamp = QDateTime::currentDateTime();
    request.traceId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    request.spanId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    
    // Create response object
    RESTResponse response;
    response.statusCode = 404;
    response.headers["Content-Type"] = "application/json";
    
    // Apply middleware
    bool continueProcessing = true;
    for (auto& middleware : server->impl->middlewares) {
        if (!middleware(request, response)) {
            continueProcessing = false;
            break;
        }
    }

    // Basic rate limit per IP
    auto nowMin = QDateTime::currentDateTime().toTime_t() / 60;
    QString rateKey = request.clientIP + QString::number(nowMin);
    server->impl->rateLimitMap[rateKey] += 1;
    if (server->impl->rateLimitMap[rateKey] > server->impl->rateLimitPerMinute) {
        response.statusCode = 429;
        response.body["error"] = "Too Many Requests";
        continueProcessing = false;
    }

    // Auth validation hook
    if (continueProcessing && server->impl->authValidator) {
        if (!server->impl->authValidator(request)) {
            response.statusCode = 401;
            response.body["error"] = "Unauthorized";
            continueProcessing = false;
        }
    }
    
    // Find and execute handler
    if (continueProcessing) {
        auto methodIt = server->impl->routes.find(method);
        if (methodIt != server->impl->routes.end()) {
            auto pathIt = methodIt->second.find(path);
            if (pathIt != methodIt->second.end()) {
                try {
                    auto start = std::chrono::steady_clock::now();
                    response.body = pathIt->second(request);
                    response.statusCode = 200;
                    if (server->impl->metricsEnabled && server->impl->metrics) {
                        auto end = std::chrono::steady_clock::now();
                        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        QMap<QString, QString> labels;
                        labels["path"] = path;
                        labels["method"] = method;
                        server->impl->metrics->recordLatency("api_request", durationMs, labels);
                        server->impl->metrics->recordCounter("api_requests_total", 1, labels);
                    }
                } catch (const std::exception& e) {
                    response.statusCode = 500;
                    response.body["error"] = QString::fromStdString(e.what());
                }
            }
        }
    }
    
    // Send response
    sendResponse(response);
    
    socket->disconnectFromHost();
}

void ConnectionHandler::onDisconnected() {
    socket->deleteLater();
    deleteLater();
}

void ConnectionHandler::sendResponse(const RESTResponse& response) {
    if (!socket || socket->state() != QTcpSocket::ConnectedState) return;
    
    QJsonDocument doc(response.body);
    QByteArray bodyData = doc.toJson();
    
    QString statusText = getHttpStatusText(response.statusCode);
    QString responseStr = QString("HTTP/1.1 %1 %2\r\n").arg(response.statusCode).arg(statusText);
    
    for (const auto& [key, value] : response.headers.toStdMap()) {
        responseStr += QString("%1: %2\r\n").arg(key, value);
    }
    
    responseStr += QString("Content-Length: %1\r\n").arg(bodyData.size());
    responseStr += "Connection: close\r\n";
    responseStr += "\r\n";
    
    socket->write(responseStr.toUtf8());
    socket->write(bodyData);
    socket->flush();
}

QString ConnectionHandler::getHttpStatusText(int statusCode) {
    static const std::map<int, QString> statusTexts = {
        {200, "OK"},
        {201, "Created"},
        {204, "No Content"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {500, "Internal Server Error"},
        {503, "Service Unavailable"}
    };
    
    auto it = statusTexts.find(statusCode);
    return it != statusTexts.end() ? it->second : "Unknown";
}

} // namespace API
} // namespace RawrXD
