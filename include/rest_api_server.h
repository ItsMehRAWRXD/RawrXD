// D:\temp\RawrXD-agentic-ide-production\RawrXD-ModelLoader\include\rest_api_server.h
// Production REST API Server Header with comprehensive type definitions

#pragma once

#include <QHttpServer>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QOpenAPI>
#include <QRegularExpression>

namespace RawrXD {
namespace API {

// HTTP request structure
struct RESTRequest {
    QHttpServerRequest httpRequest;
    QString method;              // GET, POST, PUT, DELETE, PATCH
    QString path;                // URL path
    QMap<QString, QString> headers;
    QJsonObject body;
    QList<QPair<QString, QString>> queryParams;
    QString clientIP;
    QDateTime timestamp;
    QString traceId;
    QString spanId;
    
    // Constructor from QHttpServerRequest
    RESTRequest(const QHttpServerRequest& request);
};

// HTTP response structure
struct RESTResponse {
    int statusCode = 200;
    QMap<QString, QString> headers;
    QJsonObject body;
    QDateTime timestamp;
    
    // Convert to QHttpServerResponse
    QHttpServerResponse toHttpResponse() const;
};

// API Request/Response types for versioning
enum class APIVersion {
    V1,
    V2,
    BETA
};

// Route handler function type
using RouteHandler = std::function<QJsonObject(const RESTRequest&)>;

// Middleware handler function type
using MiddlewareHandler = std::function<bool(RESTRequest&, RESTResponse&)>;

class RESTAPIServer {
public:
    class Impl;
    
    RESTAPIServer();
    ~RESTAPIServer();
    
    // Server lifecycle
    bool start(uint16_t port = 8080);
    void stop();
    bool isRunning() const;
    
    // Route registration
    void registerRoute(const QString& method, const QString& path, RouteHandler handler);
    void registerOpenAPIRoute(const QString& method, const QString& path, 
                              const QJsonObject& openAPISpec, RouteHandler handler);
    
    // OpenAPI specification management
    void setOpenAPISpec(const QJsonObject& spec);
    QJsonObject getOpenAPISpec() const;
    
    // Middleware registration
    void registerMiddleware(MiddlewareHandler middleware);
    
    // Configuration
    void setRateLimit(int requestsPerMinute);
    void enableMetrics(bool enabled);
    void setAuthValidator(const std::function<bool(const RESTRequest&)>& validator);
    
private:
    friend class ConnectionHandler;
    
    void onNewConnection();
    
    std::unique_ptr<Impl> impl;
};

// Connection handler for individual client connections
class ConnectionHandler : public QObject {
    Q_OBJECT
    
public:
    explicit ConnectionHandler(class QTcpSocket* socket, RESTAPIServer* server);
    
private slots:
    void onReadyRead();
    void onDisconnected();
    
private:
    void sendResponse(const RESTResponse& response);
    QString getHttpStatusText(int statusCode);
    
    class QTcpSocket* socket;
    RESTAPIServer* server;
};

} // namespace API
} // namespace RawrXD
