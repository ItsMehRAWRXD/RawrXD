#ifndef WEBSOCKET_HUB_H
#define WEBSOCKET_HUB_H

<<<<<<< HEAD
// C++20 / Win32. WebSocket server; no Qt. Uses Winsock in impl.

#include <string>
#include <functional>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>

namespace RawrXD {

struct WebSocketClient;  // Opaque: wraps SOCKET + state

class WebSocketHub
{
public:
    using MessageReceivedFn = std::function<void(const std::string& messageJson, void* client)>;

    WebSocketHub() = default;
    ~WebSocketHub();

    void setOnMessageReceived(MessageReceivedFn f) { m_onMessageReceived = std::move(f); }
    bool startServer(uint16_t port = 5173);
    void stopServer();
    void broadcastMessage(const std::string& messageJson);
    bool isRunning() const { return m_running.load(); }
    uint16_t getPort() const { return m_port; }

private:
    static void serverThreadFn(WebSocketHub* self);
    void serverLoop();
    void acceptOne();
    void handleClient(void* clientContext);
    bool sendTextToClient(void* clientContext, const std::string& text);
    static std::string makeWebSocketAcceptKey(const std::string& key);

    std::mutex m_clientsMutex;
    std::vector<void*> m_clients;
    MessageReceivedFn m_onMessageReceived;
    void* m_listenSocket = nullptr;  // SOCKET
    std::atomic<bool> m_running{false};
    std::thread m_serverThread;
    uint16_t m_port = 0;
};

} // namespace RawrXD

#endif // WEBSOCKET_HUB_H
=======
#include <QObject>
#include <QWebSocketServer>
#include <QWebSocket>
#include <QList>
#include <QJsonObject>

// WebSocket server embedded inside RawrXD-Agent.exe (port 5173)
class WebSocketHub : public QObject
{
    Q_OBJECT

public:
    explicit WebSocketHub(QObject *parent = nullptr);
    ~WebSocketHub();

    // Start the server
    bool startServer(quint16 port = 5173);

    // Send message to all clients
    void broadcastMessage(const QJsonObject &message);

signals:
    // Emitted when a message is received from a client
    void messageReceived(const QJsonObject &message, QWebSocket *client);

private slots:
    void onNewConnection();
    void onTextMessageReceived(const QString &message);
    void onSocketDisconnected();

private:
    QWebSocketServer *m_server;
    QList<QWebSocket *> m_clients;
};

#endif // WEBSOCKET_HUB_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
