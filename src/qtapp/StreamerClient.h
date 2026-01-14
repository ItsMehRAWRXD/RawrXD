/**
 * @file StreamerClient.h
 * @brief Complete Real-Time Streaming Client for RawrXD Agentic IDE
 * 
 * Provides WebSocket-based real-time collaboration features including:
 * - Live code sharing and editing
 * - Real-time chat and voice communication
 * - Cursor position synchronization
 * - File change broadcasting
 * - Multi-user session management
 * 
 * @author RawrXD Team
 * @copyright 2024 RawrXD
 */

#pragma once

#include <QObject>
#include <QWebSocket>
#include <QWebSocketServer>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QThread>
#include <QMutex>
#include <QMap>
#include <QSet>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QAudioInput>
#include <QAudioOutput>
#include <QTcpSocket>
#include <memory>
#include <functional>

namespace RawrXD {

/**
 * @brief Types of streaming sessions
 */
enum class StreamType {
    Code,        ///< Code editing session
    Chat,        ///< Text chat session
    Voice,       ///< Voice communication
    Screen,      ///< Screen sharing
    Webcam,      ///< Camera sharing
    File,        ///< File transfer
    Whiteboard,  ///< Collaborative whiteboard
    Terminal     ///< Shared terminal session
};

/**
 * @brief Stream quality levels
 */
enum class StreamQuality {
    Low,     ///< 360p / 64kbps
    Medium,  ///< 720p / 128kbps
    High,    ///< 1080p / 256kbps
    Ultra    ///< 4K / 512kbps
};

/**
 * @brief Client connection state
 */
enum class ClientState {
    Disconnected,  ///< Not connected
    Connecting,    ///< Connecting to server
    Connected,     ///< Connected and authenticated
    Streaming,    actively streaming
    Paused,        ///< Stream paused
    Error          ///< Connection error
};

/**
 * @brief Represents a connected client
 */
class StreamClient {
public:
    StreamClient();
    StreamClient(const QString& id, const QString& name, StreamType type);
    
    QString id() const { return m_id; }
    void setId(const QString& id) { m_id = id; }
    
    QString name() const { return m_name; }
    void setName(const QString& name) { m_name = name; }
    
    QString address() const { return m_address; }
    void setAddress(const QString& address) { m_address = address; }
    
    StreamType type() const { return m_type; }
    void setType(StreamType type) { m_type = type; }
    
    ClientState state() const { return m_state; }
    void setState(ClientState state) { m_state = state; }
    
    StreamQuality quality() const { return m_quality; }
    void setQuality(StreamQuality quality) { m_quality = quality; }
    
    qint64 latency() const { return m_latency; }
    void setLatency(qint64 latency) { m_latency = latency; }
    
    bool isHost() const { return m_isHost; }
    void setHost(bool isHost) { m_isHost = isHost; }
    
    QString currentFile() const { return m_currentFile; }
    void setCurrentFile(const QString& file) { m_currentFile = file; }
    
    int cursorLine() const { return m_cursorLine; }
    void setCursorLine(int line) { m_cursorLine = line; }
    
    int cursorColumn() const { return m_cursorColumn; }
    void setCursorColumn(int column) { m_cursorColumn = column; }
    
    QByteArray audioData() const { return m_audioData; }
    void setAudioData(const QByteArray& data) { m_audioData = data; }
    
    bool isValid() const { return !m_id.isEmpty(); }
    
private:
    QString m_id;
    QString m_name;
    QString m_address;
    StreamType m_type;
    ClientState m_state;
    StreamQuality m_quality;
    qint64 m_latency;
    bool m_isHost;
    QString m_currentFile;
    int m_cursorLine;
    int m_cursorColumn;
    QByteArray m_audioData;
};

/**
 * @brief Represents a streaming session
 */
class StreamSession {
public:
    StreamSession();
    StreamSession(const QString& id, const QString& hostId);
    
    QString id() const { return m_id; }
    void setId(const QString& id) { m_id = id; }
    
    QString hostId() const { return m_hostId; }
    void setHostId(const QString& hostId) { m_hostId = hostId; }
    
    QString name() const { return m_name; }
    void setName(const QString& name) { m_name = name; }
    
    StreamType type() const { return m_type; }
    void setType(StreamType type) { m_type = type; }
    
    StreamQuality quality() const { return m_quality; }
    void setQuality(StreamQuality quality) { m_quality = quality; }
    
    int maxClients() const { return m_maxClients; }
    void setMaxClients(int max) { m_maxClients = max; }
    
    bool isPasswordProtected() const { return m_isPasswordProtected; }
    void setPasswordProtected(bool protected_) { m_isPasswordProtected = protected_; }
    
    bool isPublic() const { return m_isPublic; }
    void setPublic(bool isPublic) { m_isPublic = isPublic; }
    
    QSet<QString> participants() const { return m_participants; }
    void addParticipant(const QString& clientId);
    void removeParticipant(const QString& clientId);
    bool hasParticipant(const QString& clientId) const;
    
    QMap<QString, QByteArray> fileShares() const { return m_fileShares; }
    void addFileShare(const QString& fileId, const QByteArray& data);
    void removeFileShare(const QString& fileId);
    
    QDateTime createdAt() const { return m_createdAt; }
    void setCreatedAt(const QDateTime& time) { m_createdAt = time; }
    
    bool isValid() const { return !m_id.isEmpty(); }
    
private:
    QString m_id;
    QString m_hostId;
    QString m_name;
    StreamType m_type;
    StreamQuality m_quality;
    int m_maxClients;
    bool m_isPasswordProtected;
    bool m_isPublic;
    QSet<QString> m_participants;
    QMap<QString, QByteArray> m_fileShares;
    QDateTime m_createdAt;
};

/**
 * @brief Audio streaming configuration
 */
struct AudioConfig {
    int sampleRate;
    int channels;
    int bitDepth;
    int bufferSize;
    bool noiseReduction;
    bool echoCancellation;
    bool autoGainControl;
    
    AudioConfig() : sampleRate(48000), channels(1), bitDepth(16), bufferSize(1024),
                   noiseReduction(true), echoCancellation(true), autoGainControl(true) {}
};

/**
 * @brief Video streaming configuration
 */
struct VideoConfig {
    int width;
    int height;
    int frameRate;
    StreamQuality quality;
    bool hardwareEncoding;
    bool screenSharing;
    
    VideoConfig() : width(1920), height(1080), frameRate(30), quality(StreamQuality::High),
                   hardwareEncoding(true), screenSharing(false) {}
};

/**
 * @brief Complete Real-Time Streaming Client for RawrXD IDE
 * 
 * Provides comprehensive real-time collaboration features:
 * - WebSocket-based communication
 * - Multi-protocol support (WebRTC for video, WebSocket for data)
 * - Audio/video streaming with quality controls
 * - File sharing and synchronization
 * - Cursor tracking and synchronization
 * - Chat and voice communication
 * 
 * Thread-safe with automatic reconnection and error handling.
 */
class StreamerClient : public QObject {
    Q_OBJECT
    
public:
    /**
     * @brief Construct a StreamerClient
     * @param parent Parent QObject
     */
    explicit StreamerClient(QObject* parent = nullptr);
    
    /**
     * @brief Destructor
     */
    ~StreamerClient() override;
    
    /**
     * @brief Connect to streaming server
     * @param serverUrl Server WebSocket URL
     * @param apiKey API key for authentication
     * @return true if connection initiated successfully
     */
    bool connectToServer(const QString& serverUrl, const QString& apiKey = QString());
    
    /**
     * @brief Disconnect from server
     */
    void disconnectFromServer();
    
    /**
     * @brief Check if connected to server
     * @return true if connected
     */
    bool isConnected() const;
    
    /**
     * @brief Create a new streaming session
     * @param type Type of session
     * @param name Session name
     * @param password Optional password
     * @return Session ID
     */
    QString createSession(StreamType type, const QString& name, const QString& password = QString());
    
    /**
     * @brief Join an existing session
     * @param sessionId Session ID to join
     * @param password Session password
     * @return true if join successful
     */
    bool joinSession(const QString& sessionId, const QString& password = QString());
    
    /**
     * @brief Leave current session
     */
    void leaveSession();
    
    /**
     * @brief Get current session
     * @return Current session object
     */
    StreamSession currentSession() const;
    
    /**
     * @brief Broadcast file change to session
     * @param filePath Changed file path
     * @param content New file content
     * @param changeType Type of change
     */
    void broadcastFileChange(const QString& filePath, const QByteArray& content, const QString& changeType);
    
    /**
     * @brief Broadcast cursor position
     * @param filePath Current file path
     * @param line Line number
     * @param column Column number
     */
    void broadcastCursorPosition(const QString& filePath, int line, int column);
    
    /**
     * @brief Send text message to session
     * @param message Message text
     * @param targetId Target client ID (empty for broadcast)
     */
    void sendMessage(const QString& message, const QString& targetId = QString());
    
    /**
     * @brief Send audio data
     * @param audioData Raw audio data
     */
    void sendAudioData(const QByteArray& audioData);
    
    /**
     * @brief Send video data
     * @param videoData Video frame data
     */
    void sendVideoData(const QByteArray& videoData);
    
    /**
     * @brief Share file with session
     * @param filePath File path to share
     * @param fileData File data
     */
    void shareFile(const QString& filePath, const QByteArray& fileData);
    
    /**
     * @brief Set audio configuration
     * @param config Audio configuration
     */
    void setAudioConfig(const AudioConfig& config);
    
    /**
     * @brief Set video configuration
     * @param config Video configuration
     */
    void setVideoConfig(const VideoConfig& config);
    
    /**
     * @brief Get list of active sessions
     * @return List of session information
     */
    QList<StreamSession> getActiveSessions() const;
    
    /**
     * @brief Get list of connected clients
     * @return List of client information
     */
    QList<StreamClient> getConnectedClients() const;
    
    /**
     * @brief Set user identity
     * @param userId User ID
     * @param userName User name
     * @param avatar Avatar image data
     */
    void setUserIdentity(const QString& userId, const QString& userName, const QByteArray& avatar = QByteArray());
    
    /**
     * @brief Enable/disable specific stream types
     * @param type Stream type
     * @param enabled Whether to enable
     */
    void setStreamTypeEnabled(StreamType type, bool enabled);
    
    /**
     * @brief Check if stream type is enabled
     * @param type Stream type
     * @return true if enabled
     */
    bool isStreamTypeEnabled(StreamType type) const;
    
    /**
     * @brief Set network quality preferences
     * @param maxLatency Maximum acceptable latency (ms)
     * @param maxBandwidth Maximum bandwidth usage (bytes/sec)
     */
    void setNetworkPreferences(int maxLatency = 100, qint64 maxBandwidth = 1024 * 1024);
    
signals:
    /**
     * @brief Emitted when connection state changes
     * @param state New connection state
     * @param message Status message
     */
    void connectionStateChanged(ClientState state, const QString& message);
    
    /**
     * @brief Emitted when session is created
     * @param sessionId New session ID
     */
    void sessionCreated(const QString& sessionId);
    
    /**
     * @brief Emitted when session is joined
     * @param sessionId Joined session ID
     */
    void sessionJoined(const QString& sessionId);
    
    /**
     * @brief Emitted when session is left
     * @param sessionId Left session ID
     */
    void sessionLeft(const QString& sessionId);
    
    /**
     * @brief Emitted when client joins session
     * @param client Client information
     */
    void clientJoined(const StreamClient& client);
    
    /**
     * @brief Emitted when client leaves session
     * @param clientId ID of client that left
     */
    void clientLeft(const QString& clientId);
    
    /**
     * @brief Emitted when file change is received
     * @param filePath File path
     * @param content File content
     * @param clientId Source client ID
     */
    void fileChanged(const QString& filePath, const QByteArray& content, const QString& clientId);
    
    /**
     * @brief Emitted when cursor position is updated
     * @param filePath File path
     * @param line Line number
     * @param column Column number
     * @param clientId Source client ID
     */
    void cursorPositionUpdated(const QString& filePath, int line, int column, const QString& clientId);
    
    /**
     * @brief Emitted when message is received
     * @param message Message text
     * @param senderId Sender client ID
     * @param senderName Sender name
     */
    void messageReceived(const QString& message, const QString& senderId, const QString& senderName);
    
    /**
     * @brief Emitted when audio data is received
     * @param audioData Audio data
     * @param senderId Source client ID
     */
    void audioDataReceived(const QByteArray& audioData, const QString& senderId);
    
    /**
     * @brief Emitted when video data is received
     * @param videoData Video data
     * @param senderId Source client ID
     */
    void videoDataReceived(const QByteArray& videoData, const QString& senderId);
    
    /**
     * @brief Emitted when file is shared
     * @param filePath File path
     * @param fileData File data
     * @param senderId Source client ID
     */
    void fileShared(const QString& filePath, const QByteArray& fileData, const QString& senderId);
    
    /**
     * @brief Emitted when error occurs
     * @param error Error message
     * @param errorCode Error code
     */
    void error(const QString& error, int errorCode = -1);
    
private slots:
    void onConnected();
    void onDisconnected();
    void onTextMessageReceived(const QString& message);
    void onBinaryMessageReceived(const QByteArray& message);
    void onSocketError(QAbstractSocket::SocketError error);
    void onAuthenticationTimeout();
    void onReconnectTimer();
    void onHeartbeatTimer();
    
private:
    /**
     * @brief Send JSON message to server
     */
    void sendJsonMessage(const QJsonObject& message);
    
    /**
     * @brief Handle incoming JSON message
     */
    void handleJsonMessage(const QJsonObject& message);
    
    /**
     * @brief Process different message types
     */
    void processAuthResponse(const QJsonObject& message);
    void processSessionCreated(const QJsonObject& message);
    void processSessionJoined(const QJsonObject& message);
    void processClientJoined(const QJsonObject& message);
    void processClientLeft(const QJsonObject& message);
    void processFileChange(const QJsonObject& message);
    void processCursorUpdate(const QJsonObject& message);
    void processMessage(const QJsonObject& message);
    void processAudioData(const QJsonObject& message);
    void processVideoData(const QJsonObject& message);
    void processFileShare(const QJsonObject& message);
    
    /**
     * @brief Start audio capture
     */
    void startAudioCapture();
    
    /**
     * @brief Stop audio capture
     */
    void stopAudioCapture();
    
    /**
     * @brief Start video capture
     */
    void startVideoCapture();
    
    /**
     * @brief Stop video capture
     */
    void stopVideoCapture();
    
    /**
     * @brief Get current network latency
     */
    qint64 getNetworkLatency() const;
    
    /**
     * @brief Check if network quality is acceptable
     */
    bool isNetworkQualityAcceptable() const;
    
    /**
     * @brief Generate unique session ID
     */
    QString generateSessionId() const;
    
    /**
     * @brief Validate message format
     */
    bool validateMessage(const QJsonObject& message) const;
    
    // Member variables
    std::unique_ptr<QWebSocket> m_websocket;
    QTimer* m_reconnectTimer;
    QTimer* m_heartbeatTimer;
    QTimer* m_authTimer;
    std::unique_ptr<QAudioInput> m_audioInput;
    std::unique_ptr<QAudioOutput> m_audioOutput;
    QNetworkAccessManager* m_networkManager;
    
    // State
    QString m_serverUrl;
    QString m_apiKey;
    QString m_sessionId;
    QString m_userId;
    QString m_userName;
    QByteArray m_avatar;
    ClientState m_state;
    
    // Configuration
    AudioConfig m_audioConfig;
    VideoConfig m_videoConfig;
    int m_maxLatency;
    qint64 m_maxBandwidth;
    QMap<StreamType, bool> m_enabledStreams;
    
    // Data
    QMap<QString, StreamSession> m_sessions;
    QMap<QString, StreamClient> m_clients;
    QMap<QString, QByteArray> m_sharedFiles;
    
    // Thread safety
    mutable QMutex m_mutex;
    
    // Constants
    static constexpr int RECONNECT_INTERVAL = 5000;  // 5 seconds
    static constexpr int HEARTBEAT_INTERVAL = 30000; // 30 seconds
    static constexpr int AUTH_TIMEOUT = 10000;        // 10 seconds
    static constexpr int MAX_RECONNECT_ATTEMPTS = 10;
};

} // namespace RawrXD
