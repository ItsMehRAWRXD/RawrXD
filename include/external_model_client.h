#pragma once

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>

/**
 * @brief Client for external AI model APIs (OpenAI, Anthropic, Groq, etc.)
 */
class ExternalModelClient : public QObject {
    Q_OBJECT

public:
    enum Provider {
        OpenAI,
        Anthropic,
        Groq,
        Ollama,
        Custom
    };

    explicit ExternalModelClient(QObject* parent = nullptr);
    virtual ~ExternalModelClient();

    void setConfiguration(Provider provider, const QString& endpoint, const QString& apiKey, const QString& model);
    
    /**
     * Send a message to the external API
     * @param prompt The user prompt
     * @param history Previous conversation history (optional)
     * @param streaming Whether to use streaming (SSE)
     */
    void sendMessage(const QString& prompt, const QJsonArray& history = QJsonArray(), bool streaming = true);

signals:
    void tokenReceived(const QString& token);
    void responseFinished(const QString& fullResponse);
    void errorOccurred(const QString& error);

private slots:
    void onReplyFinished();
    void onReadyRead();
    void onNetworkError(QNetworkReply::NetworkError code);

private:
    void processOpenAIStream(const QByteArray& data);
    void processAnthropicStream(const QByteArray& data);
    
    QNetworkAccessManager* m_networkManager;
    QNetworkReply* m_currentReply = nullptr;
    
    Provider m_provider = OpenAI;
    QString m_endpoint;
    QString m_apiKey;
    QString m_model;
    
    QString m_accumulatedResponse;
};
