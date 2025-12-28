#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>

namespace AmazonQ {

class BedrockClient : public QObject
{
    Q_OBJECT

public:
    explicit BedrockClient(QObject *parent = nullptr);
    ~BedrockClient();

    void setEndpoint(const QString &endpoint);
    void setRegion(const QString &region);
    void setModelId(const QString &modelId);
    void setUseExistingConfig(bool useExisting);

    void sendMessage(const QString &message, const QString &context = QString());
    void requestCompletion(const QString &code, int cursorPosition);

signals:
    void messageReceived(const QString &response);
    void completionReceived(const QString &completion);
    void errorOccurred(const QString &error);

private slots:
    void handleNetworkReply();
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    void makeBedrockRequest(const QJsonObject &payload, const QString &requestType);
    QString signRequest(const QByteArray &payload, const QString &service, const QString &operation);
    QString createAuthHeader(const QNetworkRequest &request, const QJsonObject &payload, const QString &timestamp);
    void parseEventStream(const QByteArray &data);
    QJsonObject createChatPayload(const QString &message, const QString &context);
    QJsonObject createCompletionPayload(const QString &code, int cursorPosition);

    QNetworkAccessManager *m_networkManager;
    QString m_endpoint;
    QString m_region;
    QString m_modelId;
    bool m_useExistingConfig;
    QString m_currentRequestType;
};

} // namespace AmazonQ