#pragma once
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>
#include <functional>

class AwsBedrockBridge : public QObject {
    Q_OBJECT

public:
    explicit AwsBedrockBridge(QObject* parent = nullptr);
    void callModel(const QString& prompt, const QString& context);

signals:
    void responseReceived(const QString& response);
    void errorOccurred(const QString& error);

private:
    QNetworkAccessManager* m_network;
    QString signRequest(const QString& payload);
    QJsonObject convertToBedrockFormat(const QString& prompt);
};
