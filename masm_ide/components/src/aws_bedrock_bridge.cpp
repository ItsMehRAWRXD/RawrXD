#include "aws_bedrock_bridge.h"
#include <QNetworkRequest>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QDateTime>
#include <QProcessEnvironment>

AwsBedrockBridge::AwsBedrockBridge(QObject* parent) : QObject(parent) {
    m_network = new QNetworkAccessManager(this);
}

void AwsBedrockBridge::callModel(const QString& prompt, const QString& context) {
    QJsonObject payload = convertToBedrockFormat(prompt);
    QJsonDocument doc(payload);
    QString jsonData = doc.toJson(QJsonDocument::Compact);
    
    QString url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet-20240229-v1:0/invoke";
    QNetworkRequest request(url);
    
    QString auth = signRequest(jsonData);
    request.setRawHeader("Authorization", auth.toUtf8());
    request.setRawHeader("Content-Type", "application/json");
    request.setRawHeader("X-Amz-Date", QDateTime::currentDateTimeUtc().toString("yyyyMMddThhmmssZ").toUtf8());
    
    QNetworkReply* reply = m_network->post(request, jsonData.toUtf8());
    
    connect(reply, &QNetworkReply::finished, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QJsonDocument response = QJsonDocument::fromJson(reply->readAll());
            QString content = response.object()["content"].toArray()[0].toObject()["text"].toString();
            emit responseReceived(content);
        } else {
            emit errorOccurred(reply->errorString());
        }
        reply->deleteLater();
    });
}

QJsonObject AwsBedrockBridge::convertToBedrockFormat(const QString& prompt) {
    return QJsonObject{
        {"anthropic_version", "bedrock-2023-05-31"},
        {"max_tokens", 4096},
        {"messages", QJsonArray{QJsonObject{{"role", "user"}, {"content", prompt}}}},
        {"temperature", 0.7}
    };
}

QString AwsBedrockBridge::signRequest(const QString& payload) {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    QString accessKey = env.value("AWS_ACCESS_KEY_ID");
    QString secretKey = env.value("AWS_SECRET_ACCESS_KEY");
    
    // Minimal SigV4 - use AWS CLI credentials
    return QString("AWS4-HMAC-SHA256 Credential=%1/20240101/us-east-1/bedrock-runtime/aws4_request").arg(accessKey);
}
