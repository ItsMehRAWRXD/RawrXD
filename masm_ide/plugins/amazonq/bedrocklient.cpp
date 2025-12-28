#include "bedrocklient.h"
#include <QNetworkRequest>
#include <QJsonArray>
#include <QDebug>
#include <QCryptographicHash>
#include <QDateTime>
#include <QSettings>
#include <QStandardPaths>
#include <QDir>
#include <QFile>

namespace AmazonQ {

BedrockClient::BedrockClient(QObject *parent)
    : QObject(parent)
    , m_networkManager(new QNetworkAccessManager(this))
    , m_endpoint("https://bedrock-runtime.us-east-1.amazonaws.com")
    , m_region("us-east-1")
    , m_modelId("anthropic.claude-3-sonnet-20240229-v1:0")
    , m_useExistingConfig(true)
{
    connect(m_networkManager, &QNetworkAccessManager::finished,
            this, &BedrockClient::handleNetworkReply);
}

BedrockClient::~BedrockClient()
{
}

void BedrockClient::setEndpoint(const QString &endpoint)
{
    m_endpoint = endpoint;
}

void BedrockClient::setRegion(const QString &region)
{
    m_region = region;
}

void BedrockClient::setModelId(const QString &modelId)
{
    m_modelId = modelId;
}

void BedrockClient::setUseExistingConfig(bool useExisting)
{
    m_useExistingConfig = useExisting;
}

void BedrockClient::sendMessage(const QString &message, const QString &context)
{
    m_currentRequestType = "chat";
    QJsonObject payload = createChatPayload(message, context);
    makeBedrockRequest(payload, "chat");
}

void BedrockClient::requestCompletion(const QString &code, int cursorPosition)
{
    m_currentRequestType = "completion";
    QJsonObject payload = createCompletionPayload(code, cursorPosition);
    makeBedrockRequest(payload, "completion");
}

void BedrockClient::makeBedrockRequest(const QJsonObject &payload, const QString &requestType)
{
    QString url = QString("%1/model/%2/invoke-with-response-stream").arg(m_endpoint, m_modelId);
    QNetworkRequest request(url);
    
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Accept", "application/vnd.amazon.eventstream");
    request.setRawHeader("User-Agent", "MASM-IDE/1.0");
    
    // AWS Signature V4 headers
    QDateTime now = QDateTime::currentDateTimeUtc();
    QString dateStamp = now.toString("yyyyMMdd");
    QString timeStamp = now.toString("yyyyMMddThhmmssZ");
    
    request.setRawHeader("X-Amz-Date", timeStamp.toUtf8());
    request.setRawHeader("Authorization", createAuthHeader(request, payload, timeStamp).toUtf8());
    
    QJsonDocument doc(payload);
    QByteArray data = doc.toJson(QJsonDocument::Compact);
    
    m_networkManager->post(request, data);
}

QJsonObject BedrockClient::createChatPayload(const QString &message, const QString &context)
{
    QJsonObject payload;
    QJsonArray messages;
    
    QString fullMessage = message;
    if (!context.isEmpty()) {
        fullMessage = QString("Context:\n%1\n\nQuestion: %2").arg(context, message);
    }
    
    QJsonObject userMessage;
    userMessage["role"] = "user";
    userMessage["content"] = fullMessage;
    messages.append(userMessage);
    
    payload["messages"] = messages;
    payload["max_tokens"] = 4000;
    payload["temperature"] = 0.7;
    payload["top_p"] = 0.9;
    payload["anthropic_version"] = "bedrock-2023-05-31";
    
    return payload;
}

QJsonObject BedrockClient::createCompletionPayload(const QString &code, int cursorPosition)
{
    QJsonObject payload;
    
    QString beforeCursor = code.left(cursorPosition);
    QString afterCursor = code.mid(cursorPosition);
    
    QString prompt = QString("Complete this MASM assembly code:\n\n%1<CURSOR>%2")
                    .arg(beforeCursor, afterCursor);
    
    payload["model"] = m_modelId;
    payload["prompt"] = prompt;
    payload["max_tokens"] = 1000;
    payload["temperature"] = 0.3;
    payload["top_p"] = 0.9;
    payload["repetition_penalty"] = 1.1;
    
    return payload;
}

void BedrockClient::handleNetworkReply()
{
    QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) return;
    
    reply->deleteLater();
    
    if (reply->error() != QNetworkReply::NoError) {
        emit errorOccurred(reply->errorString());
        return;
    }
    
    QByteArray data = reply->readAll();
    
    // Handle AWS Bedrock streaming response
    if (reply->rawHeader("Content-Type").contains("eventstream")) {
        parseEventStream(data);
        return;
    }
    
    // Handle regular JSON response
    QJsonDocument doc = QJsonDocument::fromJson(data);
    QJsonObject response = doc.object();
    
    if (response.contains("content")) {
        QJsonArray content = response["content"].toArray();
        if (!content.isEmpty()) {
            QString text = content[0].toObject()["text"].toString();
            
            if (m_currentRequestType == "chat") {
                emit messageReceived(text);
            } else if (m_currentRequestType == "completion") {
                emit completionReceived(text);
            }
            return;
        }
    }
    
    emit errorOccurred("Invalid response format");
}

void BedrockClient::handleNetworkError(QNetworkReply::NetworkError error)
{
    Q_UNUSED(error)
    QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
    if (reply) {
        emit errorOccurred(reply->errorString());
    }
}

} // namespace AmazonQ
QString BedrockClient::createAuthHeader(const QNetworkRequest &request, const QJsonObject &payload, const QString &timestamp)
{
    // Use existing AWS credentials from environment or AWS CLI
    QString accessKey = qgetenv("AWS_ACCESS_KEY_ID");
    QString secretKey = qgetenv("AWS_SECRET_ACCESS_KEY");
    QString sessionToken = qgetenv("AWS_SESSION_TOKEN");
    
    if (accessKey.isEmpty() || secretKey.isEmpty()) {
        // Fallback to AWS CLI credentials
        QSettings awsConfig(QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.aws/credentials", QSettings::IniFormat);
        accessKey = awsConfig.value("default/aws_access_key_id").toString();
        secretKey = awsConfig.value("default/aws_secret_access_key").toString();
    }
    
    if (accessKey.isEmpty()) {
        return ""; // Will cause auth error, handled gracefully
    }
    
    QString service = "bedrock";
    QString algorithm = "AWS4-HMAC-SHA256";
    QString credentialScope = QString("%1/%2/%3/aws4_request").arg(timestamp.left(8), m_region, service);
    
    // Create canonical request
    QString canonicalRequest = QString("POST\n/model/%1/invoke-with-response-stream\n\nhost:%2\nx-amz-date:%3\n\nhost;x-amz-date\n%4")
        .arg(m_modelId, request.url().host(), timestamp, QCryptographicHash::hash(QJsonDocument(payload).toJson(), QCryptographicHash::Sha256).toHex());
    
    // Create string to sign
    QString stringToSign = QString("%1\n%2\n%3\n%4")
        .arg(algorithm, timestamp, credentialScope, QCryptographicHash::hash(canonicalRequest.toUtf8(), QCryptographicHash::Sha256).toHex());
    
    // Calculate signature (simplified)
    QByteArray signingKey = ("AWS4" + secretKey).toUtf8();
    QString signature = QCryptographicHash::hash(stringToSign.toUtf8(), QCryptographicHash::Sha256).toHex();
    
    return QString("%1 Credential=%2/%3, SignedHeaders=host;x-amz-date, Signature=%4")
        .arg(algorithm, accessKey, credentialScope, signature);
}
void BedrockClient::parseEventStream(const QByteArray &data)
{
    // Parse AWS event stream format
    QStringList lines = QString::fromUtf8(data).split('\n');
    QString content;
    
    for (const QString &line : lines) {
        if (line.startsWith("data: ")) {
            QString jsonData = line.mid(6);
            QJsonDocument doc = QJsonDocument::fromJson(jsonData.toUtf8());
            QJsonObject obj = doc.object();
            
            if (obj.contains("delta")) {
                QJsonObject delta = obj["delta"].toObject();
                if (delta.contains("text")) {
                    content += delta["text"].toString();
                }
            }
        }
    }
    
    if (!content.isEmpty()) {
        if (m_currentRequestType == \"chat\") {
            emit messageReceived(content);
        } else if (m_currentRequestType == \"completion\") {
            emit completionReceived(content);
        }
    }
}