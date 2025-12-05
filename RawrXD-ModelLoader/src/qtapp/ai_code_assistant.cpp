#include "ai_code_assistant.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrl>
#include <QUrlQuery>
#include <QEventLoop>
#include <QTimer>
#include <QDebug>
#include <chrono>
#include <sstream>

AICodeAssistant::AICodeAssistant(QObject *parent)
    : QObject(parent),
      network_manager_(std::make_unique<QNetworkAccessManager>(this)),
      current_reply_(nullptr),
      ollama_url_("http://localhost:11434"),
      model_name_("ministral-3"),
      max_tokens_(256),
      temperature_(0.3f),
      current_request_type_(CodeCompletion),
      ollama_available_(false),
      request_start_time_(0)
{
    connect(this, &AICodeAssistant::connectionStatusChanged, this, [this](bool connected) {
        if (connected) {
            qDebug() << "[AICodeAssistant] Connected to Ollama:" << model_name_;
        }
    });
    
    // Check connectivity on startup
    QTimer::singleShot(500, this, &AICodeAssistant::checkOllamaConnectivity);
}

AICodeAssistant::~AICodeAssistant() {
    if (current_reply_) {
        current_reply_->abort();
    }
}

void AICodeAssistant::setOllamaUrl(const QString &url) {
    ollama_url_ = url;
    checkOllamaConnectivity();
}

void AICodeAssistant::setModel(const QString &model) {
    model_name_ = model;
}

void AICodeAssistant::setMaxTokens(int tokens) {
    max_tokens_ = tokens;
}

void AICodeAssistant::setTemperature(float temp) {
    temperature_ = std::max(0.0f, std::min(2.0f, temp));
}

bool AICodeAssistant::isOllamaAvailable() {
    return ollama_available_;
}

QString AICodeAssistant::getModelInfo() {
    return QString("Model: %1 | Tokens: %2 | Temp: %3")
        .arg(model_name_)
        .arg(max_tokens_)
        .arg(temperature_);
}

void AICodeAssistant::getCodeCompletion(const QString &code, int cursorPos) {
    QString prompt = buildCompletionPrompt(code, cursorPos);
    makeAsyncRequest(prompt, CodeCompletion, code);
}

void AICodeAssistant::getRefactoringSuggestion(const QString &code) {
    QString prompt = buildRefactoringPrompt(code);
    makeAsyncRequest(prompt, Refactoring, code);
}

void AICodeAssistant::getExplanation(const QString &code) {
    QString prompt = buildExplanationPrompt(code);
    makeAsyncRequest(prompt, Explanation, code);
}

void AICodeAssistant::getBugFix(const QString &code, const QString &errorMessage) {
    QString prompt = buildBugFixPrompt(code, errorMessage);
    makeAsyncRequest(prompt, BugFix, code);
}

void AICodeAssistant::getOptimization(const QString &code) {
    QString prompt = buildOptimizationPrompt(code);
    makeAsyncRequest(prompt, Optimization, code);
}

void AICodeAssistant::cancelPendingRequest() {
    if (current_reply_) {
        current_reply_->abort();
        current_reply_->deleteLater();
        current_reply_ = nullptr;
    }
}

void AICodeAssistant::checkOllamaConnectivity() {
    QUrl url(ollama_url_ + "/api/tags");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("User-Agent", "RawrXD-AgenticIDE/1.0");
    
    QNetworkReply *reply = network_manager_->get(request);
    
    QEventLoop loop;
    connect(reply, QOverload<QNetworkReply::NetworkError>::of(&QNetworkReply::error),
            &loop, &QEventLoop::quit);
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    
    // 2 second timeout
    QTimer::singleShot(2000, &loop, &QEventLoop::quit);
    loop.exec();
    
    if (reply->error() == QNetworkReply::NoError) {
        ollama_available_ = true;
        qDebug() << "[AICodeAssistant] Ollama is available at" << ollama_url_;
        emit connectionStatusChanged(true);
    } else {
        ollama_available_ = false;
        qWarning() << "[AICodeAssistant] Ollama unavailable:" << reply->errorString();
        emit connectionStatusChanged(false);
    }
    
    reply->deleteLater();
}

QString AICodeAssistant::buildCompletionPrompt(const QString &code, int cursorPos) {
    QString prefix = code.left(cursorPos);
    
    std::ostringstream oss;
    oss << "You are an expert code completion AI. Complete the following code snippet.\n"
        << "Only output the completion, no explanation.\n"
        << "Keep it concise and syntactically correct.\n\n"
        << "Code to complete:\n"
        << prefix.toStdString()
        << "\n\nCompletion:";
    
    return QString::fromStdString(oss.str());
}

QString AICodeAssistant::buildRefactoringPrompt(const QString &code) {
    std::ostringstream oss;
    oss << "You are an expert code refactoring AI. Suggest improvements for the following code:\n"
        << "Focus on readability, performance, and best practices.\n"
        << "Output: REFACTORED_CODE\n```\n<improved code>\n```\n\n"
        << "EXPLANATION\n<why these changes improve the code>\n\n"
        << "Original code:\n"
        << code.toStdString()
        << "\n\nRefactored version:";
    
    return QString::fromStdString(oss.str());
}

QString AICodeAssistant::buildExplanationPrompt(const QString &code) {
    std::ostringstream oss;
    oss << "You are an expert code explanation AI. Explain what the following code does.\n"
        << "Be clear and concise, suitable for a developer who is new to the codebase.\n\n"
        << "Code:\n"
        << code.toStdString()
        << "\n\nExplanation:";
    
    return QString::fromStdString(oss.str());
}

QString AICodeAssistant::buildBugFixPrompt(const QString &code, const QString &errorMessage) {
    std::ostringstream oss;
    oss << "You are an expert debugging AI. The following code has a bug.\n"
        << "Error message: " << errorMessage.toStdString() << "\n"
        << "Suggest a fix. Output:\n"
        << "FIXED_CODE\n```\n<corrected code>\n```\n\n"
        << "EXPLANATION\n<why this fixes the bug>\n\n"
        << "Buggy code:\n"
        << code.toStdString()
        << "\n\nFixed version:";
    
    return QString::fromStdString(oss.str());
}

QString AICodeAssistant::buildOptimizationPrompt(const QString &code) {
    std::ostringstream oss;
    oss << "You are an expert performance optimization AI. Suggest optimizations for the following code:\n"
        << "Focus on algorithmic complexity, memory usage, and speed.\n"
        << "Output: OPTIMIZED_CODE\n```\n<optimized code>\n```\n\n"
        << "EXPLANATION\n<performance improvements>\n\n"
        << "Current code:\n"
        << code.toStdString()
        << "\n\nOptimized version:";
    
    return QString::fromStdString(oss.str());
}

void AICodeAssistant::makeAsyncRequest(const QString &prompt, SuggestionType type, const QString &originalCode) {
    if (!ollama_available_) {
        emit error("Ollama not available. Start Ollama with: ollama run ministral-3");
        return;
    }
    
    if (current_reply_) {
        current_reply_->abort();
        current_reply_->deleteLater();
    }
    
    // Build Ollama API request
    QUrl url(ollama_url_ + "/api/generate");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("User-Agent", "RawrXD-AgenticIDE/1.0");
    request.setRawHeader("Accept-Encoding", "gzip");  // Accept MASM-compressed responses
    
    QJsonObject json_obj;
    json_obj["model"] = model_name_;
    json_obj["prompt"] = prompt;
    json_obj["temperature"] = temperature_;
    json_obj["num_predict"] = max_tokens_;
    json_obj["stream"] = true;  // Enable streaming
    
    QJsonDocument doc(json_obj);
    QByteArray data = doc.toJson(QJsonDocument::Compact);
    
    // Compress request payload using MASM brutal gzip for ultra-fast transport
    QByteArray compressed_data = brutal::compress(data);
    bool request_compressed = false;
    
    if (compressed_data.size() < data.size()) {
        request_compressed = true;
        data = compressed_data;
        request.setRawHeader("Content-Encoding", "gzip");
        qDebug() << "[AICodeAssistant] MASM compressed request:" << data.size() << "bytes";
    }
    
    current_request_type_ = type;
    current_original_code_ = originalCode;
    accumulated_response_.clear();
    request_start_time_ = std::chrono::milliseconds(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    qDebug() << "[AICodeAssistant] Requesting" << type << "from" << model_name_;
    
    current_reply_ = network_manager_->post(request, data);
    
    connect(current_reply_, &QNetworkReply::readyRead, this, &AICodeAssistant::onNetworkReplyReadyRead);
    connect(current_reply_, QOverload<QNetworkReply::NetworkError>::of(&QNetworkReply::error),
            this, &AICodeAssistant::onNetworkReplyError);
    connect(current_reply_, &QNetworkReply::finished, this, &AICodeAssistant::onNetworkReplyFinished);
}

void AICodeAssistant::onNetworkReplyReadyRead() {
    if (!current_reply_) return;
    
    // Read streaming JSON responses from Ollama
    QByteArray data = current_reply_->readAll();
    
    // Check if response is gzip-compressed (by MASM server)
    QString content_encoding = current_reply_->header(QNetworkRequest::ContentEncodingHeader).toString();
    if (content_encoding.contains("gzip", Qt::CaseInsensitive)) {
        // Decompress using MASM brutal inflate
        QByteArray decompressed = brutal::decompress(data);
        if (!decompressed.isEmpty()) {
            data = decompressed;
            qDebug() << "[AICodeAssistant] MASM decompressed response:" << data.size() << "bytes";
        }
    }
    
    // Process line-delimited JSON
    QStringList lines = QString::fromUtf8(data).split('\n', Qt::SkipEmptyParts);
    
    for (const QString &line : lines) {
        QJsonDocument doc = QJsonDocument::fromJson(line.toUtf8());
        if (!doc.isObject()) continue;
        
        QJsonObject obj = doc.object();
        if (obj.contains("response")) {
            QString response = obj["response"].toString();
            accumulated_response_ += response;
            
            // Emit streaming updates
            emit suggestionStreaming(response);
        }
    }
}

void AICodeAssistant::onNetworkReplyFinished() {
    if (!current_reply_) return;
    
    long end_time = std::chrono::milliseconds(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    int latency = static_cast<int>(end_time - request_start_time_);
    
    emit latencyMeasured(latency);
    
    if (current_reply_->error() != QNetworkReply::NoError) {
        onNetworkReplyError();
        return;
    }
    
    // Parse final response
    CodeSuggestion suggestion = parseOllamaResponse(
        accumulated_response_,
        current_request_type_,
        current_original_code_
    );
    suggestion.latency_ms = latency;
    
    qDebug() << "[AICodeAssistant] Suggestion ready in" << latency << "ms";
    emit suggestionStreamComplete();
    emit suggestionReady(suggestion);
    
    current_reply_->deleteLater();
    current_reply_ = nullptr;
}

void AICodeAssistant::onNetworkReplyError() {
    if (!current_reply_) return;
    
    QString error_msg = QString("Ollama request failed: %1")
        .arg(current_reply_->errorString());
    
    qWarning() << "[AICodeAssistant]" << error_msg;
    emit error(error_msg);
    
    current_reply_->deleteLater();
    current_reply_ = nullptr;
}

AICodeAssistant::CodeSuggestion AICodeAssistant::parseOllamaResponse(
    const QString &response,
    SuggestionType type,
    const QString &originalCode)
{
    CodeSuggestion suggestion;
    suggestion.type = type;
    suggestion.original_code = originalCode;
    suggestion.suggested_code = response.trimmed();
    suggestion.confidence = 0.75f;  // Ollama model confidence
    suggestion.latency_ms = 0;       // Will be set by caller
    
    // Generate explanation based on type
    switch (type) {
        case CodeCompletion:
            suggestion.explanation = "AI-suggested code completion";
            break;
        case Refactoring:
            suggestion.explanation = "Code refactoring suggestion for improved readability";
            break;
        case Explanation:
            suggestion.explanation = response;
            suggestion.suggested_code = "";
            break;
        case BugFix:
            suggestion.explanation = "AI-suggested bug fix";
            break;
        case Optimization:
            suggestion.explanation = "Performance optimization suggestion";
            break;
    }
    
    return suggestion;
}
