#ifndef AI_CODE_ASSISTANT_H
#define AI_CODE_ASSISTANT_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QUrl>
#include <memory>
#include <vector>

// MASM-compressed GGUF server support
#include "deflate_brutal_qt.hpp"

class QNetworkReply;
class AICodeAssistant : public QObject {
    Q_OBJECT

public:
    enum SuggestionType {
        CodeCompletion,      // Inline code continuation
        Refactoring,         // Code improvement suggestion
        Explanation,         // Explain what code does
        BugFix,              // Suggest fix for potential bug
        Optimization         // Performance optimization
    };
    Q_ENUM(SuggestionType)

    struct CodeSuggestion {
        SuggestionType type;
        QString original_code;
        QString suggested_code;
        QString explanation;
        float confidence;        // 0.0-1.0
        int latency_ms;          // Response time
    };

    explicit AICodeAssistant(QObject *parent = nullptr);
    ~AICodeAssistant();

    // Configuration
    void setOllamaUrl(const QString &url);
    void setModel(const QString &model);
    void setMaxTokens(int tokens);
    void setTemperature(float temp);

    // Request suggestions (async)
    void getCodeCompletion(const QString &code, int cursorPos);
    void getRefactoringSuggestion(const QString &code);
    void getExplanation(const QString &code);
    void getBugFix(const QString &code, const QString &errorMessage);
    void getOptimization(const QString &code);

    // Cancellation
    void cancelPendingRequest();

    // Query Ollama connectivity
    bool isOllamaAvailable();
    QString getModelInfo();

signals:
    // Emitted when suggestion is ready
    void suggestionReady(const CodeSuggestion &suggestion);
    
    // Streaming suggestions (for real-time display)
    void suggestionStreaming(const QString &partial);
    void suggestionStreamComplete();
    
    // Error handling
    void error(const QString &errorMessage);
    
    // Connection status
    void connectionStatusChanged(bool connected);
    
    // Performance metrics
    void latencyMeasured(int latency_ms);

private slots:
    void onNetworkReplyFinished();
    void onNetworkReplyReadyRead();
    void onNetworkReplyError();

private:
    // Internal helpers
    QString buildCompletionPrompt(const QString &code, int cursorPos);
    QString buildRefactoringPrompt(const QString &code);
    QString buildExplanationPrompt(const QString &code);
    QString buildBugFixPrompt(const QString &code, const QString &errorMessage);
    QString buildOptimizationPrompt(const QString &code);
    
    CodeSuggestion parseOllamaResponse(const QString &response, SuggestionType type, const QString &originalCode);
    
    void makeAsyncRequest(const QString &prompt, SuggestionType type, const QString &originalCode);
    void checkOllamaConnectivity();

    // Members
    std::unique_ptr<QNetworkAccessManager> network_manager_;
    QNetworkReply *current_reply_;
    
    QString ollama_url_;              // e.g., "http://localhost:11434"
    QString model_name_;              // e.g., "ministral-3"
    int max_tokens_;
    float temperature_;
    
    SuggestionType current_request_type_;
    QString current_original_code_;
    QString accumulated_response_;
    
    bool ollama_available_;
    long request_start_time_;
};

#endif // AI_CODE_ASSISTANT_H
