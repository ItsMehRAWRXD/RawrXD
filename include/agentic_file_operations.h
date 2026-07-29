<<<<<<< HEAD
#ifndef AGENTIC_FILE_OPERATIONS_H
#define AGENTIC_FILE_OPERATIONS_H

// C++20 / Win32 — no Qt. File operation approval workflow with callbacks.

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <fstream>
#include <iterator>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#endif

// ============ Action types (replaces Qt dialog) ============

enum class AgenticFileActionType
{
    CREATE_FILE,
    MODIFY_FILE,
    DELETE_FILE
};

// ============ AgenticFileOperations — callback-based, no QObject ============

struct FileActionRecord
{
    std::string filePath;
    AgenticFileActionType actionType = AgenticFileActionType::CREATE_FILE;
    std::string content;
    std::string oldContent;
    std::chrono::system_clock::time_point timestamp{};
};

class AgenticFileOperations
{
public:
    using ApprovalCallback = std::function<bool(const std::string& filePath, AgenticFileActionType type, const std::string* content)>;
    using NotifyCallback   = std::function<void(const std::string& filePath)>;

    AgenticFileOperations() = default;

    void setApprovalCallback(ApprovalCallback cb) { m_approvalCb = std::move(cb); }
    void setOnFileCreated(NotifyCallback cb)     { m_onCreated  = std::move(cb); }
    void setOnFileModified(NotifyCallback cb)    { m_onModified = std::move(cb); }
    void setOnFileDeleted(NotifyCallback cb)     { m_onDeleted  = std::move(cb); }
    void setOnOperationUndone(NotifyCallback cb) { m_onUndone   = std::move(cb); }
    void setOnOperationCancelled(NotifyCallback cb) { m_onCancelled = std::move(cb); }

    void createFileWithApproval(const std::string& filePath, const std::string& content);
    void modifyFileWithApproval(const std::string& filePath, const std::string& newContent);
    void deleteFileWithApproval(const std::string& filePath);

    void undoLastAction();
    bool canUndo() const { return !m_actionHistory.empty(); }
    size_t getHistorySize() const { return m_actionHistory.size(); }

#ifdef _WIN32
    void setParentWindow(HWND hwnd) { m_parentHwnd = hwnd; }
#endif

private:
    bool requestApproval(const std::string& filePath, AgenticFileActionType type, const std::string* content);

    static constexpr size_t MAX_HISTORY = 50;
    std::vector<FileActionRecord> m_actionHistory;
    ApprovalCallback m_approvalCb;
    NotifyCallback   m_onCreated;
    NotifyCallback   m_onModified;
    NotifyCallback   m_onDeleted;
    NotifyCallback   m_onUndone;
    NotifyCallback   m_onCancelled;
#ifdef _WIN32
    HWND m_parentHwnd = nullptr;
#endif
};

inline bool AgenticFileOperations::requestApproval(const std::string& filePath, AgenticFileActionType type, const std::string* content)
{
    if (m_approvalCb)
        return m_approvalCb(filePath, type, content);
#ifdef _WIN32
    std::wstring msg = L"Allow file operation?\nPath: ";
    msg += std::wstring(filePath.begin(), filePath.end());
    return MessageBoxW(m_parentHwnd, msg.c_str(), L"Agentic File Operation", MB_YESNO | MB_ICONQUESTION) == IDYES;
#else
    (void)filePath; (void)type; (void)content;
    return true;
#endif
}

inline void AgenticFileOperations::createFileWithApproval(const std::string& filePath, const std::string& content)
{
    if (!requestApproval(filePath, AgenticFileActionType::CREATE_FILE, &content)) {
        if (m_onCancelled) m_onCancelled(filePath);
        return;
    }
    std::ofstream f(filePath);
    if (f) f << content;
    if (m_actionHistory.size() < MAX_HISTORY)
        m_actionHistory.push_back({ filePath, AgenticFileActionType::CREATE_FILE, content, {}, std::chrono::system_clock::now() });
    if (m_onCreated) m_onCreated(filePath);
}

inline void AgenticFileOperations::modifyFileWithApproval(const std::string& filePath, const std::string& newContent)
{
    std::string oldContent;
    { std::ifstream f(filePath); if (f) oldContent.assign(std::istreambuf_iterator<char>(f), {}); }
    if (!requestApproval(filePath, AgenticFileActionType::MODIFY_FILE, &newContent)) {
        if (m_onCancelled) m_onCancelled(filePath);
        return;
    }
    std::ofstream f(filePath);
    if (f) f << newContent;
    if (m_actionHistory.size() < MAX_HISTORY)
        m_actionHistory.push_back({ filePath, AgenticFileActionType::MODIFY_FILE, newContent, oldContent, std::chrono::system_clock::now() });
    if (m_onModified) m_onModified(filePath);
}

inline void AgenticFileOperations::deleteFileWithApproval(const std::string& filePath)
{
    if (!requestApproval(filePath, AgenticFileActionType::DELETE_FILE, nullptr)) {
        if (m_onCancelled) m_onCancelled(filePath);
        return;
    }
    std::remove(filePath.c_str());
    if (m_actionHistory.size() < MAX_HISTORY)
        m_actionHistory.push_back({ filePath, AgenticFileActionType::DELETE_FILE, {}, {}, std::chrono::system_clock::now() });
    if (m_onDeleted) m_onDeleted(filePath);
}

inline void AgenticFileOperations::undoLastAction()
{
    if (m_actionHistory.empty()) return;
    FileActionRecord& last = m_actionHistory.back();
    if (last.actionType == AgenticFileActionType::MODIFY_FILE && !last.oldContent.empty()) {
        std::ofstream f(last.filePath);
        if (f) f << last.oldContent;
    } else if (last.actionType == AgenticFileActionType::CREATE_FILE) {
        std::remove(last.filePath.c_str());
    }
    if (m_onUndone) m_onUndone(last.filePath);
    m_actionHistory.pop_back();
}

#endif // AGENTIC_FILE_OPERATIONS_H
=======
#ifndef AGENTIC_FILE_OPERATIONS_H
#define AGENTIC_FILE_OPERATIONS_H

#include <QDialog>
#include <QPushButton>
#include <QTextEdit>
#include <QObject>
#include <QList>
#include <QDateTime>
#include <QString>

// ============ AgenticActionDialog - File Operation Approval UI ============

class AgenticActionDialog : public QDialog
{
    Q_OBJECT

public:
    enum ActionType
    {
        CREATE_FILE,
        MODIFY_FILE,
        DELETE_FILE
    };

    explicit AgenticActionDialog(const QString& filePath, ActionType type,
                                 const QString& content, QWidget* parent = nullptr);

private:
    void setupUI();

    QString m_filePath;
    QString m_content;
    ActionType m_actionType;
};

// ============ AgenticFileOperations - File Operation Handler ============

class AgenticErrorHandler;

class AgenticFileOperations : public QObject
{
    Q_OBJECT

public:
    explicit AgenticFileOperations(QObject* parent = nullptr, AgenticErrorHandler* errorHandler = nullptr);

    // Public API for file operations with approval workflow
    void createFileWithApproval(const QString& filePath, const QString& content);
    void modifyFileWithApproval(const QString& filePath, const QString& newContent);
    void modifyFileWithApproval(const QString& filePath, const QString& oldContent, const QString& newContent);  // Overload with explicit old content
    void deleteFileWithApproval(const QString& filePath);

    // Undo support
    void undoLastAction();
    bool canUndo() const { return !m_actionHistory.isEmpty(); }
    int getHistorySize() const;
    int getUndoStackSize() const { return getHistorySize(); }  // Alias for test compatibility
    
    // Metrics support (stub for test compatibility)
    struct Metrics { int operations = 0; int errors = 0; };
    const Metrics* getMetrics() const { return &m_metrics; }
    
    // Test mode - skip approval dialogs for automated testing
    void setTestMode(bool enabled) { m_testMode = enabled; }
    bool isTestMode() const { return m_testMode; }

signals:
    void fileCreated(const QString& filePath);
    void fileModified(const QString& filePath);
    void fileDeleted(const QString& filePath);
    void operationUndone(const QString& filePath);
    void operationCancelled(const QString& filePath);

private:
    // Action history tracking
    struct FileAction
    {
        QString filePath;
        AgenticActionDialog::ActionType actionType;
        QString content;
        QString oldContent;
        QDateTime timestamp;
    };

    QList<FileAction> m_actionHistory;
    int m_maxHistory = 50;  // Default, can be overridden by env var
    AgenticErrorHandler* m_errorHandler = nullptr;
    Metrics m_metrics;
    bool m_testMode = false;  // Skip approval dialogs when true
};

#endif // AGENTIC_FILE_OPERATIONS_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
