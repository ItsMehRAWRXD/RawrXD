#include "centralized_exception_handler.h"
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>

namespace RawrXD {

// Static instance pointer for terminate handler
static CentralizedExceptionHandler* g_handlerInstance = nullptr;

CentralizedExceptionHandler& CentralizedExceptionHandler::instance() {
    static CentralizedExceptionHandler instance;
    return instance;
}

CentralizedExceptionHandler::CentralizedExceptionHandler(QObject* parent)
    : QObject(parent)
    , m_totalExceptions(0)
    , m_recoveredExceptions(0)
    , m_maxCapturedExceptions(100)
    , m_automaticRecoveryEnabled(true)
    , m_logAllExceptions(true)
    , m_handlerInstalled(false)
    , m_previousTerminateHandler(nullptr)
{
    g_handlerInstance = this;
}

CentralizedExceptionHandler::~CentralizedExceptionHandler() {
    uninstallHandler();
    g_handlerInstance = nullptr;
}

void CentralizedExceptionHandler::installHandler() {
    if (m_handlerInstalled) {
        return;
    }
    
    // Install custom terminate handler
    m_previousTerminateHandler = std::set_terminate(&CentralizedExceptionHandler::terminateHandler);
    
    // Install unexpected handler (if available)
#if __cplusplus < 201703L
    std::set_unexpected(&CentralizedExceptionHandler::unexpectedHandler);
#endif
    
    m_handlerInstalled = true;
    
    qDebug() << "[ExceptionHandler] Global exception handlers installed";
}

void CentralizedExceptionHandler::uninstallHandler() {
    if (!m_handlerInstalled) {
        return;
    }
    
    if (m_previousTerminateHandler) {
        std::set_terminate(m_previousTerminateHandler);
        m_previousTerminateHandler = nullptr;
    }
    
    m_handlerInstalled = false;
    
    qDebug() << "[ExceptionHandler] Global exception handlers uninstalled";
}

void CentralizedExceptionHandler::registerRecoveryCallback(const QString& errorType, RecoveryCallback callback) {
    m_recoveryCallbacks[errorType] = callback;
    qDebug() << "[ExceptionHandler] Registered recovery callback for:" << errorType;
}

void CentralizedExceptionHandler::unregisterRecoveryCallback(const QString& errorType) {
    m_recoveryCallbacks.remove(errorType);
    qDebug() << "[ExceptionHandler] Unregistered recovery callback for:" << errorType;
}

void CentralizedExceptionHandler::reportException(const std::exception& ex, const QJsonObject& context) {
    QString error = QString::fromUtf8(ex.what());
    QString category = QString::fromUtf8(typeid(ex).name());
    
    reportError(error, category, context);
}

void CentralizedExceptionHandler::reportError(const QString& error, const QString& category, const QJsonObject& context) {
    m_totalExceptions++;
    
    // Log the exception
    logException(error, category, context);
    
    // Capture for statistics
    captureException(error, category, context);
    
    // Attempt recovery if enabled
    if (m_automaticRecoveryEnabled) {
        bool recovered = attemptRecovery(category, error, context);
        if (recovered) {
            m_recoveredExceptions++;
            emit recoveryAttempted(category, true);
        } else {
            emit recoveryAttempted(category, false);
        }
    }
    
    // Emit signal
    emit exceptionCaptured(error, category);
    
    // Check if critical
    if (error.contains("fatal", Qt::CaseInsensitive) || 
        error.contains("critical", Qt::CaseInsensitive)) {
        emit criticalError(error);
    }
}

QJsonObject CentralizedExceptionHandler::getExceptionStatistics() const {
    QJsonObject stats;
    stats["total_exceptions"] = static_cast<qint64>(m_totalExceptions);
    stats["recovered_exceptions"] = static_cast<qint64>(m_recoveredExceptions);
    stats["recovery_rate"] = m_totalExceptions > 0 
        ? (static_cast<double>(m_recoveredExceptions) / m_totalExceptions) 
        : 0.0;
    stats["captured_exceptions_count"] = m_capturedExceptions.size();
    
    // Category breakdown
    QJsonObject categoryBreakdown;
    for (const QJsonObject& ex : m_capturedExceptions) {
        QString category = ex["category"].toString();
        int count = categoryBreakdown[category].toInt(0);
        categoryBreakdown[category] = count + 1;
    }
    stats["category_breakdown"] = categoryBreakdown;
    
    return stats;
}

bool CentralizedExceptionHandler::attemptRecovery(const QString& errorType, const QString& error, const QJsonObject& context) {
    auto it = m_recoveryCallbacks.find(errorType);
    if (it != m_recoveryCallbacks.end()) {
        try {
            return it.value()(error, context);
        } catch (...) {
            qWarning() << "[ExceptionHandler] Recovery callback threw exception for:" << errorType;
            return false;
        }
    }
    
    // Try generic recovery
    it = m_recoveryCallbacks.find("*");
    if (it != m_recoveryCallbacks.end()) {
        try {
            return it.value()(error, context);
        } catch (...) {
            qWarning() << "[ExceptionHandler] Generic recovery callback threw exception";
            return false;
        }
    }
    
    return false;
}

void CentralizedExceptionHandler::logException(const QString& error, const QString& category, const QJsonObject& context) {
    if (!m_logAllExceptions) {
        return;
    }
    
    QDateTime now = QDateTime::currentDateTime();
    QString timestamp = now.toString(Qt::ISODate);
    
    // Console output
    qCritical() << "[EXCEPTION]" << timestamp << category << ":" << error;
    
    // File output (append to error log)
    QString logPath = QCoreApplication::applicationDirPath() + "/logs/exceptions.log";
    QFile logFile(logPath);
    
    if (logFile.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&logFile);
        out << timestamp << " | " << category << " | " << error << "\n";
        
        if (!context.isEmpty()) {
            out << "Context: " << QJsonDocument(context).toJson(QJsonDocument::Compact) << "\n";
        }
        
        out << "---\n";
        logFile.close();
    }
}

void CentralizedExceptionHandler::captureException(const QString& error, const QString& category, const QJsonObject& context) {
    QJsonObject captured;
    captured["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    captured["error"] = error;
    captured["category"] = category;
    captured["context"] = context;
    
    m_capturedExceptions.append(captured);
    
    // Limit size
    if (m_capturedExceptions.size() > m_maxCapturedExceptions) {
        m_capturedExceptions.remove(0);
    }
}

void CentralizedExceptionHandler::terminateHandler() {
    if (g_handlerInstance) {
        try {
            std::exception_ptr eptr = std::current_exception();
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        } catch (const std::exception& ex) {
            g_handlerInstance->reportException(ex);
        } catch (...) {
            g_handlerInstance->reportError("Unknown exception", "unknown", QJsonObject());
        }
    }
    
    qFatal("Unhandled exception - terminating application");
    std::abort();
}

void CentralizedExceptionHandler::unexpectedHandler() {
    if (g_handlerInstance) {
        g_handlerInstance->reportError("Unexpected exception", "unexpected", QJsonObject());
    }
    
    qFatal("Unexpected exception - terminating application");
    std::abort();
}

// ============================================================================
// ExceptionScopeGuard Implementation
// ============================================================================

ExceptionScopeGuard::ExceptionScopeGuard(const QString& scopeName, const QJsonObject& context)
    : m_scopeName(scopeName)
    , m_context(context)
    , m_exceptionOccurred(false)
{
    m_context["scope"] = scopeName;
    m_context["scope_start"] = QDateTime::currentDateTime().toString(Qt::ISODate);
}

ExceptionScopeGuard::~ExceptionScopeGuard() {
    if (std::uncaught_exceptions() > 0) {
        m_exceptionOccurred = true;
        m_context["scope_end"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        
        CentralizedExceptionHandler::instance().reportError(
            QString("Exception in scope: %1").arg(m_scopeName),
            "scope_exception",
            m_context
        );
    }
}

void ExceptionScopeGuard::addContext(const QString& key, const QJsonValue& value) {
    m_context[key] = value;
}

} // namespace RawrXD
