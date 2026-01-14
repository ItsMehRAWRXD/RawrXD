#include "error_handler.h"

#include <QMessageBox>
#include <QDateTime>
#include <QFile>
#include <QStandardPaths>
#include <QDir>
#include <QApplication>
#include <QDebug>
#include <stdexcept>
#include <sstream>

/**
 * @file error_handler.cpp
 * @brief Implementation of global exception handling
 */

ErrorHandler& ErrorHandler::instance() {
    static ErrorHandler inst;
    return inst;
}

ErrorHandler::ErrorHandler()
    : QObject(nullptr)
{
    try {
        initializeRecoveryActions();
        qDebug() << "[ErrorHandler] Initialized";
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error during initialization:" << e.what();
    }
}

ErrorHandler::~ErrorHandler() {
    try {
        qDebug() << "[ErrorHandler] Shutdown";
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error during shutdown:" << e.what();
    }
}

void ErrorHandler::handleException(const std::exception& e,
                                   ErrorCategory category,
                                   const QString& sourceFile,
                                   int sourceLine) {
    try {
        ErrorInfo error;
        error.message = QString::fromStdString(e.what());
        error.level = ErrorLevel::Error;
        error.category = category;
        error.timestamp = QDateTime::currentMSecsSinceEpoch();
        error.sourceFile = sourceFile;
        error.sourceLine = sourceLine;

        handleError(error.message, error.level, error.category);

        m_lastError = error;

        if (m_errorHistory.size() >= MAX_HISTORY_SIZE) {
            m_errorHistory.removeFirst();
        }
        m_errorHistory.append(error);

        logErrorToFile(error);
        emit errorOccurred(error);

        qWarning() << "[ErrorHandler] Exception:" << error.message;

    } catch (const std::exception& inner) {
        qCritical() << "[ErrorHandler] Error handling exception:" << inner.what();
    }
}

void ErrorHandler::handleError(const QString& message,
                               ErrorLevel level,
                               ErrorCategory category) {
    try {
        ErrorInfo error;
        error.message = message;
        error.level = level;
        error.category = category;
        error.timestamp = QDateTime::currentMSecsSinceEpoch();

        m_lastError = error;

        if (m_errorHistory.size() >= MAX_HISTORY_SIZE) {
            m_errorHistory.removeFirst();
        }
        m_errorHistory.append(error);

        // Log based on level
        switch (level) {
            case ErrorLevel::Info:
                qDebug() << "[ErrorHandler]" << message;
                break;
            case ErrorLevel::Warning:
                qWarning() << "[ErrorHandler]" << message;
                break;
            case ErrorLevel::Error:
                qCritical() << "[ErrorHandler]" << message;
                break;
            case ErrorLevel::Critical:
            case ErrorLevel::Fatal:
                qCritical() << "[ErrorHandler] CRITICAL:" << message;
                break;
        }

        logErrorToFile(error);
        emit errorOccurred(error);

    } catch (const std::exception& e) {
        qCritical() << "[ErrorHandler] Error handling error:" << e.what();
    }
}

void ErrorHandler::handleErrorWithDetails(const QString& message,
                                         const QString& details,
                                         ErrorLevel level,
                                         ErrorCategory category) {
    try {
        ErrorInfo error;
        error.message = message;
        error.details = details;
        error.level = level;
        error.category = category;
        error.timestamp = QDateTime::currentMSecsSinceEpoch();

        m_lastError = error;

        if (m_errorHistory.size() >= MAX_HISTORY_SIZE) {
            m_errorHistory.removeFirst();
        }
        m_errorHistory.append(error);

        logErrorToFile(error);
        emit errorOccurred(error);

        if (level == ErrorLevel::Critical || level == ErrorLevel::Fatal) {
            emit criticalErrorReported(message);
        } else {
            emit errorReported(message);
        }

        qWarning() << "[ErrorHandler]" << message << details;

    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error in handleErrorWithDetails:" << e.what();
    }
}

bool ErrorHandler::showErrorDialog(const ErrorInfo& error, const QList<RecoveryAction>& recoveryActions) {
    try {
        QMessageBox msgBox;
        msgBox.setWindowTitle("Error");

        // Set icon based on level
        switch (error.level) {
            case ErrorLevel::Info:
                msgBox.setIcon(QMessageBox::Information);
                break;
            case ErrorLevel::Warning:
                msgBox.setIcon(QMessageBox::Warning);
                break;
            case ErrorLevel::Error:
                msgBox.setIcon(QMessageBox::Critical);
                break;
            case ErrorLevel::Critical:
            case ErrorLevel::Fatal:
                msgBox.setIcon(QMessageBox::Critical);
                break;
        }

        msgBox.setText(error.message);
        if (!error.details.isEmpty()) {
            msgBox.setDetailedText(error.details);
        }

        // Add recovery action buttons
        if (!recoveryActions.isEmpty()) {
            int buttonId = 0;
            for (const RecoveryAction& action : recoveryActions) {
                auto button = msgBox.addButton(action.name, QMessageBox::ActionRole);
                if (action.isDefault) {
                    msgBox.setDefaultButton(button);
                }
                ++buttonId;
            }

            msgBox.exec();

            // Find which button was clicked
            int clickedIndex = 0;
            for (int i = 0; i < recoveryActions.size(); ++i) {
                if (msgBox.clickedButton() && 
                    msgBox.clickedButton()->text() == recoveryActions[i].name) {
                    clickedIndex = i;
                    break;
                }
            }

            if (clickedIndex >= 0 && clickedIndex < recoveryActions.size()) {
                const RecoveryAction& action = recoveryActions[clickedIndex];
                try {
                    bool success = action.action ? action.action() : false;
                    emit recoveryActionTaken(action.name, success);
                    return success;
                } catch (const std::exception& e) {
                    qWarning() << "[ErrorHandler] Recovery action failed:" << e.what();
                    emit recoveryActionTaken(action.name, false);
                    return false;
                }
            }
        } else {
            msgBox.setStandardButtons(QMessageBox::Ok);
            msgBox.exec();
        }

        emit errorDialogShown(error);
        return true;

    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error showing error dialog:" << e.what();
        return false;
    }
}

void ErrorHandler::showErrorDialog(const QString& title, const QString& message, ErrorLevel level) {
    try {
        QMessageBox msgBox;
        msgBox.setWindowTitle(title);
        msgBox.setText(message);

        switch (level) {
            case ErrorLevel::Info:
                msgBox.setIcon(QMessageBox::Information);
                break;
            case ErrorLevel::Warning:
                msgBox.setIcon(QMessageBox::Warning);
                break;
            case ErrorLevel::Error:
            case ErrorLevel::Critical:
            case ErrorLevel::Fatal:
                msgBox.setIcon(QMessageBox::Critical);
                break;
        }

        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.exec();

    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error showing dialog:" << e.what();
    }
}

void ErrorHandler::showWarningDialog(const QString& title, const QString& message) {
    try {
        QMessageBox::warning(nullptr, title, message);
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error showing warning:" << e.what();
    }
}

void ErrorHandler::showInfoDialog(const QString& title, const QString& message) {
    try {
        QMessageBox::information(nullptr, title, message);
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error showing info:" << e.what();
    }
}

bool ErrorHandler::askConfirmation(const QString& title, const QString& message, bool defaultYes) {
    try {
        QMessageBox::StandardButton result = QMessageBox::question(
            nullptr,
            title,
            message,
            defaultYes ? QMessageBox::Yes | QMessageBox::No : QMessageBox::No | QMessageBox::Yes
        );
        return result == QMessageBox::Yes;
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error asking confirmation:" << e.what();
        return false;
    }
}

const ErrorHandler::ErrorInfo& ErrorHandler::getLastError() const {
    return m_lastError;
}

QList<ErrorHandler::ErrorInfo> ErrorHandler::getErrorHistory(int count) const {
    QList<ErrorInfo> result;
    int start = qMax(0, m_errorHistory.size() - count);

    for (int i = start; i < m_errorHistory.size(); ++i) {
        result.append(m_errorHistory[i]);
    }

    return result;
}

void ErrorHandler::clearErrorHistory() {
    try {
        m_errorHistory.clear();
        qDebug() << "[ErrorHandler] Error history cleared";
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error clearing history:" << e.what();
    }
}

void ErrorHandler::registerRecoveryAction(ErrorCategory category, const RecoveryAction& action) {
    try {
        m_recoveryActions[category].append(action);
        qDebug() << "[ErrorHandler] Registered recovery action:" << action.name;
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error registering recovery action:" << e.what();
    }
}

QList<ErrorHandler::RecoveryAction> ErrorHandler::getRecoveryActions(ErrorCategory category) const {
    if (m_recoveryActions.contains(category)) {
        return m_recoveryActions[category];
    }
    return QList<RecoveryAction>();
}

bool ErrorHandler::isRecoverable(const ErrorInfo& error) const {
    try {
        return error.level == ErrorLevel::Error || 
               error.level == ErrorLevel::Warning ||
               error.level == ErrorLevel::Info;
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error checking recoverability:" << e.what();
        return false;
    }
}

QString ErrorHandler::getUserFriendlyMessage(const ErrorInfo& error) const {
    try {
        QString msg = error.message;

        // Try to make technical messages more user-friendly
        if (error.category == ErrorCategory::FileSystem) {
            if (msg.contains("Permission denied", Qt::CaseInsensitive)) {
                return "You don't have permission to access this file or folder.";
            } else if (msg.contains("not found", Qt::CaseInsensitive)) {
                return "The file or folder could not be found.";
            }
        } else if (error.category == ErrorCategory::Model) {
            if (msg.contains("out of memory", Qt::CaseInsensitive)) {
                return "Not enough memory to load the model. Try closing other applications.";
            }
        }

        return msg;

    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error creating friendly message:" << e.what();
        return error.message;
    }
}

QString ErrorHandler::getErrorLevelName(ErrorLevel level) {
    switch (level) {
        case ErrorLevel::Info: return "Info";
        case ErrorLevel::Warning: return "Warning";
        case ErrorLevel::Error: return "Error";
        case ErrorLevel::Critical: return "Critical";
        case ErrorLevel::Fatal: return "Fatal";
    }
    return "Unknown";
}

QString ErrorHandler::getErrorCategoryName(ErrorCategory category) {
    switch (category) {
        case ErrorCategory::FileSystem: return "File System";
        case ErrorCategory::Model: return "Model";
        case ErrorCategory::Build: return "Build";
        case ErrorCategory::Debug: return "Debug";
        case ErrorCategory::Execution: return "Execution";
        case ErrorCategory::Network: return "Network";
        case ErrorCategory::Configuration: return "Configuration";
        case ErrorCategory::Memory: return "Memory";
        case ErrorCategory::Unknown: return "Unknown";
    }
    return "Unknown";
}

void ErrorHandler::logErrorToFile(const ErrorInfo& error) {
    try {
        QString logPath = getErrorLogPath();
        QFile logFile(logPath);

        if (!logFile.open(QIODevice::Append | QIODevice::Text)) {
            qWarning() << "[ErrorHandler] Could not open error log file:" << logPath;
            return;
        }

        QTextStream stream(&logFile);
        stream << formatErrorForLog(error) << "\n\n";
        logFile.close();

        emit errorLogged(logPath);

    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error logging to file:" << e.what();
    }
}

QString ErrorHandler::getErrorLogPath() const {
    try {
        QString logDir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        QDir dir(logDir);
        if (!dir.exists()) {
            dir.mkpath(".");
        }
        return logDir + "/" + ERROR_LOG_FILENAME;
    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error getting log path:" << e.what();
        return "./rawrxd_errors.log";
    }
}

bool ErrorHandler::shouldExitAfterError(const ErrorInfo& error) const {
    return error.level == ErrorLevel::Fatal;
}

void ErrorHandler::initializeRecoveryActions() {
    try {
        // Default recovery actions
        registerRecoveryAction(ErrorCategory::Memory, {
            "Close other applications",
            []() { 
                QMessageBox::information(nullptr, "Memory Cleanup", 
                    "Please close other applications and retry.");
                return true; 
            },
            true
        });

        registerRecoveryAction(ErrorCategory::FileSystem, {
            "Retry",
            []() { return true; },
            true
        });

        qDebug() << "[ErrorHandler] Recovery actions initialized";

    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error initializing recovery actions:" << e.what();
    }
}

QString ErrorHandler::formatErrorForLog(const ErrorInfo& error) const {
    try {
        QString timestamp = QDateTime::fromMSecsSinceEpoch(error.timestamp)
            .toString("yyyy-MM-dd hh:mm:ss.zzz");

        QString logEntry;
        logEntry += QString("[%1] %2\n").arg(timestamp, getErrorLevelName(error.level));
        logEntry += QString("Category: %1\n").arg(getErrorCategoryName(error.category));
        logEntry += QString("Message: %1\n").arg(error.message);

        if (!error.details.isEmpty()) {
            logEntry += QString("Details: %1\n").arg(error.details);
        }

        if (!error.sourceFile.isEmpty()) {
            logEntry += QString("Source: %1:%2 in %3\n")
                .arg(error.sourceFile, QString::number(error.sourceLine), error.sourceFunction);
        }

        if (!error.stackTrace.isEmpty()) {
            logEntry += QString("Stack Trace:\n%1\n").arg(error.stackTrace);
        }

        return logEntry;

    } catch (const std::exception& e) {
        qWarning() << "[ErrorHandler] Error formatting log:" << e.what();
        return QString("Error: %1\n").arg(error.message);
    }
}

void ErrorHandler::reportError(const QString& message, const QString& levelOrDetails, ErrorLevel level) {
    handleErrorWithDetails(message, levelOrDetails, level, ErrorCategory::Unknown);
}
