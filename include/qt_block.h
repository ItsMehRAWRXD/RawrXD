/**
 * @file qt_block.h
 * @brief QT compatibility layer — maps Qt API to native C++/Win32 implementations
 *
 * Provides drop-in replacements for Qt classes that were previously no-op
 * stubs. All implementations use Windows API + C++17 standard library only.
 * Zero external dependencies beyond nlohmann/json (already in project).
 *
 * Usage: #include "qt_block.h" instead of Qt headers
 */

#pragma once

#include "core/qt_elimination.h"

// ============================================================================
// Type aliases — map Qt type names to native implementations
// ============================================================================

using QString = std::string;
using QStringList = std::vector<std::string>;
using QJsonObject = nlohmann::json;
using QJsonArray = nlohmann::json;
using QJsonValue = nlohmann::json;
using QJsonDocument = NativeJson;
using QVariant = nlohmann::json;
using QMap = std::map;
using QVector = std::vector;

// ============================================================================
// NativeObject — Base class replacing QObject with working connect/emit
// Replaces QObject::connect() which was silently ignoring connections
// ============================================================================

class NativeObject {
public:
    NativeObject() = default;
    virtual ~NativeObject() = default;

    // Connect a signal to a slot (std::function callback)
    // Returns a connection ID that can be used to disconnect
    size_t connect(const std::string& signalName, std::function<void()> slot) {
        return m_signalSlot.connect(signalName, std::move(slot));
    }

    template<typename... Args>
    size_t connect(const std::string& signalName, std::function<void(Args...)> slot) {
        // Wrap typed slot into void() for storage
        return m_signalSlot.connect(signalName, [slot = std::move(slot)]() mutable {
            // This is a simplified version; typed args would need a more
            // sophisticated slot storage system. For now, void() slots work.
            slot();
        });
    }

    // Emit a signal, invoking all connected slots
    void emit(const std::string& signalName) {
        m_signalSlot.emit(signalName);
    }

    // Disconnect all slots for a signal
    void disconnect(const std::string& signalName) {
        m_signalSlot.disconnect(signalName);
    }

    // Check if any slots are connected
    bool hasConnections(const std::string& signalName) const {
        return m_signalSlot.hasConnections(signalName);
    }

protected:
    NativeSignalSlot m_signalSlot;
};

// ============================================================================
// NativeTimer — Real timer (replaces QTimer)
// Replaces QTimer which was a detached worker capturing 'this', never firing
// ============================================================================

using QTimer = NativeTimer;

// ============================================================================
// NativeProcess — Real process execution (replaces QProcess)
// Replaces QProcess which never launched a process
// ============================================================================

using QProcess = NativeProcess;
using QProcessExitStatus = int;

// ============================================================================
// NativeSettings — Persistent disk-backed settings (replaces QSettings)
// Replaces QSettings which stored preferences only in memory
// ============================================================================

using QSettings = NativeSettings;

// ============================================================================
// NativeWidget — Real Win32 controls (replaces QWidget)
// Replaces QWidget methods which silently did nothing
// ============================================================================

using QWidget = NativeWidget;

// ============================================================================
// Helper functions for QString compatibility
// ============================================================================

inline QString toUtf8(const std::wstring& wstr) {
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string str(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], len, nullptr, nullptr);
    return str;
}

inline std::wstring fromUtf8(const QString& str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring wstr(len, '\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], len);
    return wstr;
}

// ============================================================================
// Logging replacement for QDebug
// ============================================================================

inline void qDebug(const std::string& msg) {
    std::cout << "[DEBUG] " << msg << std::endl;
}

inline void qWarning(const std::string& msg) {
    std::cerr << "[WARN] " << msg << std::endl;
}

inline void qCritical(const std::string& msg) {
    std::cerr << "[CRITICAL] " << msg << std::endl;
}

inline void qInfo(const std::string& msg) {
    std::cout << "[INFO] " << msg << std::endl;
}
