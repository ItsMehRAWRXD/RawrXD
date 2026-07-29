<<<<<<< HEAD
#pragma once

// ============================================================================
// VsixInstaller — C++20, no Qt. Handles installation of VSIX packages.
// ============================================================================

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

/**
 * Manages: downloading VSIX from URLs, extracting, installing to IDE.
 */
class VsixInstaller {
public:
    VsixInstaller() = default;
    ~VsixInstaller();

    void installFromUrl(const std::string& url, const std::string& extensionId);
    void installFromFile(const std::string& filePath);
    bool uninstallExtension(const std::string& extensionId);

    bool isExtensionInstalled(const std::string& extensionId);
    std::string getExtensionInstallPath(const std::string& extensionId);

    using StartedFn = std::function<void(const std::string& extensionId)>;
    using ProgressFn = std::function<void(const std::string& extensionId, int percentage)>;
    using CompletedFn = std::function<void(const std::string& extensionId, bool success)>;
    using ErrorFn = std::function<void(const std::string& extensionId, const std::string& error)>;

    void setOnInstallationStarted(StartedFn fn) { m_onStarted = std::move(fn); }
    void setOnInstallationProgress(ProgressFn fn) { m_onProgress = std::move(fn); }
    void setOnInstallationCompleted(CompletedFn fn) { m_onCompleted = std::move(fn); }
    void setOnInstallationError(ErrorFn fn) { m_onError = std::move(fn); }
    void setOnUninstallCompleted(CompletedFn fn) { m_onUninstallCompleted = std::move(fn); }

private:
    struct InstallationInfo {
        std::string extensionId;
        std::string downloadUrl;
        std::string tempFilePath;
        void* fileHandle = nullptr;  // FILE* or Win32 handle
    };

    void onDownloadFinished();
    void onDownloadProgress(int64_t bytesReceived, int64_t bytesTotal);

    void* m_networkContext = nullptr;
    std::vector<InstallationInfo> m_activeInstallations;

    bool extractVsixPackage(const std::string& vsixPath, const std::string& destination);
    bool activateExtension(const std::string& extensionPath);
    bool deactivateExtension(const std::string& extensionId);
    std::string getExtensionsDirectory();
    void cleanupTempFiles();

    StartedFn m_onStarted;
    ProgressFn m_onProgress;
    CompletedFn m_onCompleted;
    ErrorFn m_onError;
    CompletedFn m_onUninstallCompleted;
};
=======
#pragma once

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QFile>

/**
 * @class VsixInstaller
 * @brief Handles installation of VSIX packages
 * 
 * This class manages:
 * - Downloading VSIX files from URLs
 * - Extracting VSIX packages
 * - Installing extensions to the IDE
 * - Managing installation state
 */
class VsixInstaller : public QObject {
    Q_OBJECT

public:
    explicit VsixInstaller(QObject* parent = nullptr);
    ~VsixInstaller();

    // Installation methods
    void installFromUrl(const QString& url, const QString& extensionId);
    void installFromFile(const QString& filePath);
    bool uninstallExtension(const QString& extensionId);
    
    // Utility methods
    bool isExtensionInstalled(const QString& extensionId);
    QString getExtensionInstallPath(const QString& extensionId);

signals:
    void installationStarted(const QString& extensionId);
    void installationProgress(const QString& extensionId, int percentage);
    void installationCompleted(const QString& extensionId, bool success);
    void installationError(const QString& extensionId, const QString& error);
    void uninstallCompleted(const QString& extensionId, bool success);

private slots:
    void onDownloadFinished();
    void onDownloadProgress(qint64 bytesReceived, qint64 bytesTotal);

private:
    struct InstallationInfo {
        QString extensionId;
        QString downloadUrl;
        QString tempFilePath;
        QFile* file;
    };

    QNetworkAccessManager* m_networkManager;
    QList<InstallationInfo> m_activeInstallations;

    bool extractVsixPackage(const QString& vsixPath, const QString& destination);
    bool activateExtension(const QString& extensionPath);
    bool deactivateExtension(const QString& extensionId);
    QString getExtensionsDirectory();
    void cleanupTempFiles();
};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
