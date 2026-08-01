=====================================================================
// ExtensionMarketplaceManager — C++20, no Qt. VS Code extension marketplace.
// ============================================================================

#include <functional>
#include <string>
#include <vector>

class VsixInstaller;
class EnterprisePolicyEngine;
class OfflineCacheStore;

/**
 * Manages: search/browse, extension metadata, install/update/uninstall,
 * enterprise policy, offline cache.
 */
class ExtensionMarketplaceManager {
public:
    ExtensionMarketplaceManager() = default;
    ~ExtensionMarketplaceManager();

    void searchExtensions(const std::string& query, int page = 1, int pageSize = 20);
    void getFeaturedExtensions(int page = 1, int pageSize = 20);
    void getCategoryExtensions(const std::string& category, int page = 1, int pageSize = 20);
    void getExtensionDetails(const std::string& extensionId);

    void installExtension(const std::string& extensionId, const std::string& version = "");
    void updateExtension(const std::string& extensionId);
    void uninstallExtension(const std::string& extensionId);
    void listInstalledExtensions();

    void setEnterprisePolicyEngine(EnterprisePolicyEngine* policyEngine);
    void enableOfflineMode(bool enabled);
    void syncWithPrivateMarketplace(const std::string& url);

    void clearCache();
    void preloadExtensions(const std::vector<std::string>& extensionIds);

    using SearchResultsFn = std::function<void(const std::string& extensionsJson)>;
    using ExtensionDetailsFn = std::function<void(const std::string& extensionJson)>;
    using StartedFn = std::function<void(const std::string& extensionId)>;
    using CompletedFn = std::function<void(const std::string& extensionId, bool success)>;
    using ErrorFn = std::function<void(const std::string& extensionId, const std::string& error)>;
    using UpdateAvailableFn = std::function<void(const std::string& extensionId, const std::string& version)>;
    using ErrorMessageFn = std::function<void(const std::string& error)>;

    void setOnSearchResultsReceived(SearchResultsFn fn) { m_onSearchResults = std::move(fn); }
    void setOnExtensionDetailsReceived(ExtensionDetailsFn fn) { m_onExtensionDetails = std::move(fn); }
    void setOnInstallationStarted(StartedFn fn) { m_onInstallationStarted = std::move(fn); }
    void setOnInstallationCompleted(CompletedFn fn) { m_onInstallationCompleted = std::move(fn); }
    void setOnInstallationError(ErrorFn fn) { m_onInstallationError = std::move(fn); }
    void setOnUpdateAvailable(UpdateAvailableFn fn) { m_onUpdateAvailable = std::move(fn); }
    void setOnUninstallCompleted(CompletedFn fn) { m_onUninstallCompleted = std::move(fn); }
    void setOnInstalledExtensionsList(SearchResultsFn fn) { m_onInstalledExtensionsList = std::move(fn); }
    void setOnCacheCleared(std::function<void()> fn) { m_onCacheCleared = std::move(fn); }
    void setOnErrorOccurred(ErrorMessageFn fn) { m_onErrorOccurred = std::move(fn); }

private:
    struct ExtensionInfo {
        std::string id;
        std::string name;
        std::string version;
        std::string publisher;
        std::string description;
        std::string iconUrl;
        int64_t downloadCount = 0;
        double rating = 0.0;
        std::vector<std::string> categories;
        int64_t lastUpdated = 0;
        bool installed = false;
        std::string installedVersion;
    };

    void onSearchReplyFinished();
    void onExtensionDetailsReplyFinished();
    void onInstallReplyFinished();
    void onUpdateCheckReplyFinished();

    void* m_networkManager = nullptr;
    VsixInstaller* m_vsixInstaller = nullptr;
    EnterprisePolicyEngine* m_policyEngine = nullptr;
    OfflineCacheStore* m_cacheStore = nullptr;

    std::vector<ExtensionInfo> m_installedExtensions;
    bool m_offlineMode = false;
    std::string m_privateMarketplaceUrl;
    void* m_updateCheckTimer = nullptr;  // Win32 timer or poll

    void parseSearchResults(void* reply);
    void parseExtensionDetails(void* reply);
    std::string getExtensionDownloadUrl(const std::string& extensionId, const std::string& version);
    bool isExtensionAllowed(const std::string& extensionId);
    void saveInstalledExtensions();
    void loadInstalledExtensions();
    void checkForUpdates();

    SearchResultsFn m_onSearchResults;
    ExtensionDetailsFn m_onExtensionDetails;
    StartedFn m_onInstallationStarted;
    CompletedFn m_onInstallationCompleted;
    ErrorFn m_onInstallationError;
    UpdateAvailableFn m_onUpdateAvailable;
    CompletedFn m_onUninstallCompleted;
    SearchResultsFn m_onInstalledExtensionsList;
    std::function<void()> m_onCacheCleared;
    ErrorMessageFn m_onErrorOccurred;
};
=======
#pragma once

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QList>
#include <QTimer>

// Forward declarations
class VsixInstaller;
class EnterprisePolicyEngine;
class OfflineCacheStore;

/**
 * @class ExtensionMarketplaceManager
 * @brief Manages VS Code extension marketplace operations
 * 
 * This class handles:
 * - Searching and browsing extensions
 * - Fetching extension metadata
 * - Installing/updating/uninstalling extensions
 * - Managing extension lifecycle
 * - Enterprise policy enforcement
 * - Offline cache management
 */
class ExtensionMarketplaceManager : public QObject {
    Q_OBJECT

public:
    explicit ExtensionMarketplaceManager(QObject* parent = nullptr);
    ~ExtensionMarketplaceManager();

    // Marketplace search and browse
    void searchExtensions(const QString& query, int page = 1, int pageSize = 20);
    void getFeaturedExtensions(int page = 1, int pageSize = 20);
    void getCategoryExtensions(const QString& category, int page = 1, int pageSize = 20);
    void getExtensionDetails(const QString& extensionId);

    // Extension lifecycle management
    void installExtension(const QString& extensionId, const QString& version = QString());
    void updateExtension(const QString& extensionId);
    void uninstallExtension(const QString& extensionId);
    void listInstalledExtensions();

    // Enterprise features
    void setEnterprisePolicyEngine(EnterprisePolicyEngine* policyEngine);
    void enableOfflineMode(bool enabled);
    void syncWithPrivateMarketplace(const QString& url);

    // Cache management
    void clearCache();
    void preloadExtensions(const QStringList& extensionIds);

signals:
    void searchResultsReceived(const QJsonArray& extensions);
    void extensionDetailsReceived(const QJsonObject& extension);
    void installationStarted(const QString& extensionId);
    void installationCompleted(const QString& extensionId, bool success);
    void installationError(const QString& extensionId, const QString& error);
    void updateAvailable(const QString& extensionId, const QString& version);
    void uninstallCompleted(const QString& extensionId, bool success);
    void installedExtensionsList(const QJsonArray& extensions);
    void cacheCleared();
    void errorOccurred(const QString& error);

private slots:
    void onSearchReplyFinished();
    void onExtensionDetailsReplyFinished();
    void onInstallReplyFinished();
    void onUpdateCheckReplyFinished();

private:
    struct ExtensionInfo {
        QString id;
        QString name;
        QString version;
        QString publisher;
        QString description;
        QString iconUrl;
        qint64 downloadCount;
        double rating;
        QStringList categories;
        QDateTime lastUpdated;
        bool installed;
        QString installedVersion;
    };

    QNetworkAccessManager* m_networkManager;
    VsixInstaller* m_vsixInstaller;
    EnterprisePolicyEngine* m_policyEngine;
    OfflineCacheStore* m_cacheStore;
    
    QList<ExtensionInfo> m_installedExtensions;
    bool m_offlineMode;
    QString m_privateMarketplaceUrl;
    QTimer* m_updateCheckTimer;

    void parseSearchResults(QNetworkReply* reply);
    void parseExtensionDetails(QNetworkReply* reply);
    QString getExtensionDownloadUrl(const QString& extensionId, const QString& version);
    bool isExtensionAllowed(const QString& extensionId);
    void saveInstalledExtensions();
    void loadInstalledExtensions();
    void checkForUpdates();
};

