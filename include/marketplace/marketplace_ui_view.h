<<<<<<< HEAD
#pragma once

// ============================================================================
// MarketplaceUIView — C++20, Win32. No Qt. Extension marketplace UI.
// ============================================================================

#include <map>
#include <string>

class ExtensionMarketplaceManager;
class EnterprisePolicyEngine;

/**
 * UI for extension marketplace: search, details, install/uninstall,
 * enterprise policy, offline cache. Use void* for Win32 controls.
 */
class MarketplaceUIView {
public:
    explicit MarketplaceUIView(void* parent = nullptr);
    ~MarketplaceUIView();

    void setMarketplaceManager(ExtensionMarketplaceManager* manager);
    void setPolicyEngine(EnterprisePolicyEngine* engine);

    void onSearchClicked();
    void onInstallClicked();
    void onUninstallClicked();
    void onExtensionSelected();
    void onSearchResultsReceived(const std::string& extensionsJson);
    void onExtensionDetailsReceived(const std::string& extensionJson);
    void onInstallationStarted(const std::string& extensionId);
    void onInstallationCompleted(const std::string& extensionId, bool success);
    void onInstallationError(const std::string& extensionId, const std::string& error);
    void onUpdateAvailable(const std::string& extensionId, const std::string& version);
    void onUninstallCompleted(const std::string& extensionId, bool success);
    void onInstalledExtensionsList(const std::string& extensionsJson);
    void onErrorOccurred(const std::string& error);
    void onCacheCleared();
    void onRefreshClicked();
    void onSettingsChanged();

private:
    void setupSearchTab();
    void setupDetailsTab();
    void setupInstalledTab();
    void setupSettingsTab();
    void setupConnections();
    void updateExtensionList(const std::string& extensionsJson);
    void showExtensionDetails(const std::string& extensionJson);
    void updateInstalledExtensionsList(const std::string& extensionsJson);
    void showError(const std::string& message);
    void showStatus(const std::string& message);
    void* createExtensionItemWidget(const std::string& extensionJson);
    void clearDetailsView();

    void* m_searchBox = nullptr;
    void* m_searchButton = nullptr;
    void* m_refreshButton = nullptr;
    void* m_tabWidget = nullptr;
    void* m_searchResultsList = nullptr;
    void* m_searchStatus = nullptr;
    void* m_extensionIcon = nullptr;
    void* m_extensionName = nullptr;
    void* m_extensionPublisher = nullptr;
    void* m_extensionVersion = nullptr;
    void* m_extensionRating = nullptr;
    void* m_extensionDownloads = nullptr;
    void* m_extensionDescription = nullptr;
    void* m_installButton = nullptr;
    void* m_uninstallButton = nullptr;
    void* m_installProgress = nullptr;
    void* m_installStatus = nullptr;
    void* m_installedExtensionsList = nullptr;
    void* m_uninstallSelectedButton = nullptr;
    void* m_offlineModeCheckBox = nullptr;
    void* m_privateMarketplaceUrl = nullptr;
    void* m_syncButton = nullptr;
    void* m_clearCacheButton = nullptr;
    void* m_cacheSizeLabel = nullptr;
    void* m_allowListEdit = nullptr;
    void* m_denyListEdit = nullptr;
    void* m_requireSignatureCheckBox = nullptr;

    ExtensionMarketplaceManager* m_marketplaceManager = nullptr;
    EnterprisePolicyEngine* m_policyEngine = nullptr;

    std::string m_selectedExtensionId;
    std::map<std::string, std::string> m_extensionCache;  // extensionId -> JSON
};
=======
#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>
#include <QTreeWidget>
#include <QLabel>
#include <QProgressBar>
#include <QTabWidget>
#include <QScrollArea>
#include <QFrame>
#include <QComboBox>
#include <QCheckBox>
#include <QTextEdit>

// Forward declarations
class ExtensionMarketplaceManager;
class EnterprisePolicyEngine;

/**
 * @class MarketplaceUIView
 * @brief UI widget for the VS Code extension marketplace
 * 
 * This class provides:
 * - Search and browse interface
 * - Extension details view
 * - Installation management
 * - Enterprise policy settings
 * - Offline cache management
 */
class MarketplaceUIView : public QWidget {
    Q_OBJECT

public:
    explicit MarketplaceUIView(QWidget* parent = nullptr);
    ~MarketplaceUIView();

    void setMarketplaceManager(ExtensionMarketplaceManager* manager);
    void setPolicyEngine(EnterprisePolicyEngine* engine);

protected:
    void resizeEvent(QResizeEvent* event) override;

private slots:
    void onSearchClicked();
    void onInstallClicked();
    void onUninstallClicked();
    void onExtensionSelected();
    void onSearchResultsReceived(const QJsonArray& extensions);
    void onExtensionDetailsReceived(const QJsonObject& extension);
    void onInstallationStarted(const QString& extensionId);
    void onInstallationCompleted(const QString& extensionId, bool success);
    void onInstallationError(const QString& extensionId, const QString& error);
    void onUpdateAvailable(const QString& extensionId, const QString& version);
    void onUninstallCompleted(const QString& extensionId, bool success);
    void onInstalledExtensionsList(const QJsonArray& extensions);
    void onErrorOccurred(const QString& error);
    void onCacheCleared();
    void onRefreshClicked();
    void onSettingsChanged();

private:
    // UI components
    QLineEdit* m_searchBox;
    QPushButton* m_searchButton;
    QPushButton* m_refreshButton;
    QTabWidget* m_tabWidget;
    
    // Search results tab
    QListWidget* m_searchResultsList;
    QLabel* m_searchStatus;
    
    // Extension details tab
    QLabel* m_extensionIcon;
    QLabel* m_extensionName;
    QLabel* m_extensionPublisher;
    QLabel* m_extensionVersion;
    QLabel* m_extensionRating;
    QLabel* m_extensionDownloads;
    QTextEdit* m_extensionDescription;
    QPushButton* m_installButton;
    QPushButton* m_uninstallButton;
    QProgressBar* m_installProgress;
    QLabel* m_installStatus;
    
    // Installed extensions tab
    QListWidget* m_installedExtensionsList;
    QPushButton* m_uninstallSelectedButton;
    
    // Settings tab
    QCheckBox* m_offlineModeCheckBox;
    QLineEdit* m_privateMarketplaceUrl;
    QPushButton* m_syncButton;
    QPushButton* m_clearCacheButton;
    QLabel* m_cacheSizeLabel;
    QTextEdit* m_allowListEdit;
    QTextEdit* m_denyListEdit;
    QCheckBox* m_requireSignatureCheckBox;
    
    // Backend components
    ExtensionMarketplaceManager* m_marketplaceManager;
    EnterprisePolicyEngine* m_policyEngine;
    
    // State tracking
    QString m_selectedExtensionId;
    QHash<QString, QJsonObject> m_extensionCache;
    
    // UI setup methods
    void setupSearchTab();
    void setupDetailsTab();
    void setupInstalledTab();
    void setupSettingsTab();
    void setupConnections();
    
    // Helper methods
    void updateExtensionList(const QJsonArray& extensions);
    void showExtensionDetails(const QJsonObject& extension);
    void updateInstalledExtensionsList(const QJsonArray& extensions);
    void showError(const QString& message);
    void showStatus(const QString& message);
    QWidget* createExtensionItemWidget(const QJsonObject& extension);
    void clearDetailsView();
};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
