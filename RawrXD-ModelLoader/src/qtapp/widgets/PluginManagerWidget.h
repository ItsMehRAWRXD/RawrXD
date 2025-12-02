#ifndef PLUGINMANAGERWIDGET_H
#define PLUGINMANAGERWIDGET_H

#include <QWidget>
#include <QJsonObject>
#include <QVector>
#include <QPointer>

class QTableWidget;
class QLabel;
class QPushButton;
class QLineEdit;
class QProcess;

struct PluginMetadata {
    QString id;           // e.g. "rust-analyzer-helper"
    QString name;         // Display name
    QString version;      // Semver
    QString author;
    QString description;
    QString entrypoint;   // Python: main.py, QML: plugin.qml
    QString type;         // "python" | "qml" | "javascript"
    QJsonObject manifest; // Full plugin.json
    bool enabled = false;
    bool loaded = false;
};

class PluginManagerWidget : public QWidget
{
    Q_OBJECT

public:
    explicit PluginManagerWidget(QWidget* parent = nullptr);
    ~PluginManagerWidget() override;

    void loadInstalledPlugins();
    void discoverMarketplace();
    
signals:
    void pluginEnabled(const QString& id);
    void pluginDisabled(const QString& id);
    void pluginInstalled(const QString& id);
    void pluginUninstalled(const QString& id);
    void logMessage(const QString& msg);

private slots:
    void refreshPluginList();
    void onEnableToggle(const QString& id);
    void onInstallPlugin();
    void onUninstallPlugin();
    void onSearchMarketplace();
    void onGitHubSearchFinished();

private:
    void setupUi();
    bool loadPluginManifest(const QString& path, PluginMetadata& meta);
    void loadPythonPlugin(const PluginMetadata& meta);
    void loadQMLPlugin(const PluginMetadata& meta);
    void unloadPlugin(const QString& id);
    QString getPluginsDir() const;
    
    QTableWidget* pluginTable_;
    QLineEdit* searchInput_;
    QPushButton* refreshBtn_;
    QPushButton* installBtn_;
    QPushButton* uninstallBtn_;
    QLabel* statusLabel_;
    
    QVector<PluginMetadata> plugins_;
    QPointer<QProcess> ghSearchProc_;
};

#endif // PLUGINMANAGERWIDGET_H
