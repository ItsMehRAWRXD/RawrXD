#include "PluginManagerWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QProcess>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStandardPaths>
#include <QMessageBox>
#include <QCheckBox>

PluginManagerWidget::PluginManagerWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
    loadInstalledPlugins();
}

PluginManagerWidget::~PluginManagerWidget() = default;

void PluginManagerWidget::setupUi()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Header
    QLabel* title = new QLabel(tr("🧩 Plugin Manager"), this);
    title->setStyleSheet("font-weight: bold; font-size: 14px;");
    
    // Search bar
    QHBoxLayout* searchLayout = new QHBoxLayout();
    searchInput_ = new QLineEdit(this);
    searchInput_->setPlaceholderText(tr("Search GitHub topic 'rawrxd-plugin'..."));
    QPushButton* searchBtn = new QPushButton(tr("🔍 Search"), this);
    connect(searchBtn, &QPushButton::clicked, this, &PluginManagerWidget::onSearchMarketplace);
    searchLayout->addWidget(searchInput_);
    searchLayout->addWidget(searchBtn);
    
    // Plugin table
    pluginTable_ = new QTableWidget(this);
    pluginTable_->setColumnCount(6);
    pluginTable_->setHorizontalHeaderLabels({tr("ID"), tr("Name"), tr("Version"), tr("Type"), tr("Enabled"), tr("Loaded")});
    pluginTable_->horizontalHeader()->setStretchLastSection(false);
    pluginTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    pluginTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    pluginTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    
    // Buttons
    QHBoxLayout* btnLayout = new QHBoxLayout();
    refreshBtn_ = new QPushButton(tr("🔄 Refresh"), this);
    installBtn_ = new QPushButton(tr("📥 Install Selected"), this);
    uninstallBtn_ = new QPushButton(tr("🗑️ Uninstall Selected"), this);
    
    connect(refreshBtn_, &QPushButton::clicked, this, &PluginManagerWidget::refreshPluginList);
    connect(installBtn_, &QPushButton::clicked, this, &PluginManagerWidget::onInstallPlugin);
    connect(uninstallBtn_, &QPushButton::clicked, this, &PluginManagerWidget::onUninstallPlugin);
    
    btnLayout->addWidget(refreshBtn_);
    btnLayout->addWidget(installBtn_);
    btnLayout->addWidget(uninstallBtn_);
    btnLayout->addStretch();
    
    // Status
    statusLabel_ = new QLabel(tr("Ready"), this);
    statusLabel_->setStyleSheet("color: #888; font-size: 11px;");
    
    mainLayout->addWidget(title);
    mainLayout->addLayout(searchLayout);
    mainLayout->addWidget(pluginTable_);
    mainLayout->addLayout(btnLayout);
    mainLayout->addWidget(statusLabel_);
}

QString PluginManagerWidget::getPluginsDir() const
{
    const QString appData = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return QDir(appData).filePath("plugins");
}

void PluginManagerWidget::loadInstalledPlugins()
{
    plugins_.clear();
    
    const QString pluginsDir = getPluginsDir();
    if (!QDir(pluginsDir).exists()) {
        QDir().mkpath(pluginsDir);
        emit logMessage(tr("Created plugins directory: %1").arg(pluginsDir));
    }
    
    const QFileInfoList dirs = QDir(pluginsDir).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QFileInfo& dir : dirs) {
        const QString manifestPath = QDir(dir.filePath()).filePath("plugin.json");
        if (!QFile::exists(manifestPath)) continue;
        
        PluginMetadata meta;
        if (loadPluginManifest(manifestPath, meta)) {
            plugins_.append(meta);
            emit logMessage(tr("Discovered plugin: %1 v%2").arg(meta.name, meta.version));
        }
    }
    
    refreshPluginList();
}

bool PluginManagerWidget::loadPluginManifest(const QString& path, PluginMetadata& meta)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return false;
    
    const QByteArray data = file.readAll();
    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) return false;
    
    const QJsonObject obj = doc.object();
    meta.id = obj.value("id").toString();
    meta.name = obj.value("name").toString();
    meta.version = obj.value("version").toString();
    meta.author = obj.value("author").toString();
    meta.description = obj.value("description").toString();
    meta.entrypoint = obj.value("entrypoint").toString();
    meta.type = obj.value("type").toString();
    meta.manifest = obj;
    
    return !meta.id.isEmpty() && !meta.name.isEmpty();
}

void PluginManagerWidget::refreshPluginList()
{
    pluginTable_->setRowCount(plugins_.size());
    
    for (int i = 0; i < plugins_.size(); ++i) {
        const PluginMetadata& p = plugins_[i];
        
        pluginTable_->setItem(i, 0, new QTableWidgetItem(p.id));
        pluginTable_->setItem(i, 1, new QTableWidgetItem(p.name));
        pluginTable_->setItem(i, 2, new QTableWidgetItem(p.version));
        pluginTable_->setItem(i, 3, new QTableWidgetItem(p.type));
        
        QCheckBox* enabledCheck = new QCheckBox();
        enabledCheck->setChecked(p.enabled);
        connect(enabledCheck, &QCheckBox::toggled, this, [this, id = p.id](bool checked) {
            if (checked) emit pluginEnabled(id);
            else emit pluginDisabled(id);
        });
        pluginTable_->setCellWidget(i, 4, enabledCheck);
        
        QLabel* loadedLabel = new QLabel(p.loaded ? tr("✓") : tr("–"));
        loadedLabel->setAlignment(Qt::AlignCenter);
        pluginTable_->setCellWidget(i, 5, loadedLabel);
    }
    
    statusLabel_->setText(tr("%1 plugin(s) installed").arg(plugins_.size()));
}

void PluginManagerWidget::onEnableToggle(const QString& id)
{
    for (PluginMetadata& p : plugins_) {
        if (p.id == id) {
            p.enabled = !p.enabled;
            if (p.enabled) {
                if (p.type == "python") loadPythonPlugin(p);
                else if (p.type == "qml") loadQMLPlugin(p);
                p.loaded = true;
            } else {
                unloadPlugin(id);
                p.loaded = false;
            }
            refreshPluginList();
            break;
        }
    }
}

void PluginManagerWidget::loadPythonPlugin(const PluginMetadata& meta)
{
    // TODO: pybind11 integration
    // For now, mock implementation
    emit logMessage(tr("[Python] Loading %1 from %2").arg(meta.name, meta.entrypoint));
    
    // Future: PyImport_ImportModule, IRawrAPI::registerCommand, etc.
    // Example:
    // py::module_ plugin = py::module_::import(meta.id.toStdString());
    // plugin.attr("activate")(IRawrAPI::instance());
}

void PluginManagerWidget::loadQMLPlugin(const PluginMetadata& meta)
{
    // TODO: QQmlComponent integration
    emit logMessage(tr("[QML] Loading %1 from %2").arg(meta.name, meta.entrypoint));
    
    // Future:
    // QQmlComponent comp(engine_, pluginPath);
    // QObject* obj = comp.create();
    // obj->setProperty("rawrApi", QVariant::fromValue(IRawrAPI::instance()));
}

void PluginManagerWidget::unloadPlugin(const QString& id)
{
    emit logMessage(tr("Unloading plugin: %1").arg(id));
    // TODO: Cleanup resources, deregister commands, disconnect signals
}

void PluginManagerWidget::onInstallPlugin()
{
    // TODO: Download from GitHub, extract, validate manifest
    QMessageBox::information(this, tr("Install Plugin"), tr("Marketplace installation not implemented yet."));
}

void PluginManagerWidget::onUninstallPlugin()
{
    const int row = pluginTable_->currentRow();
    if (row < 0 || row >= plugins_.size()) return;
    
    const PluginMetadata& meta = plugins_[row];
    const auto reply = QMessageBox::question(this, tr("Uninstall Plugin"),
                                             tr("Remove %1?").arg(meta.name));
    if (reply == QMessageBox::Yes) {
        const QString pluginDir = QDir(getPluginsDir()).filePath(meta.id);
        if (QDir(pluginDir).removeRecursively()) {
            emit logMessage(tr("Uninstalled %1").arg(meta.id));
            emit pluginUninstalled(meta.id);
            loadInstalledPlugins();
        }
    }
}

void PluginManagerWidget::onSearchMarketplace()
{
    const QString query = searchInput_->text().isEmpty() ? "rawrxd-plugin" : searchInput_->text();
    statusLabel_->setText(tr("Searching GitHub for '%1'...").arg(query));
    
    ghSearchProc_ = new QProcess(this);
    connect(ghSearchProc_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &PluginManagerWidget::onGitHubSearchFinished);
    
    // Use GitHub CLI (gh) if available, else fallback to API
    ghSearchProc_->start("gh", {"search", "repos", "--topic", query, "--json", "name,owner,description"});
}

void PluginManagerWidget::onGitHubSearchFinished()
{
    if (!ghSearchProc_) return;
    
    const QByteArray output = ghSearchProc_->readAllStandardOutput();
    const QJsonDocument doc = QJsonDocument::fromJson(output);
    
    if (doc.isArray()) {
        const QJsonArray arr = doc.array();
        statusLabel_->setText(tr("Found %1 plugin(s) on GitHub").arg(arr.size()));
        emit logMessage(tr("Marketplace search returned %1 results").arg(arr.size()));
        
        // TODO: Display results in table, add "Install" buttons
    } else {
        statusLabel_->setText(tr("Search failed (install GitHub CLI: gh)"));
    }
    
    ghSearchProc_->deleteLater();
    ghSearchProc_ = nullptr;
}

void PluginManagerWidget::discoverMarketplace()
{
    // Alias for search with default topic
    searchInput_->setText("rawrxd-plugin");
    onSearchMarketplace();
}
