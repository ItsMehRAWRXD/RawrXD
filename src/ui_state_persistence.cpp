#include "ui_state_persistence.h"
#include "logging/structured_logger.h"
#include "error_handler.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>

namespace RawrXD {

UIStatePersistence& UIStatePersistence::instance() {
    static UIStatePersistence instance;
    return instance;
}

void UIStatePersistence::initialize(QMainWindow* mainWindow, const QString& configFile) {
    if (initialized_) {
        return;
    }
    
    mainWindow_ = mainWindow;
    configFile_ = configFile.isEmpty() ? getConfigFilePath() : configFile;
    
    // Initialize settings
    settings_ = new QSettings(configFile_, QSettings::IniFormat);
    
    // Load recent files
    loadRecentFiles();
    
    // Connect to window close event for auto-save
    if (mainWindow_) {
        QObject::connect(mainWindow_, &QMainWindow::destroyed, this, [this]() {
            if (autoSave_) {
                saveState();
            }
        });
    }
    
    initialized_ = true;
    
    LOG_INFO("UI state persistence initialized", {{"config_file", configFile_}});
}

void UIStatePersistence::shutdown() {
    if (initialized_) {
        if (autoSave_) {
            saveState();
        }
        
        delete settings_;
        settings_ = nullptr;
        mainWindow_ = nullptr;
        initialized_ = false;
        
        LOG_INFO("UI state persistence shut down");
    }
}

bool UIStatePersistence::saveState() {
    if (!initialized_ || !mainWindow_) {
        return false;
    }
    
    try {
        // Save window state
        saveWindowState();
        
        // Save dock states
        for (auto it = dockWidgets_.begin(); it != dockWidgets_.end(); ++it) {
            saveDockState(it.key());
        }
        
        // Save splitter states
        for (auto it = splitters_.begin(); it != splitters_.end(); ++it) {
            saveSplitterState(it.key());
        }
        
        // Save tab states
        for (auto it = tabWidgets_.begin(); it != tabWidgets_.end(); ++it) {
            saveTabState(it.key());
        }
        
        // Save recent files
        saveRecentFiles();
        
        // Save widget states
        for (auto it = currentState_.widgetStates.begin(); it != currentState_.widgetStates.end(); ++it) {
            settings_->setValue("widgets/" + it.key(), it.value());
        }
        
        settings_->sync();
        
        LOG_INFO("UI state saved successfully");
        return true;
        
    } catch (const std::exception& e) {
        ERROR_EXCEPTION(e, ErrorContext()
            .setSeverity(ErrorSeverity::MEDIUM)
            .setCategory(ErrorCategory::FILE_SYSTEM)
            .setOperation("UIStatePersistence saveState"));
        return false;
    }
}

bool UIStatePersistence::loadState() {
    if (!initialized_ || !mainWindow_) {
        return false;
    }
    
    try {
        // Load window state
        if (!restoreWindowState()) {
            LOG_WARN("Failed to restore window state");
        }
        
        // Load dock states
        for (auto it = dockWidgets_.begin(); it != dockWidgets_.end(); ++it) {
            if (!restoreDockState(it.key())) {
                LOG_WARN("Failed to restore dock state", {{"dock", it.key()}});
            }
        }
        
        // Load splitter states
        for (auto it = splitters_.begin(); it != splitters_.end(); ++it) {
            if (!restoreSplitterState(it.key())) {
                LOG_WARN("Failed to restore splitter state", {{"splitter", it.key()}});
            }
        }
        
        // Load tab states
        for (auto it = tabWidgets_.begin(); it != tabWidgets_.end(); ++it) {
            if (!restoreTabState(it.key())) {
                LOG_WARN("Failed to restore tab state", {{"tab", it.key()}});
            }
        }
        
        // Load recent files
        loadRecentFiles();
        
        // Load widget states
        settings_->beginGroup("widgets");
        QStringList keys = settings_->allKeys();
        for (const QString& key : keys) {
            currentState_.widgetStates[key] = settings_->value(key);
        }
        settings_->endGroup();
        
        LOG_INFO("UI state loaded successfully");
        return true;
        
    } catch (const std::exception& e) {
        ERROR_EXCEPTION(e, ErrorContext()
            .setSeverity(ErrorSeverity::MEDIUM)
            .setCategory(ErrorCategory::FILE_SYSTEM)
            .setOperation("UIStatePersistence loadState"));
        return false;
    }
}

void UIStatePersistence::setAutoSave(bool enable) {
    autoSave_ = enable;
    LOG_DEBUG("Auto-save", {{"enabled", enable}});
}

void UIStatePersistence::saveWindowState() {
    if (!mainWindow_) return;
    
    currentState_.windowGeometry = mainWindow_->saveGeometry();
    currentState_.windowState = mainWindow_->saveState();
    
    settings_->setValue("window/geometry", currentState_.windowGeometry);
    settings_->setValue("window/state", currentState_.windowState);
    
    LOG_DEBUG("Window state saved");
}

bool UIStatePersistence::restoreWindowState() {
    if (!mainWindow_) return false;
    
    QByteArray geometry = settings_->value("window/geometry").toByteArray();
    QByteArray state = settings_->value("window/state").toByteArray();
    
    if (!geometry.isEmpty()) {
        mainWindow_->restoreGeometry(geometry);
    }
    
    if (!state.isEmpty()) {
        mainWindow_->restoreState(state);
    }
    
    LOG_DEBUG("Window state restored");
    return true;
}

void UIStatePersistence::registerDockWidget(const QString& name, QDockWidget* dock) {
    dockWidgets_[name] = dock;
    LOG_DEBUG("Dock widget registered", {{"name", name}});
}

void UIStatePersistence::saveDockState(const QString& name) {
    if (!dockWidgets_.contains(name)) {
        LOG_WARN("Dock widget not registered", {{"name", name}});
        return;
    }
    
    QDockWidget* dock = dockWidgets_[name];
    currentState_.dockStates[name] = dock->saveGeometry();
    settings_->setValue("docks/" + name, currentState_.dockStates[name]);
    
    LOG_DEBUG("Dock state saved", {{"dock", name}});
}

bool UIStatePersistence::restoreDockState(const QString& name) {
    if (!dockWidgets_.contains(name)) {
        LOG_WARN("Dock widget not registered", {{"name", name}});
        return false;
    }
    
    QDockWidget* dock = dockWidgets_[name];
    QByteArray state = settings_->value("docks/" + name).toByteArray();
    
    if (!state.isEmpty()) {
        dock->restoreGeometry(state);
        LOG_DEBUG("Dock state restored", {{"dock", name}});
        return true;
    }
    
    return false;
}

void UIStatePersistence::registerSplitter(const QString& name, QSplitter* splitter) {
    splitters_[name] = splitter;
    LOG_DEBUG("Splitter registered", {{"name", name}});
}

void UIStatePersistence::saveSplitterState(const QString& name) {
    if (!splitters_.contains(name)) {
        LOG_WARN("Splitter not registered", {{"name", name}});
        return;
    }
    
    QSplitter* splitter = splitters_[name];
    currentState_.splitterStates[name] = splitter->saveState();
    settings_->setValue("splitters/" + name, currentState_.splitterStates[name]);
    
    LOG_DEBUG("Splitter state saved", {{"splitter", name}});
}

bool UIStatePersistence::restoreSplitterState(const QString& name) {
    if (!splitters_.contains(name)) {
        LOG_WARN("Splitter not registered", {{"name", name}});
        return false;
    }
    
    QSplitter* splitter = splitters_[name];
    QByteArray state = settings_->value("splitters/" + name).toByteArray();
    
    if (!state.isEmpty()) {
        splitter->restoreState(state);
        LOG_DEBUG("Splitter state restored", {{"splitter", name}});
        return true;
    }
    
    return false;
}

void UIStatePersistence::registerTabWidget(const QString& name, QTabWidget* tabs) {
    tabWidgets_[name] = tabs;
    LOG_DEBUG("Tab widget registered", {{"name", name}});
}

void UIStatePersistence::saveTabState(const QString& name) {
    if (!tabWidgets_.contains(name)) {
        LOG_WARN("Tab widget not registered", {{"name", name}});
        return;
    }
    
    QTabWidget* tabs = tabWidgets_[name];
    currentState_.tabStates[name] = tabs->currentIndex();
    settings_->setValue("tabs/" + name, currentState_.tabStates[name]);
    
    LOG_DEBUG("Tab state saved", {{"tab", name}});
}

bool UIStatePersistence::restoreTabState(const QString& name) {
    if (!tabWidgets_.contains(name)) {
        LOG_WARN("Tab widget not registered", {{"name", name}});
        return false;
    }
    
    QTabWidget* tabs = tabWidgets_[name];
    int index = settings_->value("tabs/" + name, -1).toInt();
    
    if (index >= 0 && index < tabs->count()) {
        tabs->setCurrentIndex(index);
        LOG_DEBUG("Tab state restored", {{"tab", name}, {"index", index}});
        return true;
    }
    
    return false;
}

void UIStatePersistence::addRecentFile(const QString& filePath) {
    if (filePath.isEmpty() || !QFile::exists(filePath)) {
        return;
    }
    
    // Remove if already in list
    currentState_.recentFiles.removeAll(filePath);
    
    // Add to front
    currentState_.recentFiles.prepend(filePath);
    
    // Trim to max size
    while (currentState_.recentFiles.size() > currentState_.maxRecentFiles) {
        currentState_.recentFiles.removeLast();
    }
    
    LOG_DEBUG("Recent file added", {{"file", filePath}});
}

QList<QString> UIStatePersistence::getRecentFiles() const {
    return currentState_.recentFiles;
}

void UIStatePersistence::clearRecentFiles() {
    currentState_.recentFiles.clear();
    LOG_DEBUG("Recent files cleared");
}

void UIStatePersistence::setMaxRecentFiles(int max) {
    currentState_.maxRecentFiles = max;
    
    // Trim if necessary
    while (currentState_.recentFiles.size() > max) {
        currentState_.recentFiles.removeLast();
    }
    
    LOG_DEBUG("Max recent files set", {{"max", max}});
}

void UIStatePersistence::saveWidgetState(const QString& name, const QVariant& state) {
    currentState_.widgetStates[name] = state;
    settings_->setValue("widgets/" + name, state);
    LOG_DEBUG("Widget state saved", {{"widget", name}});
}

QVariant UIStatePersistence::getWidgetState(const QString& name, const QVariant& defaultValue) const {
    return currentState_.widgetStates.value(name, defaultValue);
}

bool UIStatePersistence::createBackup(const QString& backupPath) {
    QString actualPath = backupPath.isEmpty() ? 
        QDir::tempPath() + "/rawrxd_ui_backup_" + QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss") + ".ini" :
        backupPath;
    
    QFile sourceFile(configFile_);
    if (!sourceFile.exists()) {
        LOG_WARN("No config file to backup", {{"config_file", configFile_}});
        return false;
    }
    
    if (!sourceFile.copy(actualPath)) {
        ERROR_HANDLE("Failed to create UI state backup", ErrorContext()
            .setSeverity(ErrorSeverity::MEDIUM)
            .setCategory(ErrorCategory::FILE_SYSTEM)
            .setOperation("UIStatePersistence createBackup")
            .addMetadata("backup_path", actualPath));
        return false;
    }
    
    LOG_INFO("UI state backup created", {{"backup_path", actualPath}});
    return true;
}

bool UIStatePersistence::restoreFromBackup(const QString& backupPath) {
    if (!QFile::exists(backupPath)) {
        LOG_WARN("Backup file not found", {{"backup_path", backupPath}});
        return false;
    }
    
    // Create backup of current config
    QString currentBackup = QDir::tempPath() + "/rawrxd_ui_current_" + QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss") + ".ini";
    if (QFile::exists(configFile_)) {
        QFile::copy(configFile_, currentBackup);
    }
    
    // Restore from backup
    if (!QFile::copy(backupPath, configFile_)) {
        ERROR_HANDLE("Failed to restore UI state from backup", ErrorContext()
            .setSeverity(ErrorSeverity::MEDIUM)
            .setCategory(ErrorCategory::FILE_SYSTEM)
            .setOperation("UIStatePersistence restoreFromBackup")
            .addMetadata("backup_path", backupPath));
        return false;
    }
    
    // Reload settings
    delete settings_;
    settings_ = new QSettings(configFile_, QSettings::IniFormat);
    
    // Reload state
    loadState();
    
    LOG_INFO("UI state restored from backup", {{"backup_path", backupPath}});
    return true;
}

QString UIStatePersistence::getConfigFilePath() const {
    QDir appDir(QCoreApplication::applicationDirPath());
    return appDir.filePath("ui_state.ini");
}

void UIStatePersistence::loadRecentFiles() {
    int count = settings_->value("recent/files_count", 0).toInt();
    currentState_.recentFiles.clear();
    
    for (int i = 0; i < count; ++i) {
        QString filePath = settings_->value(QString("recent/file_%1").arg(i)).toString();
        if (QFile::exists(filePath)) {
            currentState_.recentFiles.append(filePath);
        }
    }
    
    LOG_DEBUG("Recent files loaded", {{"count", currentState_.recentFiles.size()}});
}

void UIStatePersistence::saveRecentFiles() {
    settings_->setValue("recent/files_count", currentState_.recentFiles.size());
    
    for (int i = 0; i < currentState_.recentFiles.size(); ++i) {
        settings_->setValue(QString("recent/file_%1").arg(i), currentState_.recentFiles[i]);
    }
    
    LOG_DEBUG("Recent files saved", {{"count", currentState_.recentFiles.size()}});
}

UIStatePersistence::~UIStatePersistence() {
    shutdown();
}

} // namespace RawrXD
