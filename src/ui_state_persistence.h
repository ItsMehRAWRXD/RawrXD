#ifndef UI_STATE_PERSISTENCE_H
#define UI_STATE_PERSISTENCE_H

#include <QObject>
#include <QString>
#include <QSettings>
#include <QMainWindow>
#include <QDockWidget>
#include <QTabWidget>
#include <QSplitter>
#include <QList>
#include <QHash>

namespace RawrXD {

struct UIState {
    QByteArray windowGeometry;
    QByteArray windowState;
    QHash<QString, QByteArray> dockStates;
    QHash<QString, QByteArray> splitterStates;
    QHash<QString, QVariant> tabStates;
    QHash<QString, QVariant> widgetStates;
    QList<QString> recentFiles;
    int maxRecentFiles;
    
    UIState() : maxRecentFiles(20) {}
};

class UIStatePersistence : public QObject {
    Q_OBJECT

public:
    static UIStatePersistence& instance();
    
    void initialize(QMainWindow* mainWindow, const QString& configFile = QString());
    void shutdown();
    
    // State management
    bool saveState();
    bool loadState();
    void setAutoSave(bool enable);
    
    // Window state
    void saveWindowState();
    bool restoreWindowState();
    
    // Dock widgets
    void registerDockWidget(const QString& name, QDockWidget* dock);
    void saveDockState(const QString& name);
    bool restoreDockState(const QString& name);
    
    // Splitters
    void registerSplitter(const QString& name, QSplitter* splitter);
    void saveSplitterState(const QString& name);
    bool restoreSplitterState(const QString& name);
    
    // Tab widgets
    void registerTabWidget(const QString& name, QTabWidget* tabs);
    void saveTabState(const QString& name);
    bool restoreTabState(const QString& name);
    
    // Recent files
    void addRecentFile(const QString& filePath);
    QList<QString> getRecentFiles() const;
    void clearRecentFiles();
    void setMaxRecentFiles(int max);
    
    // Custom widget states
    void saveWidgetState(const QString& name, const QVariant& state);
    QVariant getWidgetState(const QString& name, const QVariant& defaultValue = QVariant()) const;
    
    // Backup and restore
    bool createBackup(const QString& backupPath = QString());
    bool restoreFromBackup(const QString& backupPath);
    
private:
    UIStatePersistence() = default;
    ~UIStatePersistence();
    
    QString getConfigFilePath() const;
    void loadRecentFiles();
    void saveRecentFiles();
    
    QMainWindow* mainWindow_ = nullptr;
    QSettings* settings_ = nullptr;
    UIState currentState_;
    
    QHash<QString, QDockWidget*> dockWidgets_;
    QHash<QString, QSplitter*> splitters_;
    QHash<QString, QTabWidget*> tabWidgets_;
    
    bool autoSave_ = true;
    bool initialized_ = false;
    QString configFile_;
};

// Convenience macros
#define UI_SAVE_STATE() RawrXD::UIStatePersistence::instance().saveState()
#define UI_LOAD_STATE() RawrXD::UIStatePersistence::instance().loadState()
#define UI_ADD_RECENT(file) RawrXD::UIStatePersistence::instance().addRecentFile(file)
#define UI_GET_RECENT() RawrXD::UIStatePersistence::instance().getRecentFiles()

} // namespace RawrXD

#endif // UI_STATE_PERSISTENCE_H