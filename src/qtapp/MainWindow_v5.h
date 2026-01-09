#ifndef MAINWINDOW_V5_H
#define MAINWINDOW_V5_H

#include <QMainWindow>
#include <QTabWidget>
#include <QTreeWidget>
#include <QPlainTextEdit>

class AIDigestionPanel;
class AIChatPanel;

class MainWindow_v5 : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow_v5(QWidget* parent = nullptr);
    ~MainWindow_v5() override = default;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onNewFile();
    void onOpenFile();
    void onSaveFile();
    void toggleAIChatPanel();
    void toggleFileBrowser();
    void toggleTerminal();

private:
    void setupUI();
    void setupMenuBar();
    void setupToolBar();
    void setupStatusBar();
    void setupDockWidgets();
    void applyDarkTheme();
    void restoreWindowState();
    void saveWindowState();

private:
    QTabWidget* m_tabWidget = nullptr;
    AIDigestionPanel* m_digestionPanel = nullptr;
    AIChatPanel* m_aiChatPanel = nullptr;
    QPlainTextEdit* m_codeEditor = nullptr;
    QTreeWidget* m_fileBrowser = nullptr;
    QPlainTextEdit* m_terminal = nullptr;
};

#endif // MAINWINDOW_V5_H
