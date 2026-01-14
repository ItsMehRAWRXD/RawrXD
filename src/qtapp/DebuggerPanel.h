#ifndef DEBUGGERPANEL_H
#define DEBUGGERPANEL_H

#include <QWidget>
#include <QTreeWidget>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QToolBar>
#include <QAction>
#include <QTabWidget>

struct DebugVariable {
    QString name;
    QString value;
    QString type;
    bool expanded;
    QVector<DebugVariable> children;
};

struct DebugStackFrame {
    QString function;
    QString file;
    int line;
    uintptr_t address;
};

class DebuggerPanel : public QWidget {
    Q_OBJECT

public:
    explicit DebuggerPanel(QWidget* parent = nullptr);
    ~DebuggerPanel() override = default;

    void updateVariables(const QVector<DebugVariable>& variables);
    void updateCallStack(const QVector<DebugStackFrame>& stack);
    void setStatus(const QString& status);
    void setPaused(bool paused);

signals:
    void continueRequested();
    void stepOverRequested();
    void stepIntoRequested();
    void stepOutRequested();
    void stopRequested();
    void breakpointToggled(const QString& file, int line);
    void variableChanged(const QString& name, const QString& newValue);

private slots:
    void onVariablesItemExpanded(QTreeWidgetItem* item);

private:
    void setupUI();
    void populateVariables(QTreeWidgetItem* parent, const QVector<DebugVariable>& variables);

    QTabWidget* m_tabWidget;
    QTreeWidget* m_variablesTree;
    QListWidget* m_callStackList;
    QListWidget* m_breakpointsList;
    QTreeWidget* m_watchList;
    
    QLabel* m_statusLabel;
    QToolBar* m_toolBar;
    
    QAction* m_continueAction;
    QAction* m_stepOverAction;
    QAction* m_stepIntoAction;
    QAction* m_stepOutAction;
    QAction* m_stopAction;
    
    bool m_isPaused;
};

#endif // DEBUGGERPANEL_H
