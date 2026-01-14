/**
 * @file TerminalClusterWidget.h
 * @brief Production implementation of TerminalClusterWidget
 * 
 * Replaces bespoke terminal panel with production-grade terminal components:
 * - Uses TerminalWidget/TerminalManager for shell management
 * - Provides PowerShell and CMD terminals in tabs
 * - Integrates AI "Fix" functionality
 * - Maintains VS Code-style interface
 * 
 * Per AI Toolkit Production Readiness Instructions:
 * - NO SIMPLIFICATIONS - all logic must remain intact
 * - Full structured logging for observability
 */

#pragma once

#include <QWidget>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QPointer>
#include "TerminalWidget.h"
#include "TerminalManager.h"

class QPushButton;
class QCheckBox;

class TerminalClusterWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TerminalClusterWidget(QWidget* parent = nullptr);
    ~TerminalClusterWidget() override;

    void initialize();
    void startShells();
    void stopShells();
    
    // Agentic capability: Analyze terminal output for errors and suggest fixes
    void askAIToFix(TerminalManager::ShellType shellType);

signals:
    void errorDetected(const QString& errorText, TerminalManager::ShellType shellType);
    void fixSuggested(const QString& fixCommand, TerminalManager::ShellType shellType);
    void terminalCommand(const QString& command, TerminalManager::ShellType shellType);
    
    // MainWindow integration signals
    void terminalCreated(TerminalWidget* terminal);
    void terminalClosed(TerminalWidget* terminal);
    void currentTerminalChanged(TerminalWidget* terminal);
    void titleChanged(const QString& title);

private slots:
    void onPowerShellErrorDetected(const QString& errorText);
    void onPowerShellFixSuggested(const QString& fixCommand);
    void onCmdErrorDetected(const QString& errorText);
    void onCmdFixSuggested(const QString& fixCommand);
    void onFixButtonClicked();
    void onAutoHealToggled(bool checked);

private:
    void setupUI();
    void setupConnections();
    void setupTerminalTab(const QString& tabName, TerminalManager::ShellType shellType);
    void appendWelcomeMessage(TerminalManager::ShellType shellType);
    
    QTabWidget* m_tabWidget;
    QPointer<TerminalWidget> m_powerShellTerminal;
    QPointer<TerminalWidget> m_cmdTerminal;
    QPushButton* m_fixButton;
    QCheckBox* m_autoHealCheckbox;
    bool m_autonomousMode;
    TerminalManager::ShellType m_currentShellType;
};
