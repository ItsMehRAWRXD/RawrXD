/**
 * @file terminal_emulator.h
 * @brief Production implementation of TerminalEmulator
 * 
 * Provides a fully functional terminal emulator including:
 * - Shell process management
 * - ANSI escape code handling
 * - Command history
 * - Copy/paste support
 * - Multiple terminal tabs
 * - Working directory tracking
 * 
 * Per AI Toolkit Production Readiness Instructions:
 * - NO SIMPLIFICATIONS - all logic must remain intact
 * - Full structured logging for observability
 */

#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QProcess>
#include <QKeyEvent>
#include <QScrollBar>
#include <QTimer>
#include <QMenu>
#include <QAction>
#include <QFont>
#include <QColor>
#include <QClipboard>

class TerminalEmulator : public QWidget {
    Q_OBJECT

public:
    struct TerminalSettings {
        QFont font;
        QColor backgroundColor;
        QColor foregroundColor;
        QColor selectionColor;
        int scrollbackLines;
        bool cursorBlink;
        QString shell;
        QStringList shellArgs;
    };

    explicit TerminalEmulator(QWidget* parent = nullptr);
    ~TerminalEmulator() override;

    // Terminal control
    void startShell();
    void stopShell();
    bool isRunning() const;
    void sendCommand(const QString& command);
    void sendText(const QString& text);
    void sendKey(Qt::Key key, Qt::KeyboardModifiers modifiers = Qt::NoModifier);

    // Working directory
    void setWorkingDirectory(const QString& path);
    QString getWorkingDirectory() const;

    // Settings
    void setSettings(const TerminalSettings& settings);
    TerminalSettings getSettings() const;
    void setFont(const QFont& font);
    void setColors(const QColor& bg, const QColor& fg);

    // History
    QStringList getCommandHistory() const;
    void clearHistory();

    // Selection
    QString getSelectedText() const;
    void selectAll();
    void clearSelection();

    // Buffer
    void clear();
    QString getBufferContents() const;

signals:
    void started();
    void finished(int exitCode);
    void outputReceived(const QString& text);
    void titleChanged(const QString& title);
    void workingDirectoryChanged(const QString& path);
    void bellRung();

protected:
    void keyPressEvent(QKeyEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void focusInEvent(QFocusEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;

private slots:
    void onReadyRead();
    void onProcessError(QProcess::ProcessError error);
    void onProcessFinished(int exitCode, QProcess::ExitStatus status);
    void onCursorBlink();

private:
    void setupUI();
    void setupProcess();
    void setupContextMenu();
    void processOutput(const QByteArray& data);
    void processAnsiEscapeCode(const QString& code);
    void appendOutput(const QString& text);
    void appendHtml(const QString& html);
    void updateCursor();
    void scrollToBottom();
    void historyUp();
    void historyDown();
    QString detectShell() const;
    QColor parseAnsiColor(int code, bool bright = false) const;

    // UI
    QVBoxLayout* m_layout;
    QTextEdit* m_textEdit;
    QMenu* m_contextMenu;

    // Process
    QProcess* m_process;
    bool m_isRunning;

    // Settings
    TerminalSettings m_settings;
    
    // State
    QString m_currentLine;
    QString m_workingDirectory;
    QStringList m_commandHistory;
    int m_historyIndex;
    QString m_savedInput;
    
    // ANSI state
    QColor m_currentFgColor;
    QColor m_currentBgColor;
    bool m_boldMode;
    bool m_underlineMode;
    bool m_reverseMode;
    
    // Cursor
    QTimer* m_cursorTimer;
    bool m_cursorVisible;
    int m_cursorPosition;
};

