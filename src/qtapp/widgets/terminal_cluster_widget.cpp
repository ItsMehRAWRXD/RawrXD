/**
 * @file terminal_cluster_widget.cpp
 * @brief Implementation of TerminalClusterWidget - Multi-terminal management interface
 */

#include "terminal_cluster_widget.h"
#include "../integration/ProdIntegration.h"
#include "../integration/InitializationTracker.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTabWidget>
#include <QTabBar>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QSpinBox>
#include <QGroupBox>
#include <QProgressBar>
#include <QTimer>
#include <QMenu>
#include <QAction>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QSettings>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QRegularExpressionMatchIterator>
#include <QTextCharFormat>
#include <QFont>
#include <QColor>
#include <QBrush>
#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QFocusEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QApplication>
#include <QClipboard>
#include <QDesktopServices>
#include <QDateTime>
#include <QUuid>
#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QTemporaryFile>
#include <QDebug>
#include <QScrollBar>
#include <QTextCursor>
#include <QTextBlock>
#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <QPalette>

// ============================================================================
// TerminalProcess Implementation
// ============================================================================

TerminalProcess::TerminalProcess(QObject* parent)
    : QObject(parent)
    , process_(nullptr)
    , shell_("cmd")
    , historyIndex_(-1)
{
}

TerminalProcess::~TerminalProcess()
{
    stop();
}

void TerminalProcess::start(const QString& program, const QStringList& arguments, const QString& workingDirectory)
{
    if (process_) {
        stop();
    }

    process_ = new QProcess(this);

    if (!workingDirectory.isEmpty()) {
        process_->setWorkingDirectory(workingDirectory);
    }

    connect(process_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &TerminalProcess::onFinished);
    connect(process_, &QProcess::errorOccurred, this, &TerminalProcess::onErrorOccurred);
    connect(process_, &QProcess::stateChanged, this, &TerminalProcess::onStateChanged);
    connect(process_, &QProcess::readyReadStandardOutput, this, &TerminalProcess::onReadyReadStandardOutput);
    connect(process_, &QProcess::readyReadStandardError, this, &TerminalProcess::onReadyReadStandardError);
    connect(process_, &QProcess::started, this, &TerminalProcess::onStarted);

    QString prog = program.isEmpty() ? shell_ : program;
    QStringList args = arguments;

    // Set up environment for better terminal experience
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("TERM", "xterm-256color");
    process_->setProcessEnvironment(env);

    process_->start(prog, args);
}

void TerminalProcess::stop()
{
    if (process_) {
        process_->terminate();
        if (!process_->waitForFinished(3000)) {
            process_->kill();
            process_->waitForFinished(1000);
        }
        process_->deleteLater();
        process_ = nullptr;
    }
}

void TerminalProcess::write(const QByteArray& data)
{
    if (process_ && process_->isWritable()) {
        process_->write(data);
    }
}

void TerminalProcess::sendCommand(const QString& command)
{
    addToHistory(command);
    write((command + "\n").toUtf8());
}

QString TerminalProcess::getWorkingDirectory() const
{
    if (process_) {
        return process_->workingDirectory();
    }
    return workingDirectory_;
}

void TerminalProcess::setWorkingDirectory(const QString& dir)
{
    workingDirectory_ = dir;
    if (process_) {
        process_->setWorkingDirectory(dir);
    }
}

void TerminalProcess::addToHistory(const QString& command)
{
    if (!command.trimmed().isEmpty() && (history_.isEmpty() || history_.last() != command)) {
        history_.append(command);
        if (history_.size() > 1000) { // Limit history size
            history_.removeFirst();
        }
    }
    historyIndex_ = -1;
}

QString TerminalProcess::getHistoryItem(int index) const
{
    if (index >= 0 && index < history_.size()) {
        return history_[index];
    }
    return QString();
}

void TerminalProcess::onReadyReadStandardOutput()
{
    if (process_) {
        QByteArray data = process_->readAllStandardOutput();
        emit readyReadStandardOutput(data);
    }
}

void TerminalProcess::onReadyReadStandardError()
{
    if (process_) {
        QByteArray data = process_->readAllStandardError();
        emit readyReadStandardError(data);
    }
}

void TerminalProcess::onStarted()
{
    emit started();
}

void TerminalProcess::onFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    emit finished(exitCode, exitStatus);
}

void TerminalProcess::onErrorOccurred(QProcess::ProcessError error)
{
    emit errorOccurred(error);
}

void TerminalProcess::onStateChanged(QProcess::ProcessState state)
{
    emit stateChanged(state);
}

// ============================================================================
// TerminalWidget Implementation
// ============================================================================

TerminalWidget::TerminalWidget(QWidget* parent)
    : QWidget(parent)
    , layout_(nullptr)
    , terminal_(nullptr)
    , inputLine_(nullptr)
    , process_(nullptr)
    , historyIndex_(-1)
    , scrollbackLines_(1000)
    , inEscapeSequence_(false)
{
    RawrXD::Integration::ScopedInitTimer init("TerminalWidget");
    setupUI();
    setupProcess();

    outputColor_ = QColor(200, 200, 200);
    errorColor_ = QColor(255, 100, 100);
    inputColor_ = QColor(150, 150, 255);

    updatePrompt();
}

TerminalWidget::~TerminalWidget()
{
    terminate();
}

void TerminalWidget::setupUI()
{
    layout_ = new QVBoxLayout(this);
    layout_->setContentsMargins(2, 2, 2, 2);
    layout_->setSpacing(0);

    terminal_ = new QPlainTextEdit(this);
    terminal_->setReadOnly(true);
    terminal_->setFont(QFont("Consolas", 10));
    terminal_->setWordWrapMode(QTextOption::NoWrap);
    terminal_->setMaximumBlockCount(scrollbackLines_);

    // Set dark theme colors
    QPalette palette = terminal_->palette();
    palette.setColor(QPalette::Base, QColor(30, 30, 30));
    palette.setColor(QPalette::Text, QColor(200, 200, 200));
    terminal_->setPalette(palette);

    layout_->addWidget(terminal_);

    inputLine_ = new QLineEdit(this);
    inputLine_->setFont(QFont("Consolas", 10));
    inputLine_->setPlaceholderText(tr("Type command here..."));
    layout_->addWidget(inputLine_);

    connect(inputLine_, &QLineEdit::returnPressed, this, [this]() {
        QString input = inputLine_->text();
        if (!input.isEmpty()) {
            handleInput(input);
            inputLine_->clear();
        }
    });
}

void TerminalWidget::setupProcess()
{
    process_ = new TerminalProcess(this);

    connect(process_, &TerminalProcess::readyReadStandardOutput, this, &TerminalWidget::onProcessOutput);
    connect(process_, &TerminalProcess::readyReadStandardError, this, &TerminalWidget::onProcessError);
    connect(process_, &TerminalProcess::started, this, &TerminalWidget::onProcessStarted);
    connect(process_, &TerminalProcess::finished, this, &TerminalWidget::onProcessFinished);
    connect(process_, &TerminalProcess::errorOccurred, this, &TerminalWidget::onProcessError);
}

void TerminalWidget::initialize(const QString& shell, const QString& workingDirectory)
{
    shell_ = shell.isEmpty() ? "cmd" : shell;
    currentDirectory_ = workingDirectory.isEmpty() ? QDir::currentPath() : workingDirectory;

    process_->setShell(shell_);
    process_->setWorkingDirectory(currentDirectory_);

    // Start the shell process
    QStringList args;
    if (shell_.contains("bash") || shell_.contains("sh")) {
        args << "--login" << "-i";
    } else if (shell_.contains("powershell")) {
        args << "-NoExit" << "-Command" << "Set-Location '" + currentDirectory_ + "'";
    }

    process_->start(shell_, args, currentDirectory_);

    updatePrompt();
}

void TerminalWidget::terminate()
{
    if (process_) {
        process_->stop();
    }
}

void TerminalWidget::sendInput(const QString& text)
{
    if (process_ && process_->isRunning()) {
        process_->write(text.toUtf8());
    }
}

void TerminalWidget::sendCommand(const QString& command)
{
    if (process_ && process_->isRunning()) {
        addToHistory(command);
        appendOutput(prompt_ + command + "\n", inputColor_);
        process_->sendCommand(command);
    }
}

void TerminalWidget::clear()
{
    terminal_->clear();
    updatePrompt();
}

void TerminalWidget::scrollToBottom()
{
    QScrollBar* scrollbar = terminal_->verticalScrollBar();
    scrollbar->setValue(scrollbar->maximum());
}

void TerminalWidget::setFont(const QFont& font)
{
    terminal_->setFont(font);
    inputLine_->setFont(font);
}

void TerminalWidget::setColors(const QColor& foreground, const QColor& background)
{
    QPalette palette = terminal_->palette();
    palette.setColor(QPalette::Text, foreground);
    palette.setColor(QPalette::Base, background);
    terminal_->setPalette(palette);

    outputColor_ = foreground;
}

void TerminalWidget::addToHistory(const QString& command)
{
    if (process_) {
        process_->addToHistory(command);
    }
    history_.append(command);
    if (history_.size() > 100) {
        history_.removeFirst();
    }
    historyIndex_ = -1;
}

QStringList TerminalWidget::getHistory() const
{
    return process_ ? process_->getHistory() : QStringList();
}

void TerminalWidget::showHistory()
{
    QStringList history = getHistory();
    if (history.isEmpty()) {
        appendOutput("No command history available.\n", errorColor_);
        return;
    }

    appendOutput("Command History:\n", outputColor_);
    for (int i = 0; i < history.size(); ++i) {
        appendOutput(QString("%1: %2\n").arg(i + 1).arg(history[i]), outputColor_);
    }
}

QString TerminalWidget::getTitle() const
{
    if (currentDirectory_.isEmpty()) {
        return tr("Terminal");
    }

    QFileInfo dirInfo(currentDirectory_);
    return dirInfo.baseName();
}

QString TerminalWidget::getWorkingDirectory() const
{
    return process_ ? process_->getWorkingDirectory() : currentDirectory_;
}

void TerminalWidget::setShell(const QString& shell)
{
    shell_ = shell;
    if (process_) {
        process_->setShell(shell);
    }
}

QString TerminalWidget::getShell() const
{
    return shell_;
}

void TerminalWidget::setScrollbackLines(int lines)
{
    scrollbackLines_ = lines;
    terminal_->setMaximumBlockCount(lines);
}

void TerminalWidget::paintEvent(QPaintEvent* event)
{
    QWidget::paintEvent(event);
}

void TerminalWidget::keyPressEvent(QKeyEvent* event)
{
    if (inputLine_->hasFocus()) {
        // Handle special keys in input line
        if (event->key() == Qt::Key_Up) {
            navigateHistory(-1);
            event->accept();
            return;
        } else if (event->key() == Qt::Key_Down) {
            navigateHistory(1);
            event->accept();
            return;
        } else if (event->key() == Qt::Key_Tab) {
            // Implement tab completion for shell commands and file paths
            QString currentInput = toPlainText().split('\n').last();
            
            // Extract the current word being typed
            int lastSpace = currentInput.lastIndexOf(' ');
            QString prefix = (lastSpace >= 0) ? currentInput.mid(lastSpace + 1) : currentInput;
            
            // Get completion suggestions
            QStringList suggestions;
            
            // Try to complete as a command (from system PATH or history)
            if (lastSpace < 0) {
                // Command completion
                QProcess proc;
                #ifdef Q_OS_WINDOWS
                proc.start("cmd.exe", QStringList() << "/c" << "where" << prefix + "*");
                #else
                proc.start("which", QStringList() << "-a" << prefix + "*");
                #endif
                
                if (proc.waitForFinished(1000)) {
                    suggestions = QString::fromUtf8(proc.readAllStandardOutput()).split('\n', QString::SkipEmptyParts);
                }
            } else {
                // File path completion
                QFileInfo fileInfo(prefix);
                QDir dir = fileInfo.isDir() ? QDir(prefix) : fileInfo.dir();
                
                QStringList filters;
                if (prefix.endsWith(QDir::separator())) {
                    filters = dir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot);
                } else {
                    QString baseName = fileInfo.fileName();
                    dir.setNameFilters(QStringList(baseName + "*"));
                    filters = dir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot);
                }
                
                for (const QString& entry : filters) {
                    suggestions.append(dir.absolutePath() + QDir::separator() + entry);
                }
            }
            
            // Apply first suggestion if available
            if (!suggestions.isEmpty()) {
                QString completion = suggestions.first();
                if (lastSpace >= 0) {
                    currentInput.truncate(lastSpace + 1);
                } else {
                    currentInput.clear();
                }
                
                insertPlainText(completion.mid(prefix.length()));
                ensureCursorVisible();
            }
            
            event->accept();
            return;
        }
    }

    QWidget::keyPressEvent(event);
}

void TerminalWidget::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton) {
        emit activated(this);
    }
    QWidget::mousePressEvent(event);
}

void TerminalWidget::focusInEvent(QFocusEvent* event)
{
    inputLine_->setFocus();
    emit activated(this);
    QWidget::focusInEvent(event);
}

void TerminalWidget::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void TerminalWidget::onProcessOutput(const QByteArray& data)
{
    QString text = QString::fromUtf8(data);
    appendOutput(text, outputColor_);
    scrollToBottom();
}

void TerminalWidget::onProcessError(const QByteArray& data)
{
    QString text = QString::fromUtf8(data);
    appendOutput(text, errorColor_);
    scrollToBottom();
}

void TerminalWidget::onProcessStarted()
{
    appendOutput(tr("Terminal started: %1\n").arg(shell_), outputColor_);
    updatePrompt();
}

void TerminalWidget::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    QString message = tr("Process finished with exit code %1").arg(exitCode);
    if (exitStatus == QProcess::CrashExit) {
        message += tr(" (crashed)");
    }
    message += "\n";
    appendOutput(message, errorColor_);
}

void TerminalWidget::onProcessError(QProcess::ProcessError error)
{
    QString errorMsg;
    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = tr("Failed to start terminal process");
            break;
        case QProcess::Crashed:
            errorMsg = tr("Terminal process crashed");
            break;
        case QProcess::Timedout:
            errorMsg = tr("Terminal process timed out");
            break;
        case QProcess::WriteError:
            errorMsg = tr("Write error to terminal");
            break;
        case QProcess::ReadError:
            errorMsg = tr("Read error from terminal");
            break;
        default:
            errorMsg = tr("Unknown terminal error");
    }
    appendOutput(errorMsg + "\n", errorColor_);
}

void TerminalWidget::updateDisplay()
{
    // Force update of display
    terminal_->viewport()->update();
}

void TerminalWidget::handleInput(const QString& input)
{
    currentInput_ = input;

    if (input.trimmed() == "clear") {
        clear();
    } else if (input.trimmed() == "history") {
        showHistory();
    } else if (input.trimmed() == "exit" || input.trimmed() == "quit") {
        emit closed(this);
    } else {
        sendCommand(input);
    }
}

void TerminalWidget::updatePrompt()
{
    QString dir = getWorkingDirectory();
    if (dir.isEmpty()) {
        dir = "~";
    } else {
        QFileInfo info(dir);
        dir = info.baseName();
        if (dir.isEmpty()) {
            dir = info.absolutePath();
        }
    }

    if (shell_.contains("bash") || shell_.contains("sh")) {
        prompt_ = QString("%1$ ").arg(dir);
    } else if (shell_.contains("powershell")) {
        prompt_ = QString("PS %1> ").arg(dir);
    } else {
        prompt_ = QString("%1> ").arg(dir);
    }
}

void TerminalWidget::appendOutput(const QString& text, const QColor& color)
{
    QTextCursor cursor = terminal_->textCursor();
    cursor.movePosition(QTextCursor::End);

    QTextCharFormat format;
    if (color.isValid()) {
        format.setForeground(color);
    }

    cursor.insertText(text, format);
}

void TerminalWidget::processEscapeSequence(const QString& sequence)
{
    // Basic ANSI escape sequence processing
    // In a full implementation, this would handle cursor movement, colors, etc.
    Q_UNUSED(sequence)
}

void TerminalWidget::navigateHistory(int direction)
{
    QStringList history = getHistory();
    if (history.isEmpty()) return;

    historyIndex_ += direction;

    if (historyIndex_ < 0) {
        historyIndex_ = -1;
        inputLine_->clear();
    } else if (historyIndex_ >= history.size()) {
        historyIndex_ = history.size() - 1;
    }

    if (historyIndex_ >= 0 && historyIndex_ < history.size()) {
        inputLine_->setText(history[historyIndex_]);
    }
}

// ============================================================================
// TerminalClusterWidget Implementation
// ============================================================================

TerminalClusterWidget::TerminalClusterWidget(QWidget* parent, QSettings* settings)
    : QWidget(parent)
    , settings_(settings)
    , mainLayout_(nullptr)
    , tabWidget_(nullptr)
    , shellSelector_(nullptr)
    , newTabButton_(nullptr)
    , currentTerminalIndex_(-1)
{
    RawrXD::Integration::ScopedInitTimer init("TerminalClusterWidget");
    setObjectName("TerminalClusterWidget");
    setupUI();
    setupConnections();

    if (settings_) {
        restoreTerminalState();
        connect(settings_, &QSettings::changed, this, &TerminalClusterWidget::onSettingsChanged);
    }

    // Fallback if no terminals were restored
    if (tabWidget_->count() == 0) {
        createTerminal();
    }
}

TerminalClusterWidget::~TerminalClusterWidget()
{
    if (settings_) {
        saveTerminalState();
    }
}

void TerminalClusterWidget::setupUI()
{
    mainLayout_ = new QVBoxLayout(this);
    mainLayout_->setContentsMargins(0, 0, 0, 0);
    mainLayout_->setSpacing(0);

    setupToolbar();
    setupTabWidget();

    updateLayout();
}

void TerminalClusterWidget::setupToolbar()
{
    toolbarWidget_ = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarWidget_);
    toolbarLayout_->setContentsMargins(4, 2, 4, 2);

    // Terminal management
    newTerminalBtn_ = new QPushButton(tr("New"), toolbarWidget_);
    closeTerminalBtn_ = new QPushButton(tr("Close"), toolbarWidget_);
    closeAllBtn_ = new QPushButton(tr("Close All"), toolbarWidget_);
    renameBtn_ = new QPushButton(tr("Rename"), toolbarWidget_);
    duplicateBtn_ = new QPushButton(tr("Duplicate"), toolbarWidget_);
    splitBtn_ = new QPushButton(tr("Split"), toolbarWidget_);

    toolbarLayout_->addWidget(newTerminalBtn_);
    toolbarLayout_->addWidget(closeTerminalBtn_);
    toolbarLayout_->addWidget(closeAllBtn_);
    toolbarLayout_->addWidget(renameBtn_);
    toolbarLayout_->addWidget(duplicateBtn_);
    toolbarLayout_->addWidget(splitBtn_);

    toolbarLayout_->addSeparator();

    // Operations
    clearBtn_ = new QPushButton(tr("Clear"), toolbarWidget_);
    restartBtn_ = new QPushButton(tr("Restart"), toolbarWidget_);

    toolbarLayout_->addWidget(clearBtn_);
    toolbarLayout_->addWidget(restartBtn_);

    toolbarLayout_->addSeparator();

    // Layout controls
    layoutLabel_ = new QLabel(tr("Layout:"), toolbarWidget_);
    layoutCombo_ = new QComboBox(toolbarWidget_);
    layoutCombo_->addItem(tr("Tabs"), 0);
    layoutCombo_->addItem(tr("Split Horizontal"), 1);
    layoutCombo_->addItem(tr("Split Vertical"), 2);
    layoutCombo_->addItem(tr("Grid"), 3);
    layoutCombo_->setCurrentIndex(layoutMode_);

    toolbarLayout_->addWidget(layoutLabel_);
    toolbarLayout_->addWidget(layoutCombo_);

    toolbarLayout_->addSeparator();

    // Appearance
    fontBtn_ = new QPushButton(tr("Font"), toolbarWidget_);
    colorsBtn_ = new QPushButton(tr("Colors"), toolbarWidget_);
    settingsBtn_ = new QPushButton(tr("Settings"), toolbarWidget_);

    toolbarLayout_->addWidget(fontBtn_);
    toolbarLayout_->addWidget(colorsBtn_);
    toolbarLayout_->addWidget(settingsBtn_);

    toolbarLayout_->addStretch();

    mainLayout_->addWidget(toolbarWidget_);
}

void TerminalClusterWidget::setupTabWidget()
{
    tabWidget_ = new QTabWidget(this);
    tabWidget_->setTabsClosable(true);
    tabWidget_->setMovable(true);
    mainLayout_->addWidget(tabWidget_);

    // Create split widget for alternative layouts
    splitWidget_ = new QWidget(this);
    splitter_ = new QSplitter(splitWidget_);
    mainLayout_->addWidget(splitWidget_);
    splitWidget_->hide();
}

void TerminalClusterWidget::setupConnections()
{
    // Toolbar actions
    connect(newTerminalBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onNewTerminal);
    connect(closeTerminalBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onCloseTerminal);
    connect(closeAllBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onCloseAllTerminals);
    connect(renameBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onRenameTerminal);
    connect(duplicateBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onDuplicateTerminal);
    connect(splitBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onSplitTerminal);
    connect(clearBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onClearTerminal);
    connect(restartBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onRestartTerminal);

    connect(layoutCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &TerminalClusterWidget::onLayoutChanged);
    connect(fontBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onFontChanged);
    connect(colorsBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onColorsChanged);
    connect(settingsBtn_, &QPushButton::clicked, this, &TerminalClusterWidget::onSettingsChanged);

    // Tab widget
    connect(tabWidget_, &QTabWidget::tabCloseRequested, this, &TerminalClusterWidget::onTabCloseRequested);
    connect(tabWidget_, &QTabWidget::currentChanged, this, &TerminalClusterWidget::onCurrentTabChanged);
}

TerminalWidget* TerminalClusterWidget::createTerminal(const QString& name, const QString& shell, const QString& workingDirectory)
{
    QString terminalName = name.isEmpty() ? generateTerminalName() : name;
    QString terminalShell = shell.isEmpty() ? defaultShell_ : shell;
    QString terminalDir = workingDirectory.isEmpty() ? defaultWorkingDirectory_ : workingDirectory;

    TerminalWidget* terminal = new TerminalWidget(this);
    terminal->setFont(font_);
    terminal->setColors(foregroundColor_, backgroundColor_);
    terminal->initialize(terminalShell, terminalDir);

    terminals_.append(terminal);
    currentTerminal_ = terminal;

    // Add to tab widget
    int tabIndex = tabWidget_->addTab(terminal, terminalName);
    tabWidget_->setCurrentIndex(tabIndex);

    connect(terminal, &TerminalWidget::activated, this, &TerminalClusterWidget::onTerminalActivated);
    connect(terminal, &TerminalWidget::closed, this, &TerminalClusterWidget::onTerminalClosed);
    connect(terminal, &TerminalWidget::titleChanged, this, [this, tabIndex](const QString& title) {
        tabWidget_->setTabText(tabIndex, title);
    });

    updateLayout();
    updateToolbar();
    updateWindowTitle();

    emit terminalCreated(terminal);
    return terminal;
}

void TerminalClusterWidget::closeTerminal(TerminalWidget* terminal)
{
    if (!terminal) return;

    int index = terminals_.indexOf(terminal);
    if (index >= 0) {
        closeTerminal(index);
    }
}

void TerminalClusterWidget::closeTerminal(int index)
{
    if (index < 0 || index >= terminals_.size()) return;

    TerminalWidget* terminal = terminals_[index];
    terminals_.removeAt(index);

    // Remove from tab widget
    tabWidget_->removeTab(index);

    terminal->terminate();
    terminal->deleteLater();

    if (terminals_.isEmpty()) {
        currentTerminal_ = nullptr;
    } else if (currentTerminal_ == terminal) {
        currentTerminal_ = terminals_.first();
    }

    updateLayout();
    updateToolbar();
    updateWindowTitle();

    emit terminalClosed(terminal);
}

TerminalWidget* TerminalClusterWidget::getCurrentTerminal() const
{
    return currentTerminal_;
}

TerminalWidget* TerminalClusterWidget::getTerminal(int index) const
{
    if (index >= 0 && index < terminals_.size()) {
        return terminals_[index];
    }
    return nullptr;
}

void TerminalClusterWidget::setLayoutMode(int mode)
{
    if (layoutMode_ != mode) {
        layoutMode_ = mode;
        layoutCombo_->setCurrentIndex(mode);
        updateLayout();
    }
}

void TerminalClusterWidget::sendToAllTerminals(const QString& command)
{
    for (TerminalWidget* terminal : terminals_) {
        if (terminal->isActive()) {
            terminal->sendCommand(command);
        }
    }
}

void TerminalClusterWidget::clearAllTerminals()
{
    for (TerminalWidget* terminal : terminals_) {
        terminal->clear();
    }
}

void TerminalClusterWidget::restartAllTerminals()
{
    for (TerminalWidget* terminal : terminals_) {
        terminal->terminate();
        terminal->initialize(terminal->getShell(), terminal->getWorkingDirectory());
    }
}

void TerminalClusterWidget::setFont(const QFont& font)
{
    font_ = font;
    for (TerminalWidget* terminal : terminals_) {
        terminal->setFont(font);
    }
    settings_->setValue("font", font);
}

void TerminalClusterWidget::setColors(const QColor& foreground, const QColor& background)
{
    foregroundColor_ = foreground;
    backgroundColor_ = background;
    for (TerminalWidget* terminal : terminals_) {
        terminal->setColors(foreground, background);
    }
    settings_->setValue("foregroundColor", foreground);
    settings_->setValue("backgroundColor", background);
}

void TerminalClusterWidget::refresh()
{
    updateLayout();
    updateToolbar();
    updateWindowTitle();
}

void TerminalClusterWidget::setReadOnly(bool readOnly)
{
    readOnly_ = readOnly;
    // Update terminal read-only state if needed
    updateToolbar();
}

QString TerminalClusterWidget::getTitle() const
{
    if (terminals_.isEmpty()) {
        return tr("Terminal Cluster");
    }

    if (terminals_.size() == 1) {
        return terminals_.first()->getTitle();
    }

    return tr("Terminals (%1)").arg(terminals_.size());
}

void TerminalClusterWidget::closeEvent(QCloseEvent* event)
{
    // Close all terminals
    for (TerminalWidget* terminal : terminals_) {
        terminal->terminate();
    }
    event->accept();
}

void TerminalClusterWidget::dragEnterEvent(QDragEnterEvent* event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void TerminalClusterWidget::dropEvent(QDropEvent* event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls()) {
        QList<QUrl> urls = mimeData->urls();
        if (!urls.isEmpty()) {
            QString filePath = urls.first().toLocalFile();
            if (QFileInfo(filePath).isDir()) {
                // Create terminal in dropped directory
                createTerminal(QString(), defaultShell_, filePath);
            }
        }
    }
}

void TerminalClusterWidget::updateLayout()
{
    switch (layoutMode_) {
        case 0: // Tabs
            createTabLayout();
            break;
        case 1: // Horizontal split
            createSplitLayout();
            break;
        case 2: // Vertical split
            createSplitLayout();
            break;
        case 3: // Grid
            createGridLayout();
            break;
    }
}

void TerminalClusterWidget::createTabLayout()
{
    tabWidget_->show();
    splitWidget_->hide();

    // Ensure all terminals are in tabs
    for (int i = tabWidget_->count() - 1; i >= 0; --i) {
        tabWidget_->removeTab(i);
    }

    for (TerminalWidget* terminal : terminals_) {
        tabWidget_->addTab(terminal, terminal->getTitle());
    }
}

void TerminalClusterWidget::createSplitLayout()
{
    tabWidget_->hide();
    splitWidget_->show();

    // Clear existing splitter
    QList<int> sizes = splitter_->sizes();
    for (int i = splitter_->count() - 1; i >= 0; --i) {
        splitter_->widget(i)->setParent(nullptr);
    }

    // Add terminals to splitter
    for (TerminalWidget* terminal : terminals_) {
        splitter_->addWidget(terminal);
    }

    splitter_->setOrientation(layoutMode_ == 1 ? Qt::Horizontal : Qt::Vertical);
    if (!sizes.isEmpty()) {
        splitter_->setSizes(sizes);
    }
}

void TerminalClusterWidget::createGridLayout()
{
    // For grid layout, we'd need a more complex widget
    // For now, fall back to tabs
    createTabLayout();
}

QString TerminalClusterWidget::generateTerminalName() const
{
    int count = terminals_.size() + 1;
    QString baseName = tr("Terminal %1");
    QString name = baseName.arg(count);

    // Ensure unique name
    QSet<QString> existingNames;
    for (TerminalWidget* terminal : terminals_) {
        existingNames.insert(terminal->getTitle());
    }

    while (existingNames.contains(name)) {
        name = baseName.arg(++count);
    }

    return name;
}

void TerminalClusterWidget::saveTerminalState()
{
    RawrXD::Integration::ScopedTimer timer("TerminalClusterWidget", "TerminalClusterWidget", "saveTerminalState");
    QJsonArray terminalsArray;
    for (int i = 0; i < tabWidget_->count(); ++i) {
        TerminalWidget* terminal = qobject_cast<TerminalWidget*>(tabWidget_->widget(i));
        if (terminal) {
            QJsonObject terminalObj;
            terminalObj["name"] = tabWidget_->tabText(i);
            terminalObj["shell"] = terminal->getShell();
            terminalObj["directory"] = terminal->getWorkingDirectory();
            // History could be saved here if needed
            terminalsArray.append(terminalObj);
        }
    }
    QJsonObject state;
    state["terminals"] = terminalsArray;
    state["layoutMode"] = layoutMode_;
    
    QJsonDocument doc(state);
    settings_->setValue("terminalState", doc.toJson(QJsonDocument::Compact));
    RawrXD::Integration::logInfo("TerminalClusterWidget", "saveTerminalState", "Terminal state saved successfully", {{"terminalCount", terminalsArray.size()}});
    RawrXD::Integration::recordMetric("terminal.state.save.count");
}

void TerminalClusterWidget::restoreTerminalState()
{
    RawrXD::Integration::ScopedTimer timer("TerminalClusterWidget", "TerminalClusterWidget", "restoreTerminalState");
    QByteArray jsonData = settings_->value("terminalState").toByteArray();
    if (jsonData.isEmpty()) {
        RawrXD::Integration::logInfo("TerminalClusterWidget", "restoreTerminalState", "No saved terminal state found, creating default terminal.");
        createTerminal(); // Create a default terminal if no state
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(jsonData);
    if (doc.isNull() || !doc.isObject()) {
        RawrXD::Integration::logInfo("TerminalClusterWidget", "restoreTerminalState", "Failed to parse saved terminal state.");
        createTerminal();
        return;
    }

    QJsonObject state = doc.object();
    
    // Close any existing terminals before restoring
    onCloseAllTerminals();

    QJsonArray terminalsArray = state["terminals"].toArray();
    for (const QJsonValue &val : terminalsArray) {
        QJsonObject terminalObj = val.toObject();
        createTerminal(
            terminalObj["name"].toString(),
            terminalObj["shell"].toString(),
            terminalObj["directory"].toString()
        );
    }

    if (state.contains("layoutMode")) {
        setLayoutMode(state["layoutMode"].toInt());
    }
    
    if (terminals_.isEmpty()) {
        createTerminal(); // Ensure at least one terminal exists
    }
    RawrXD::Integration::logInfo("TerminalClusterWidget", "restoreTerminalState", "Terminal state restored successfully.", {{"terminalCount", terminalsArray.size()}});
    RawrXD::Integration::recordMetric("terminal.state.restore.count");
}

void TerminalClusterWidget::onNewTerminal()
{
    createTerminal();
}

void TerminalClusterWidget::onCloseTerminal()
{
    if (currentTerminal_) {
        closeTerminal(currentTerminal_);
    }
}

void TerminalClusterWidget::onCloseAllTerminals()
{
    while (!terminals_.isEmpty()) {
        closeTerminal(0);
    }
}

void TerminalClusterWidget::onRenameTerminal()
{
    if (!currentTerminal_) return;

    bool ok;
    QString newName = QInputDialog::getText(this, tr("Rename Terminal"),
                                          tr("New name:"), QLineEdit::Normal,
                                          currentTerminal_->getTitle(), &ok);

    if (ok && !newName.isEmpty()) {
        int index = terminals_.indexOf(currentTerminal_);
        if (index >= 0) {
            tabWidget_->setTabText(index, newName);
        }
    }
}

void TerminalClusterWidget::onDuplicateTerminal()
{
    if (!currentTerminal_) return;

    createTerminal(currentTerminal_->getTitle() + tr(" (Copy)"),
                  currentTerminal_->getShell(),
                  currentTerminal_->getWorkingDirectory());
}

void TerminalClusterWidget::onSplitTerminal()
{
    // Create a new terminal split from current
    if (currentTerminal_) {
        createTerminal(currentTerminal_->getTitle() + tr(" (Split)"),
                      currentTerminal_->getShell(),
                      currentTerminal_->getWorkingDirectory());
    }
}

void TerminalClusterWidget::onLayoutChanged(int mode)
{
    setLayoutMode(mode);
}

void TerminalClusterWidget::onFontChanged()
{
    bool ok;
    QFont font = QFontDialog::getFont(&ok, font_, this);
    if (ok) {
        setFont(font);
    }
}

void TerminalClusterWidget::onColorsChanged()
{
    QColor foreground = QColorDialog::getColor(foregroundColor_, this, tr("Choose foreground color"));
    if (foreground.isValid()) {
        QColor background = QColorDialog::getColor(backgroundColor_, this, tr("Choose background color"));
        if (background.isValid()) {
            setColors(foreground, background);
        }
    }
}

void TerminalClusterWidget::onSettingsChanged()
{
    RawrXD::Integration::logInfo("TerminalClusterWidget", "onSettingsChanged", "Settings dialog opened by user");
    // Placeholder for settings dialog
    QMessageBox::information(this, tr("Settings"), tr("Settings dialog not yet implemented."));
}

void TerminalClusterWidget::onTerminalActivated(TerminalWidget* terminal)
{
    currentTerminal_ = terminal;
    int index = terminals_.indexOf(terminal);
    if (index >= 0) {
        tabWidget_->setCurrentIndex(index);
    }

    emit currentTerminalChanged(terminal);
}

void TerminalClusterWidget::onTerminalClosed(TerminalWidget* terminal)
{
    closeTerminal(terminal);
}

void TerminalClusterWidget::onTabCloseRequested(int index)
{
    closeTerminal(index);
}

void TerminalClusterWidget::onCurrentTabChanged(int index)
{
    if (index >= 0 && index < terminals_.size()) {
        currentTerminal_ = terminals_[index];
        emit currentTerminalChanged(currentTerminal_);
    }
}

void TerminalClusterWidget::updateToolbar()
{
    bool hasTerminals = !terminals_.isEmpty();
    bool hasCurrent = currentTerminal_ != nullptr;

    closeTerminalBtn_->setEnabled(hasCurrent);
    closeAllBtn_->setEnabled(hasTerminals);
    renameBtn_->setEnabled(hasCurrent);
    duplicateBtn_->setEnabled(hasCurrent);
    splitBtn_->setEnabled(hasCurrent);
    clearBtn_->setEnabled(hasCurrent);
    restartBtn_->setEnabled(hasCurrent);

    layoutCombo_->setEnabled(hasTerminals);
    fontBtn_->setEnabled(hasTerminals);
    colorsBtn_->setEnabled(hasTerminals);
}

void TerminalClusterWidget::updateWindowTitle()
{
    emit titleChanged(getTitle());
}

// Missing method implementations
void TerminalClusterWidget::onClearTerminal()
{
    if (currentTerminal_) {
        currentTerminal_->clear();
    }
}

void TerminalClusterWidget::onRestartTerminal()
{
    if (currentTerminal_) {
        currentTerminal_->terminate();
        currentTerminal_->initialize(currentTerminal_->getShell(),
                                   currentTerminal_->getWorkingDirectory());
    }
}

void TerminalClusterWidget::appendLog(const QString& message)
{
    if (currentTerminal_) {
        currentTerminal_->appendOutput(message);
    }
}

void TerminalClusterWidget::appendError(const QString& error)
{
    if (currentTerminal_) {
        currentTerminal_->appendOutput(error, QColor(255, 100, 100));  // Red for errors
    }
}
