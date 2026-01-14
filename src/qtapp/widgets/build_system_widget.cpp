/**
 * @file build_system_widget.cpp
 * @brief Production implementation of BuildSystemWidget
 * 
 * Per AI Toolkit Production Readiness Instructions:
 * - NO SIMPLIFICATIONS - all logic must remain intact
 * - Full structured logging for observability
 * - Comprehensive error handling
 */

#include "build_system_widget.h"
#include <QHeaderView>
#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonArray>
#include <QRegularExpression>
#include <QScrollBar>
#include <QDateTime>
#include "../integration/ProdIntegration.h"
#include "../integration/InitializationTracker.h"

// ==================== Structured Logging ====================
#define LOG_BUILD(level, msg) \
    qDebug() << QString("[%1] [BuildSystemWidget] [%2] %3") \
        .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz")) \
        .arg(level) \
        .arg(msg)

#define LOG_DEBUG(msg) LOG_BUILD("DEBUG", msg)
#define LOG_INFO(msg)  LOG_BUILD("INFO", msg)
#define LOG_WARN(msg)  LOG_BUILD("WARN", msg)
#define LOG_ERROR(msg) LOG_BUILD("ERROR", msg)

// ==================== Constructor/Destructor ====================
BuildSystemWidget::BuildSystemWidget(QWidget* parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_toolbar(nullptr)
    , m_configCombo(nullptr)
    , m_targetCombo(nullptr)
    , m_buildButton(nullptr)
    , m_stopButton(nullptr)
    , m_cleanButton(nullptr)
    , m_rebuildButton(nullptr)
    , m_splitter(nullptr)
    , m_outputView(nullptr)
    , m_errorTree(nullptr)
    , m_progressBar(nullptr)
    , m_statusLabel(nullptr)
    , m_buildProcess(nullptr)
    , m_isBuilding(false)
    , m_lastExitCode(0)
    , m_lastBuildDuration(0)
    , m_buildSystem(BuildSystem::CMake)
    , m_buildConfig(BuildConfig::Debug)
    , m_fileWatcher(nullptr)
{
    RawrXD::Integration::ScopedInitTimer initTimer("BuildSystemWidget");
    LOG_INFO("Initializing BuildSystemWidget...");
    
    setupUI();
    setupToolbar();
    setupConnections();
    
    // Initialize build process
    m_buildProcess = new QProcess(this);
    m_buildProcess->setProcessChannelMode(QProcess::MergedChannels);
    
    // Initialize file watcher for auto-rebuild
    m_fileWatcher = new QFileSystemWatcher(this);
    
    LOG_INFO("BuildSystemWidget initialized successfully");
}

BuildSystemWidget::~BuildSystemWidget()
{
    LOG_INFO("Destroying BuildSystemWidget...");
    
    if (m_isBuilding && m_buildProcess) {
        m_buildProcess->kill();
        m_buildProcess->waitForFinished(3000);
    }
}

// ==================== UI Setup ====================
void BuildSystemWidget::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setContentsMargins(0, 0, 0, 0);
    m_mainLayout->setSpacing(2);

    // Toolbar placeholder (filled in setupToolbar)
    m_toolbar = new QToolBar(this);
    m_toolbar->setMovable(false);
    m_toolbar->setIconSize(QSize(16, 16));
    m_mainLayout->addWidget(m_toolbar);

    // Progress bar
    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(true);
    m_progressBar->setVisible(false);
    m_mainLayout->addWidget(m_progressBar);

    // Splitter for output and errors
    m_splitter = new QSplitter(Qt::Vertical, this);

    // Build output view
    m_outputView = new QTextEdit(this);
    m_outputView->setReadOnly(true);
    m_outputView->setFont(QFont("Consolas", 9));
    m_outputView->setLineWrapMode(QTextEdit::NoWrap);
    m_outputView->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #d4d4d4; }");
    m_splitter->addWidget(m_outputView);

    // Error tree
    m_errorTree = new QTreeWidget(this);
    m_errorTree->setHeaderLabels({"Severity", "File", "Line", "Message"});
    m_errorTree->setRootIsDecorated(false);
    m_errorTree->setAlternatingRowColors(true);
    m_errorTree->header()->setStretchLastSection(true);
    m_errorTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_splitter->addWidget(m_errorTree);

    m_splitter->setStretchFactor(0, 3);
    m_splitter->setStretchFactor(1, 1);
    m_mainLayout->addWidget(m_splitter, 1);

    // Status bar
    m_statusLabel = new QLabel("Ready", this);
    m_statusLabel->setStyleSheet("QLabel { padding: 2px; background-color: #333; }");
    m_mainLayout->addWidget(m_statusLabel);
}

void BuildSystemWidget::setupToolbar()
{
    // Configuration combo
    m_configCombo = new QComboBox(this);
    m_configCombo->addItem("Debug", static_cast<int>(BuildConfig::Debug));
    m_configCombo->addItem("Release", static_cast<int>(BuildConfig::Release));
    m_configCombo->addItem("RelWithDebInfo", static_cast<int>(BuildConfig::RelWithDebInfo));
    m_configCombo->addItem("MinSizeRel", static_cast<int>(BuildConfig::MinSizeRel));
    m_configCombo->setToolTip("Build Configuration");
    m_toolbar->addWidget(new QLabel(" Config: ", this));
    m_toolbar->addWidget(m_configCombo);
    m_toolbar->addSeparator();

    // Target combo
    m_targetCombo = new QComboBox(this);
    m_targetCombo->setMinimumWidth(150);
    m_targetCombo->setToolTip("Build Target");
    m_toolbar->addWidget(new QLabel(" Target: ", this));
    m_toolbar->addWidget(m_targetCombo);
    m_toolbar->addSeparator();

    // Build button
    m_buildButton = new QPushButton("Build", this);
    m_buildButton->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    m_buildButton->setShortcut(QKeySequence("Ctrl+B"));
    m_toolbar->addWidget(m_buildButton);

    // Stop button
    m_stopButton = new QPushButton("Stop", this);
    m_stopButton->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    m_stopButton->setEnabled(false);
    m_toolbar->addWidget(m_stopButton);

    // Clean button
    m_cleanButton = new QPushButton("Clean", this);
    m_cleanButton->setIcon(style()->standardIcon(QStyle::SP_TrashIcon));
    m_toolbar->addWidget(m_cleanButton);

    // Rebuild button
    m_rebuildButton = new QPushButton("Rebuild", this);
    m_rebuildButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    m_rebuildButton->setShortcut(QKeySequence("Ctrl+Shift+B"));
    m_toolbar->addWidget(m_rebuildButton);

    m_toolbar->addSeparator();

    // Clear output action
    QAction* clearAction = m_toolbar->addAction(style()->standardIcon(QStyle::SP_DialogResetButton), "Clear");
    connect(clearAction, &QAction::triggered, this, &BuildSystemWidget::clearOutput);

    // Copy output action
    QAction* copyAction = m_toolbar->addAction(style()->standardIcon(QStyle::SP_DialogSaveButton), "Copy");
    connect(copyAction, &QAction::triggered, this, &BuildSystemWidget::copyOutput);
}

void BuildSystemWidget::setupConnections()
{
    connect(m_buildButton, &QPushButton::clicked, this, &BuildSystemWidget::onBuildButtonClicked);
    connect(m_stopButton, &QPushButton::clicked, this, &BuildSystemWidget::stopBuild);
    connect(m_cleanButton, &QPushButton::clicked, this, &BuildSystemWidget::onCleanButtonClicked);
    connect(m_rebuildButton, &QPushButton::clicked, this, &BuildSystemWidget::onRebuildButtonClicked);
    connect(m_configCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &BuildSystemWidget::onConfigChanged);
    connect(m_targetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &BuildSystemWidget::onTargetChanged);

    // Process connections
    connect(m_buildProcess, &QProcess::readyReadStandardOutput, this, &BuildSystemWidget::onProcessOutput);
    connect(m_buildProcess, &QProcess::readyReadStandardError, this, &BuildSystemWidget::onProcessError);
    connect(m_buildProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &BuildSystemWidget::onProcessFinished);

    // Error tree double click
    connect(m_errorTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item) {
        QString file = item->text(1);
        int line = item->text(2).toInt();
        emit errorDoubleClicked(file, line, 0);
    });
}

// ==================== Configuration ====================
void BuildSystemWidget::setProjectPath(const QString& path)
{
    LOG_INFO(QString("Setting project path: %1").arg(path));
    m_projectPath = path;
    detectBuildSystem();
    loadBuildTargets();
}

void BuildSystemWidget::setBuildSystem(BuildSystem system)
{
    m_buildSystem = system;
    LOG_INFO(QString("Build system set to: %1").arg(static_cast<int>(system)));
}

void BuildSystemWidget::setBuildConfig(BuildConfig config)
{
    m_buildConfig = config;
    int index = m_configCombo->findData(static_cast<int>(config));
    if (index >= 0) {
        m_configCombo->setCurrentIndex(index);
    }
    emit configChanged(config);
}

void BuildSystemWidget::setCustomBuildCommand(const QString& command)
{
    m_customCommand = command;
    m_buildSystem = BuildSystem::Custom;
}

// ==================== Build Control ====================
void BuildSystemWidget::startBuild()
{
    RawrXD::Integration::ScopedTimer timer("BuildSystemWidget", "startBuild", "build_operation");
    if (m_isBuilding) {
        LOG_WARN("Build already in progress");
        return;
    }

    LOG_INFO("Starting build...");
    m_errors.clear();
    m_errorTree->clear();
    clearOutput();

    QString command = getBuildCommand();
    QStringList args = getBuildArguments();

    appendOutput(QString("=== Build Started: %1 ===\n").arg(
        QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")), "#569cd6");
    appendOutput(QString("Command: %1 %2\n").arg(command, args.join(" ")), "#9cdcfe");
    appendOutput(QString("Working Directory: %1\n\n").arg(m_projectPath), "#9cdcfe");

    m_buildProcess->setWorkingDirectory(m_projectPath);
    m_buildTimer.start();
    m_isBuilding = true;

    m_buildButton->setEnabled(false);
    m_stopButton->setEnabled(true);
    m_cleanButton->setEnabled(false);
    m_rebuildButton->setEnabled(false);
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_statusLabel->setText("Building...");

    emit buildStarted();

    m_buildProcess->start(command, args);
    if (!m_buildProcess->waitForStarted(5000)) {
        LOG_ERROR(QString("Failed to start build process: %1").arg(m_buildProcess->errorString()));
        appendOutput(QString("Error: Failed to start build: %1\n").arg(m_buildProcess->errorString()), "#f14c4c");
        m_isBuilding = false;
        m_buildButton->setEnabled(true);
        m_stopButton->setEnabled(false);
        m_cleanButton->setEnabled(true);
        m_rebuildButton->setEnabled(true);
        m_progressBar->setVisible(false);
    }
}

void BuildSystemWidget::stopBuild()
{
    if (!m_isBuilding || !m_buildProcess) return;

    LOG_INFO("Stopping build...");
    m_buildProcess->kill();
    appendOutput("\n=== Build Cancelled ===\n", "#ce9178");
}

void BuildSystemWidget::cleanBuild()
{
    if (m_isBuilding) return;

    LOG_INFO("Cleaning build...");
    clearOutput();
    appendOutput("=== Clean Started ===\n", "#569cd6");

    QString cleanCommand;
    QStringList cleanArgs;

    switch (m_buildSystem) {
        case BuildSystem::CMake:
            cleanCommand = "cmake";
            cleanArgs << "--build" << "." << "--target" << "clean";
            break;
        case BuildSystem::Make:
            cleanCommand = "make";
            cleanArgs << "clean";
            break;
        case BuildSystem::MSBuild:
            cleanCommand = "msbuild";
            cleanArgs << "/t:Clean";
            break;
        case BuildSystem::Ninja:
            cleanCommand = "ninja";
            cleanArgs << "-t" << "clean";
            break;
        default:
            appendOutput("Clean not supported for custom build system\n", "#ce9178");
            return;
    }

    m_buildProcess->setWorkingDirectory(m_projectPath);
    m_buildProcess->start(cleanCommand, cleanArgs);
}

void BuildSystemWidget::rebuildAll()
{
    cleanBuild();
    // Queue build after clean
    QTimer::singleShot(500, this, [this]() {
        if (!m_isBuilding) {
            startBuild();
        }
    });
}

// ==================== Target Management ====================
void BuildSystemWidget::addBuildTarget(const BuildTarget& target)
{
    m_targets.append(target);
    m_targetCombo->addItem(target.name, target.name);
    if (target.isDefault) {
        m_targetCombo->setCurrentText(target.name);
        m_activeTarget = target.name;
    }
}

void BuildSystemWidget::removeBuildTarget(const QString& name)
{
    for (int i = 0; i < m_targets.size(); ++i) {
        if (m_targets[i].name == name) {
            m_targets.removeAt(i);
            int index = m_targetCombo->findData(name);
            if (index >= 0) {
                m_targetCombo->removeItem(index);
            }
            break;
        }
    }
}

QList<BuildSystemWidget::BuildTarget> BuildSystemWidget::getTargets() const
{
    return m_targets;
}

void BuildSystemWidget::setActiveTarget(const QString& name)
{
    m_activeTarget = name;
    m_targetCombo->setCurrentText(name);
    emit targetChanged(name);
}

// ==================== Status ====================
bool BuildSystemWidget::isBuilding() const
{
    return m_isBuilding;
}

int BuildSystemWidget::getLastExitCode() const
{
    return m_lastExitCode;
}

QList<BuildSystemWidget::BuildError> BuildSystemWidget::getLastErrors() const
{
    return m_errors;
}

qint64 BuildSystemWidget::getLastBuildDuration() const
{
    return m_lastBuildDuration;
}

// ==================== Slots ====================
void BuildSystemWidget::onBuildButtonClicked()
{
    startBuild();
}

void BuildSystemWidget::onCleanButtonClicked()
{
    cleanBuild();
}

void BuildSystemWidget::onRebuildButtonClicked()
{
    rebuildAll();
}

void BuildSystemWidget::onConfigChanged(int index)
{
    m_buildConfig = static_cast<BuildConfig>(m_configCombo->itemData(index).toInt());
    LOG_INFO(QString("Build config changed to: %1").arg(index));
    emit configChanged(m_buildConfig);
}

void BuildSystemWidget::onTargetChanged(int index)
{
    m_activeTarget = m_targetCombo->itemData(index).toString();
    LOG_INFO(QString("Build target changed to: %1").arg(m_activeTarget));
    emit targetChanged(m_activeTarget);
}

void BuildSystemWidget::onProcessOutput()
{
    QString output = QString::fromUtf8(m_buildProcess->readAllStandardOutput());
    parseBuildOutput(output);
}

void BuildSystemWidget::onProcessError()
{
    QString error = QString::fromUtf8(m_buildProcess->readAllStandardError());
    appendOutput(error, "#f14c4c");
}

void BuildSystemWidget::onProcessFinished(int exitCode, QProcess::ExitStatus status)
{
    m_isBuilding = false;
    m_lastExitCode = exitCode;
    m_lastBuildDuration = m_buildTimer.elapsed();

    m_buildButton->setEnabled(true);
    m_stopButton->setEnabled(false);
    m_cleanButton->setEnabled(true);
    m_rebuildButton->setEnabled(true);
    m_progressBar->setVisible(false);

    bool success = (exitCode == 0 && status == QProcess::NormalExit);
    QString resultColor = success ? "#4ec9b0" : "#f14c4c";
    QString resultText = success ? "SUCCESS" : "FAILED";

    appendOutput(QString("\n=== Build %1 (exit code: %2, duration: %3ms) ===\n")
        .arg(resultText).arg(exitCode).arg(m_lastBuildDuration), resultColor);

    if (!m_errors.isEmpty()) {
        int errorCount = 0, warningCount = 0;
        for (const auto& err : m_errors) {
            if (err.severity == "error") errorCount++;
            else if (err.severity == "warning") warningCount++;
        }
        appendOutput(QString("Errors: %1, Warnings: %2\n")
            .arg(errorCount).arg(warningCount), "#dcdcaa");
        m_statusLabel->setText(QString("Build %1 - %2 errors, %3 warnings")
            .arg(resultText).arg(errorCount).arg(warningCount));
    } else {
        m_statusLabel->setText(QString("Build %1 - 0 errors, 0 warnings")
            .arg(resultText));
    }

    LOG_INFO(QString("Build finished: %1, exit code %2, duration %3ms")
        .arg(resultText).arg(exitCode).arg(m_lastBuildDuration));

    emit buildFinished(success, exitCode);
}

void BuildSystemWidget::clearOutput()
{
    m_outputView->clear();
    m_errorTree->clear();
    m_errors.clear();
}

void BuildSystemWidget::copyOutput()
{
    QApplication::clipboard()->setText(m_outputView->toPlainText());
}

void BuildSystemWidget::exportBuildLog()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Export Build Log",
        QString(), "Log Files (*.log);;Text Files (*.txt)");
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream stream(&file);
            stream << m_outputView->toPlainText();
            file.close();
        }
    }
}

// ==================== Private Methods ====================
void BuildSystemWidget::detectBuildSystem()
{
    QDir projectDir(m_projectPath);
    
    if (projectDir.exists("CMakeLists.txt")) {
        m_buildSystem = BuildSystem::CMake;
        LOG_INFO("Detected CMake build system");
    } else if (projectDir.exists("Makefile")) {
        m_buildSystem = BuildSystem::Make;
        LOG_INFO("Detected Make build system");
    } else if (projectDir.exists("*.pro")) {
        m_buildSystem = BuildSystem::QMake;
        LOG_INFO("Detected QMake build system");
    } else if (projectDir.exists("build.ninja")) {
        m_buildSystem = BuildSystem::Ninja;
        LOG_INFO("Detected Ninja build system");
    } else {
        LOG_WARN("Could not detect build system");
    }
}

void BuildSystemWidget::loadBuildTargets()
{
    m_targetCombo->clear();
    m_targets.clear();

    // Add default "all" target
    BuildTarget allTarget;
    allTarget.name = "all";
    allTarget.description = "Build all targets";
    allTarget.isDefault = true;
    addBuildTarget(allTarget);

    // For CMake, try to parse CMakeLists.txt for targets
    if (m_buildSystem == BuildSystem::CMake) {
        QString cmakePath = m_projectPath + "/CMakeLists.txt";
        QFile file(cmakePath);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString content = QTextStream(&file).readAll();
            file.close();

            // Find add_executable and add_library calls
            QRegularExpression targetRegex(R"(add_(?:executable|library)\s*\(\s*(\w+))");
            QRegularExpressionMatchIterator it = targetRegex.globalMatch(content);
            
            while (it.hasNext()) {
                QRegularExpressionMatch match = it.next();
                BuildTarget target;
                target.name = match.captured(1);
                target.isDefault = false;
                addBuildTarget(target);
            }
        }
    }
}

void BuildSystemWidget::parseBuildOutput(const QString& output)
{
    QStringList lines = output.split('\n');
    for (const QString& line : lines) {
        if (line.trimmed().isEmpty()) continue;

        // Check for error patterns
        parseErrorLine(line);
        
        // Update progress
        updateProgress(line);

        // Color code the output
        QString color;
        if (line.contains("error", Qt::CaseInsensitive)) {
            color = "#f14c4c";
        } else if (line.contains("warning", Qt::CaseInsensitive)) {
            color = "#cca700";
        } else if (line.contains("Building") || line.contains("Compiling")) {
            color = "#569cd6";
        } else if (line.contains("Linking")) {
            color = "#4ec9b0";
        }

        appendOutput(line + "\n", color);
    }

    emit buildOutput(output);
}

void BuildSystemWidget::parseErrorLine(const QString& line)
{
    // GCC/Clang error format: file:line:column: error/warning: message
    QRegularExpression gccRegex(R"(^(.+):(\d+):(\d+):\s*(error|warning|note):\s*(.+)$)");
    QRegularExpressionMatch match = gccRegex.match(line);

    if (match.hasMatch()) {
        BuildError error;
        error.file = match.captured(1);
        error.line = match.captured(2).toInt();
        error.column = match.captured(3).toInt();
        error.severity = match.captured(4);
        error.message = match.captured(5);

        m_errors.append(error);
        highlightError(error);
        emit buildError(error);
        return;
    }

    // MSVC error format: file(line): error/warning CODE: message
    QRegularExpression msvcRegex(R"(^(.+)\((\d+)\):\s*(error|warning)\s+(\w+):\s*(.+)$)");
    match = msvcRegex.match(line);

    if (match.hasMatch()) {
        BuildError error;
        error.file = match.captured(1);
        error.line = match.captured(2).toInt();
        error.column = 0;
        error.severity = match.captured(3);
        error.message = match.captured(4) + ": " + match.captured(5);

        m_errors.append(error);
        highlightError(error);
        emit buildError(error);
    }
}

void BuildSystemWidget::updateProgress(const QString& line)
{
    // CMake progress format: [ XX%]
    QRegularExpression progressRegex(R"(\[\s*(\d+)%\])");
    QRegularExpressionMatch match = progressRegex.match(line);

    if (match.hasMatch()) {
        int percent = match.captured(1).toInt();
        m_progressBar->setValue(percent);
        emit buildProgress(percent, line);
    }
}

QString BuildSystemWidget::getBuildCommand() const
{
    switch (m_buildSystem) {
        case BuildSystem::CMake:
            return "cmake";
        case BuildSystem::Make:
            return "make";
        case BuildSystem::QMake:
            return "qmake";
        case BuildSystem::MSBuild:
            return "msbuild";
        case BuildSystem::Ninja:
            return "ninja";
        case BuildSystem::Custom:
            return m_customCommand.split(' ').first();
        default:
            return "cmake";
    }
}

QStringList BuildSystemWidget::getBuildArguments() const
{
    QStringList args;

    switch (m_buildSystem) {
        case BuildSystem::CMake:
            args << "--build" << ".";
            if (!m_activeTarget.isEmpty() && m_activeTarget != "all") {
                args << "--target" << m_activeTarget;
            }
            args << "--config" << m_configCombo->currentText();
            args << "--parallel";
            break;
        case BuildSystem::Make:
            args << "-j";
            if (!m_activeTarget.isEmpty() && m_activeTarget != "all") {
                args << m_activeTarget;
            }
            break;
        case BuildSystem::Ninja:
            if (!m_activeTarget.isEmpty() && m_activeTarget != "all") {
                args << m_activeTarget;
            }
            break;
        case BuildSystem::MSBuild:
            args << "/m" << QString("/p:Configuration=%1").arg(m_configCombo->currentText());
            break;
        case BuildSystem::Custom:
            args = m_customCommand.split(' ').mid(1);
            break;
        default:
            break;
    }

    return args;
}

void BuildSystemWidget::appendOutput(const QString& text, const QString& color)
{
    QTextCursor cursor = m_outputView->textCursor();
    cursor.movePosition(QTextCursor::End);

    QTextCharFormat format;
    if (!color.isEmpty()) {
        format.setForeground(QColor(color));
    }

    cursor.insertText(text, format);
    m_outputView->setTextCursor(cursor);
    m_outputView->verticalScrollBar()->setValue(m_outputView->verticalScrollBar()->maximum());
}

void BuildSystemWidget::highlightError(const BuildError& error)
{
    QTreeWidgetItem* item = new QTreeWidgetItem(m_errorTree);
    
    item->setText(0, error.severity);
    item->setText(1, QFileInfo(error.file).fileName());
    item->setText(2, QString::number(error.line));
    item->setText(3, error.message);

    if (error.severity == "error") {
        item->setForeground(0, QColor("#f14c4c"));
        item->setIcon(0, style()->standardIcon(QStyle::SP_MessageBoxCritical));
    } else if (error.severity == "warning") {
        item->setForeground(0, QColor("#cca700"));
        item->setIcon(0, style()->standardIcon(QStyle::SP_MessageBoxWarning));
    } else {
        item->setForeground(0, QColor("#569cd6"));
        item->setIcon(0, style()->standardIcon(QStyle::SP_MessageBoxInformation));
    }

    item->setData(1, Qt::UserRole, error.file);  // Store full path
}

int BuildSystemWidget::countErrors() const
{
    int count = 0;
    for (const BuildError& e : m_errors) {
        if (e.severity == "error") count++;
    }
    return count;
}

int BuildSystemWidget::countWarnings() const
{
    int count = 0;
    for (const BuildError& e : m_errors) {
        if (e.severity == "warning") count++;
    }
    return count;
}

void BuildSystemWidget::appendLog(const QString& message)
{
    LOG_DEBUG("appendLog called with message: " + message.left(100));
    appendOutput(message);
}

void BuildSystemWidget::buildCompleted(bool success)
{
    LOG_INFO(QString("Build completed: %1").arg(success ? "SUCCESS" : "FAILED"));
    emit buildFinished(success, m_buildProcess ? m_buildProcess->exitCode() : 0);
}

