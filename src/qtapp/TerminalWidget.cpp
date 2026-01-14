#include "TerminalWidget.h"
#include "TerminalManager.h"

#include <QPlainTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QProcess>

TerminalWidget::TerminalWidget(QWidget* parent)
    : QWidget(parent)
    , m_manager(new TerminalManager(this))
    , m_output(nullptr)
    , m_input(nullptr)
    , m_shellSelect(nullptr)
    , m_startStopBtn(nullptr)
{
    // Lightweight constructor - defers Qt widget creation to initialize()
}

void TerminalWidget::initialize() {
    if (m_output) return;  // Already initialized
    
    m_output = new QPlainTextEdit(this);
    m_input = new QLineEdit(this);
    m_shellSelect = new QComboBox(this);
    m_startStopBtn = new QPushButton("Start", this);
    m_fixBtn = new QPushButton("✨ Fix", this);
    m_fixBtn->setToolTip("Ask AI to analyze and fix terminal errors");
    m_fixBtn->setEnabled(false);
    
    m_output->setReadOnly(true);
    m_output->setFont(QFont("Consolas", 10));

    m_shellSelect->addItem("PowerShell", QVariant::fromValue((int)TerminalManager::PowerShell));
    m_shellSelect->addItem("Command Prompt", QVariant::fromValue((int)TerminalManager::CommandPrompt));

    QHBoxLayout* inputLayout = new QHBoxLayout();
    inputLayout->addWidget(m_shellSelect);
    inputLayout->addWidget(m_startStopBtn);
    inputLayout->addWidget(m_fixBtn);
    inputLayout->addWidget(new QLabel("Cmd>"));
    inputLayout->addWidget(m_input);

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->addWidget(m_output);
    layout->addLayout(inputLayout);

    connect(m_startStopBtn, &QPushButton::clicked, [this]() {
        if (m_manager->isRunning()) {
            stopShell();
        } else {
            startShell((TerminalManager::ShellType)m_shellSelect->currentData().toInt());
        }
    });

    connect(m_fixBtn, &QPushButton::clicked, this, &TerminalWidget::askAIToFix);
    connect(m_input, &QLineEdit::returnPressed, this, &TerminalWidget::onUserCommand);

    connect(m_manager, &TerminalManager::outputReady, this, &TerminalWidget::onOutputReady);
    connect(m_manager, &TerminalManager::errorReady, this, &TerminalWidget::onErrorReady);
    connect(m_manager, &TerminalManager::started, this, &TerminalWidget::onStarted);
    connect(m_manager, &TerminalManager::finished, this, &TerminalWidget::onFinished);
}

TerminalWidget::~TerminalWidget() = default;

void TerminalWidget::startShell(TerminalManager::ShellType type)
{
    if (m_manager->start(type)) {
        m_output->appendPlainText(QStringLiteral("Shell started: PID=%1").arg(m_manager->pid()));
        m_startStopBtn->setText("Stop");
    } else {
        m_output->appendPlainText("Failed to start shell");
    }
}

void TerminalWidget::stopShell()
{
    m_manager->stop();
    m_startStopBtn->setText("Start");
}

bool TerminalWidget::isRunning() const
{
    return m_manager->isRunning();
}

qint64 TerminalWidget::pid() const
{
    return m_manager->pid();
}

QString TerminalWidget::getTitle() const
{
    if (m_manager->isRunning()) {
        return m_shellSelect->currentText() + " (PID: " + QString::number(m_manager->pid()) + ")";
    }
    return m_shellSelect->currentText() + " (stopped)";
}

void TerminalWidget::onUserCommand()
{
    QString cmd = m_input->text();
    if (cmd.isEmpty()) return;
    appendOutput(cmd);
    m_manager->writeInput(cmd.toUtf8());
    m_input->clear();
}

void TerminalWidget::onOutputReady(const QByteArray& data)
{
    QString text = QString::fromUtf8(data);
    appendOutput(text);
    checkForErrors(text);
}

void TerminalWidget::onErrorReady(const QByteArray& data)
{
    QString text = QString::fromUtf8(data);
    appendOutput("<font color='red'>" + text + "</font>");
    checkForErrors(text);
}

void TerminalWidget::checkForErrors(const QString& text)
{
    // Simple autonomous error detection
    static const QStringList errorPatterns = {
        "error:", "fatal error", "failed", "exception", "not found", "denied"
    };

    bool errorFound = false;
    for (const auto& pattern : errorPatterns) {
        if (text.contains(pattern, Qt::CaseInsensitive)) {
            errorFound = true;
            break;
        }
    }

    if (errorFound) {
        m_fixBtn->setEnabled(true);
        m_fixBtn->setStyleSheet("background-color: #4a2b2b; color: #ff9999; border: 1px solid #ff4444;");
        emit errorDetected(text);
    }
}

void TerminalWidget::askAIToFix()
{
    QString lastOutput = m_output->toPlainText().right(2000); // Get last 2KB
    if (lastOutput.isEmpty()) return;

    appendOutput("\n<font color='#007acc'>[Agent] Analyzing terminal error...</font>");
    m_fixBtn->setEnabled(false);
    m_fixBtn->setStyleSheet("");

    // This signal will be caught by MainWindow and passed to the agent
    emit errorDetected(lastOutput);
}

void TerminalWidget::onStarted()
{
    appendOutput("Shell process started");
    m_startStopBtn->setText("Stop");
}

void TerminalWidget::onFinished(int exitCode, QProcess::ExitStatus)
{
    appendOutput(QString("Shell exited: %1").arg(exitCode));
    m_startStopBtn->setText("Start");
    
    if (exitCode != 0) {
        checkForErrors(QString("Process exited with non-zero code %1").arg(exitCode));
    }
}

void TerminalWidget::appendOutput(const QString& text)
{
    // Use HTML for coloring if needed
    if (text.contains("font color")) {
        m_output->appendHtml(text);
    } else {
        m_output->appendPlainText(text);
    }
    m_output->ensureCursorVisible();
}
