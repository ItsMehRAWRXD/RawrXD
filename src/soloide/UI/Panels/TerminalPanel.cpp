#include "TerminalPanel.hpp"
#include <QVBoxLayout>
#include <QDebug>

namespace SoloIDE {

TerminalPanel::TerminalPanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_output = new QTextEdit(this);
    m_output->setReadOnly(true);
    m_output->setFont(QFont("Consolas", 10));
    m_output->setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;");
    layout->addWidget(m_output);

    m_process = new QProcess(this);
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_process, &QProcess::readyReadStandardOutput, this, [this]() {
        QString data = QString::fromUtf8(m_process->readAllStandardOutput());
        m_output->append(data);
        emit outputReceived(data);
    });
    connect(m_process, &QProcess::readyReadStandardError, this, [this]() {
        QString data = QString::fromUtf8(m_process->readAllStandardError());
        m_output->append("[ERR] " + data);
        emit outputReceived(data);
    });
}

TerminalPanel::~TerminalPanel() {
    if (m_process->state() != QProcess::NotRunning) {
        m_process->kill();
        m_process->waitForFinished(3000);
    }
}

void TerminalPanel::executeCommand(const QString& cmd) {
    m_output->append("$ " + cmd);
    m_process->start("powershell.exe", QStringList() << "-NoProfile" << "-Command" << cmd);
}

void TerminalPanel::writeInput(const QString& text) {
    if (m_process->state() == QProcess::Running) {
        m_process->write(text.toUtf8() + "\n");
    }
}

} // namespace SoloIDE
