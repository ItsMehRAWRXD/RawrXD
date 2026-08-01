#include "ChatPanel.hpp"
#include <QDateTime>
#include <QHBoxLayout>

namespace SoloIDE {

ChatPanel::ChatPanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_display = new QTextEdit(this);
    m_display->setReadOnly(true);
    m_display->setFont(QFont("Consolas", 10));
    layout->addWidget(m_display, 1);

    m_input = new QLineEdit(this);
    m_input->setPlaceholderText("Ask the Sovereign Agent...");
    m_input->setFont(QFont("Consolas", 10));
    layout->addWidget(m_input);

    connect(m_input, &QLineEdit::returnPressed, this, [this]() {
        if (!m_input->text().trimmed().isEmpty()) {
            emit messageSubmitted(m_input->text());
        }
    });
}

ChatPanel::~ChatPanel() = default;

void ChatPanel::appendMessage(const QString& role, const QString& content) {
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString prefix = (role == "user") ? "You" : "Agent";
    m_display->append(QString("[%1] %2: %3").arg(timestamp, prefix, content));
}

void ChatPanel::appendUserMessage(const QString& text) {
    appendMessage("user", text);
}

void ChatPanel::appendAgentMessage(const QString& text) {
    appendMessage("agent", text);
}

QString ChatPanel::pendingMessage() const {
    return m_input->text();
}

QString ChatPanel::takeInputText() {
    QString text = m_input->text();
    m_input->clear();
    return text;
}

} // namespace SoloIDE
