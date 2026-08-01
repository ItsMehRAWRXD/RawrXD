#include "DebugPanel.hpp"
#include <QVBoxLayout>

namespace SoloIDE {

DebugPanel::DebugPanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_output = new QTextEdit(this);
    m_output->setReadOnly(true);
    m_output->setFont(QFont("Consolas", 10));
    layout->addWidget(m_output);
}

DebugPanel::~DebugPanel() = default;

void DebugPanel::showStackTrace(const QStringList& frames) {
    m_output->clear();
    m_output->append("=== Stack Trace ===");
    for (int i = 0; i < frames.size(); ++i) {
        m_output->append(QString("  #%1 %2").arg(i).arg(frames[i]));
    }
}

void DebugPanel::appendOutput(const QString& text) {
    m_output->append(text);
}

void DebugPanel::clear() {
    m_output->clear();
}

} // namespace SoloIDE
