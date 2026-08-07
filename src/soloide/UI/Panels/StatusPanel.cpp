#include "StatusPanel.hpp"
#include <QHBoxLayout>

namespace SoloIDE {

StatusPanel::StatusPanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(4, 0, 4, 0);

    m_statusLabel = new QLabel("Ready | Sovereign Mode", this);
    m_tpsLabel = new QLabel("TPS: --", this);
    m_modelLabel = new QLabel("Model: --", this);

    layout->addWidget(m_statusLabel, 1);
    layout->addWidget(m_modelLabel);
    layout->addWidget(m_tpsLabel);
}

StatusPanel::~StatusPanel() = default;

void StatusPanel::setStatus(const QString& text) { m_statusLabel->setText(text); }
void StatusPanel::setTps(double tps) { m_tpsLabel->setText(QString("TPS: %1").arg(tps, 0, 'f', 1)); }
void StatusPanel::setModelName(const QString& name) { m_modelLabel->setText("Model: " + name); }
void StatusPanel::setInferenceProgress(bool active) {
    m_statusLabel->setText(active ? "Inferencing..." : "Ready | Sovereign Mode");
}

} // namespace SoloIDE
