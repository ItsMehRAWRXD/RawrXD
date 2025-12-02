#include "TaskProposalWidget.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QPlainTextEdit>

TaskProposalWidget::TaskProposalWidget(const QString& taskId,
                                       const QString& agentType,
                                       QWidget* parent)
    : QWidget(parent), taskId_(taskId), agentLabel_(agentType) {
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(6,6,6,6);
    outer->setSpacing(4);

    auto* header = new QWidget(this);
    auto* h = new QHBoxLayout(header);
    h->setContentsMargins(0,0,0,0);

    headerButton_ = new QPushButton(QString("[%1] %2").arg(agentLabel_, taskId_), header);
    headerButton_->setCheckable(true);
    headerButton_->setChecked(true);
    connect(headerButton_, &QPushButton::clicked, this, &TaskProposalWidget::toggleBody);

    statusLabel_ = new QLabel("Running…", header);
    statusLabel_->setStyleSheet("color: #888;");

    h->addWidget(headerButton_, 1);
    h->addWidget(statusLabel_);
    outer->addWidget(header);

    body_ = new QPlainTextEdit(this);
    body_->setReadOnly(true);
    body_->setStyleSheet("background:#111; color:#ddd; font-family: Consolas, 'Courier New', monospace;");
    outer->addWidget(body_, 1);
}

void TaskProposalWidget::appendChunk(const QString& chunk) {
    body_->appendPlainText(chunk);
}

void TaskProposalWidget::setStatus(const QString& statusText) {
    statusLabel_->setText(statusText);
    QString style;
    const QString s = statusText.toLower();
    if (s.contains("completed") || s.contains("success")) {
        style = "background-color: #D4EDDA; color: #155724; font-weight: bold;"; // green
    } else if (s.contains("failed") || s.contains("blocked")) {
        style = "background-color: #F8D7DA; color: #721C24; font-weight: bold;"; // red
    } else if (s.contains("running") || s.contains("retrying") || s.contains("re-evaluating")) {
        style = "background-color: #FFF3CD; color: #856404; font-weight: bold;"; // amber
    } else {
        style = "";
    }
    if (headerButton_) headerButton_->setStyleSheet(style);
    if (statusLabel_) statusLabel_->setStyleSheet(style);
}

void TaskProposalWidget::updateHeader(const QString& agentType, const QString& statusText) {
    if (headerButton_) headerButton_->setText(QString("[%1] %2").arg(agentType, taskId_));
    if (statusLabel_) statusLabel_->setText(statusText);
    // Apply color cues via setStatus to keep logic centralized
    setStatus(statusText);
}

void TaskProposalWidget::toggleBody() {
    expanded_ = !expanded_;
    body_->setVisible(expanded_);
}
