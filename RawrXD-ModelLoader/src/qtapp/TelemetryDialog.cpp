#include "TelemetryDialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QCheckBox>
#include <QPushButton>
#include <QSettings>
#include <QApplication>

TelemetryDialog::TelemetryDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Privacy & Telemetry"));
    setModal(true);
    setupUi();
    
    QSettings settings("RawrXD", "QtShell");
    usageStatsCheck_->setChecked(settings.value("telemetry/usage_stats", false).toBool());
    crashDumpsCheck_->setChecked(settings.value("telemetry/crash_dumps", false).toBool());
}

void TelemetryDialog::setupUi()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    
    QLabel* title = new QLabel(tr("🔒 Help Improve RawrXD"), this);
    title->setStyleSheet("font-size: 16px; font-weight: bold;");
    layout->addWidget(title);
    
    QLabel* intro = new QLabel(
        tr("RawrXD uses cloud services (GitHub API, WebSocket logs) for builds. "
           "You can opt-in to send anonymous telemetry to help us fix bugs faster."),
        this
    );
    intro->setWordWrap(true);
    intro->setStyleSheet("color: #888; margin: 10px 0px;");
    layout->addWidget(intro);
    
    usageStatsCheck_ = new QCheckBox(
        tr("📊 Send anonymous usage stats (API errors, job durations)"),
        this
    );
    layout->addWidget(usageStatsCheck_);
    
    crashDumpsCheck_ = new QCheckBox(
        tr("🐛 Send crash dumps (mini-dump, no source files)"),
        this
    );
    layout->addWidget(crashDumpsCheck_);
    
    QLabel* privacy = new QLabel(
        tr("• No personal data, source code, or secrets are collected\n"
           "• Data is stored for 30 days max\n"
           "• Change anytime in Settings"),
        this
    );
    privacy->setStyleSheet("color: #666; font-size: 11px; margin-top: 10px;");
    layout->addWidget(privacy);
    
    layout->addStretch();
    
    QHBoxLayout* btnLayout = new QHBoxLayout();
    QPushButton* acceptBtn = new QPushButton(tr("Save Preferences"), this);
    QPushButton* declineBtn = new QPushButton(tr("Decline All"), this);
    
    connect(acceptBtn, &QPushButton::clicked, this, &TelemetryDialog::accept);
    connect(declineBtn, &QPushButton::clicked, this, [this]() {
        usageStatsCheck_->setChecked(false);
        crashDumpsCheck_->setChecked(false);
        accept();
    });
    
    btnLayout->addStretch();
    btnLayout->addWidget(declineBtn);
    btnLayout->addWidget(acceptBtn);
    
    layout->addLayout(btnLayout);
    
    setMinimumWidth(500);
}

bool TelemetryDialog::usageStatsEnabled() const
{
    return usageStatsCheck_->isChecked();
}

bool TelemetryDialog::crashDumpsEnabled() const
{
    return crashDumpsCheck_->isChecked();
}

void TelemetryDialog::accept()
{
    QSettings settings("RawrXD", "QtShell");
    settings.setValue("telemetry/usage_stats", usageStatsCheck_->isChecked());
    settings.setValue("telemetry/crash_dumps", crashDumpsCheck_->isChecked());
    settings.setValue("telemetry/dialog_shown", true);
    
    // Set Qt logging rules based on choice
    if (!usageStatsCheck_->isChecked()) {
        qputenv("QT_LOGGING_RULES", "*.debug=false");
    }
    
    QDialog::accept();
}

void TelemetryDialog::checkFirstRun(QWidget* parent)
{
    QSettings settings("RawrXD", "QtShell");
    if (!settings.value("telemetry/dialog_shown", false).toBool()) {
        TelemetryDialog dialog(parent);
        dialog.exec();
    }
}
