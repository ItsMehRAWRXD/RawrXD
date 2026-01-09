#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QTabWidget>
#include <QLabel>
#include <QSettings>

class AppSettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit AppSettingsDialog(QWidget* parent = nullptr);
    ~AppSettingsDialog();

signals:
    void settingsSaved();

private slots:
    void onBrowseProjectRoot();
    void onBrowseModelCache();
    void onLoadFromEnv();
    void onSave();
    void onCancel();

private:
    void setupUI();
    void loadSettings();
    void applySettings();

    // UI
    QTabWidget* m_tabs;
    // General
    QLineEdit* m_llmEndpointEdit;
    QSpinBox*  m_ggufPortSpin;
    QLineEdit* m_projectRootEdit;
    QLineEdit* m_modelCacheEdit;
    QComboBox* m_logLevelCombo;
    QSpinBox* m_readinessRetriesSpin;
    QSpinBox* m_readinessBackoffSpin;
    QCheckBox* m_headlessModeCheck;
    QPushButton* m_browseRootBtn;
    QPushButton* m_browseCacheBtn;
    QPushButton* m_loadEnvBtn;

    // Agent toggles
    QCheckBox* m_enableAutonomousCheck;
    QCheckBox* m_enableStreamingCheck;
    QCheckBox* m_enableMetricsCheck;

    QPushButton* m_saveBtn;
    QPushButton* m_cancelBtn;
};
