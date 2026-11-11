#pragma once
#include <QWidget>
#include <QLabel>

namespace SoloIDE {

class StatusPanel : public QWidget {
    Q_OBJECT
public:
    explicit StatusPanel(QWidget* parent = nullptr);
    ~StatusPanel() override;

    void setStatus(const QString& text);
    void setTps(double tps);
    void setModelName(const QString& name);
    void setInferenceProgress(bool active);

private:
    QLabel* m_statusLabel;
    QLabel* m_tpsLabel;
    QLabel* m_modelLabel;
};

} // namespace SoloIDE
