#pragma once
#include <QWidget>
#include <QTextEdit>

namespace SoloIDE {

class DebugPanel : public QWidget {
    Q_OBJECT
public:
    explicit DebugPanel(QWidget* parent = nullptr);
    ~DebugPanel() override;

    void showStackTrace(const QStringList& frames);
    void appendOutput(const QString& text);
    void clear();

private:
    QTextEdit* m_output;
};

} // namespace SoloIDE
