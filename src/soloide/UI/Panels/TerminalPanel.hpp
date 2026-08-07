#pragma once
#include <QWidget>
#include <QTextEdit>
#include <QProcess>

namespace SoloIDE {

class TerminalPanel : public QWidget {
    Q_OBJECT
public:
    explicit TerminalPanel(QWidget* parent = nullptr);
    ~TerminalPanel() override;

    void executeCommand(const QString& cmd);
    void writeInput(const QString& text);

signals:
    void outputReceived(const QString& text);

private:
    QTextEdit* m_output;
    QProcess* m_process;
};

} // namespace SoloIDE
