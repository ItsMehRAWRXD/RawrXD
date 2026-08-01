#pragma once
#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QVBoxLayout>

namespace SoloIDE {

class ChatPanel : public QWidget {
    Q_OBJECT
public:
    explicit ChatPanel(QWidget* parent = nullptr);
    ~ChatPanel() override;

    void appendMessage(const QString& role, const QString& content);
    void appendUserMessage(const QString& text);
    void appendAgentMessage(const QString& text);
    QString pendingMessage() const;
    QString takeInputText();

signals:
    void messageSubmitted(const QString& text);

private:
    QTextEdit* m_display;
    QLineEdit* m_input;
};

} // namespace SoloIDE
