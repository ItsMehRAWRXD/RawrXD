#pragma once
#include <QPlainTextEdit>
#include <QString>
#include <QPoint>

namespace SoloIDE {

class EditorPanel : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit EditorPanel(QWidget* parent = nullptr);
    ~EditorPanel() override;

    QString currentFile() const { return m_currentFile; }
    void setCurrentFile(const QString& file) { m_currentFile = file; }
    QPoint cursorPosition() const;
    QString selectedText() const;
    int currentLine() const;

    // Ghost text overlay
    void showGhostText(const QString& text);
    void setGhostText(const QString& text);
    void acceptGhostText();
    void rejectGhostText();
    void clearGhostText();

signals:
    void fileChanged(const QString& path);
    void ghostTextAccepted(const QString& text);
    void ghostTextRejected();

protected:
    void paintEvent(QPaintEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;

private:
    QString m_currentFile;
    QString m_ghostText;
    bool m_hasGhostText = false;
};

} // namespace SoloIDE
