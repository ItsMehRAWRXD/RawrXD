#include "EditorPanel.hpp"
#include <QPainter>
#include <QKeyEvent>
#include <QTextCursor>
#include <QDebug>

namespace SoloIDE {

EditorPanel::EditorPanel(QWidget* parent)
    : QPlainTextEdit(parent)
{
    setTabStopDistance(fontMetrics().horizontalAdvance(' ') * 4);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFont(QFont("Consolas", 11));
}

EditorPanel::~EditorPanel() = default;

QPoint EditorPanel::cursorPosition() const {
    QTextCursor c = textCursor();
    return QPoint(c.columnNumber(), c.blockNumber());
}

QString EditorPanel::selectedText() const {
    return textCursor().selectedText();
}

int EditorPanel::currentLine() const {
    return textCursor().blockNumber() + 1;
}

void EditorPanel::showGhostText(const QString& text) {
    m_ghostText = text;
    m_hasGhostText = true;
    viewport()->update();
}

void EditorPanel::setGhostText(const QString& text) {
    showGhostText(text);
}

void EditorPanel::acceptGhostText() {
    if (!m_hasGhostText) return;
    QTextCursor c = textCursor();
    c.insertText(m_ghostText);
    m_hasGhostText = false;
    m_ghostText.clear();
    emit ghostTextAccepted(m_ghostText);
    viewport()->update();
}

void EditorPanel::rejectGhostText() {
    if (!m_hasGhostText) return;
    m_hasGhostText = false;
    m_ghostText.clear();
    emit ghostTextRejected();
    viewport()->update();
}

void EditorPanel::clearGhostText() {
    rejectGhostText();
}

void EditorPanel::paintEvent(QPaintEvent* event) {
    QPlainTextEdit::paintEvent(event);

    if (!m_hasGhostText || m_ghostText.isEmpty()) return;

    QPainter painter(viewport());
    painter.setPen(QColor(128, 128, 128, 160));
    QFont f = font();
    f.setItalic(true);
    painter.setFont(f);

    QTextCursor c = textCursor();
    QRect r = cursorRect();
    painter.drawText(r.topLeft() + QPoint(0, r.height()), m_ghostText);
}

void EditorPanel::keyPressEvent(QKeyEvent* event) {
    if (event->key() == Qt::Key_Tab && m_hasGhostText) {
        acceptGhostText();
        return;
    }
    if (event->key() == Qt::Key_Escape && m_hasGhostText) {
        rejectGhostText();
        return;
    }
    QPlainTextEdit::keyPressEvent(event);
    // Clear ghost on any other key
    if (m_hasGhostText) clearGhostText();
}

} // namespace SoloIDE
