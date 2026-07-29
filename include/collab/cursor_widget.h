<<<<<<< HEAD
#ifndef CURSOR_WIDGET_H
#define CURSOR_WIDGET_H

// C++20 / Win32. Presence cursor widget; no Qt. RGB color as uint32_t.

#include <string>
#include <map>
#include <cstdint>

struct CursorInfo {
    int position = 0;
    std::string userName;
    uint32_t color = 0;  // 0xRRGGBB
};

class CursorWidget
{
public:
    CursorWidget() = default;

    void updateCursor(const std::string& userId, const CursorInfo& info);
    void removeCursor(const std::string& userId);

    void* getWidgetHandle() const { return m_handle; }
    void setWidgetHandle(void* h) { m_handle = h; }

private:
    void* m_handle = nullptr;
    std::map<std::string, CursorInfo> m_cursors;
};

#endif // CURSOR_WIDGET_H
=======
#ifndef CURSOR_WIDGET_H
#define CURSOR_WIDGET_H

#include <QWidget>
#include <QMap>
#include <QColor>
#include <QString>

// Presence: cursor position, user name, avatar color
class CursorWidget : public QWidget
{
    Q_OBJECT

public:
    explicit CursorWidget(QWidget *parent = nullptr);

    struct CursorInfo {
        int position;
        QString userName;
        QColor color;
    };

    // Add or update a cursor
    void updateCursor(const QString &userId, const CursorInfo &info);

    // Remove a cursor
    void removeCursor(const QString &userId);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QMap<QString, CursorInfo> m_cursors;
};

#endif // CURSOR_WIDGET_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
