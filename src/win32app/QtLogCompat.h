#pragma once

// Qt logging compatibility for the Qt-free builds.
//
// The native Win32 IDE is deliberately built without Qt (see the
// RawrXD-Win32IDE-Native target in the root CMakeLists.txt), but two
// translation units still carry qt-style logging calls left over from the
// Qt-coupled variant:
//   - src/win32app/Win32IDE_VSCodeUI.cpp  (used to #include <QDebug>)
//   - src/win32app/Win32IDE_Sidebar.cpp
// Those calls fail to compile with "qInfo/qDebug/qWarning/qCritical/qError:
// identifier not found". This shim routes them to the IDE's real logger
// (IDELogger, which writes .\RawrXD_IDE.log) instead of being dropped.
//
// When Qt IS available the real Qt categories win, so nothing changes for the
// Qt-coupled target.

#include <sstream>

#if defined(QT_CORE_LIB) || defined(Q_QDOC)

#include <QDebug>

#else

#include "IDELogger.h"

namespace rawrxd_logshim {

// Stream-style sink that mirrors qDebug()/qInfo() semantics: accumulate the
// message, then flush to the log exactly once when the temporary dies.
class LogStream {
public:
    explicit LogStream(IDELogger::Level level) : m_level(level) {}
    ~LogStream() {
        IDELogger::getInstance().log(m_level, "IDE", m_stream.str());
    }

    LogStream(const LogStream&) = delete;
    LogStream& operator=(const LogStream&) = delete;

    template <typename T>
    LogStream& operator<<(const T& value) {
        m_stream << value;
        return *this;
    }

    // Qt stream manipulators (std::endl, "\n", Qt::endl, ...) pass through.
    LogStream& operator<<(std::ostream& (*manip)(std::ostream&)) {
        manip(m_stream);
        return *this;
    }

private:
    IDELogger::Level m_level;
    std::ostringstream m_stream;
};

} // namespace rawrxd_logshim

#define qDebug()    rawrxd_logshim::LogStream(IDELogger::Level::DEBUG)
#define qInfo()     rawrxd_logshim::LogStream(IDELogger::Level::INFO)
#define qWarning()  rawrxd_logshim::LogStream(IDELogger::Level::WARNING)
#define qCritical() rawrxd_logshim::LogStream(IDELogger::Level::CRITICAL)
#define qError()    rawrxd_logshim::LogStream(IDELogger::Level::ERR)

#endif // QT_CORE_LIB
