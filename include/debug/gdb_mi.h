<<<<<<< HEAD
#ifndef GDB_MI_H
#define GDB_MI_H

// C++20, no Qt. Minimal GDB/MI parser. Returns JSON as std::string.

#include <string>

class GdbMI
{
public:
    static std::string parseOutputRecord(const std::string& record);
    static std::string parseResultRecord(const std::string& record);
    static std::string parseAsyncRecord(const std::string& record);

private:
    static std::string parseCString(const std::string& str, size_t& index);
    static std::string parseTuple(const std::string& str, size_t& index);
    static std::string parseList(const std::string& str, size_t& index);
    static std::string parseResult(const std::string& str, size_t& index);
};

#endif // GDB_MI_H
=======
#ifndef GDB_MI_H
#define GDB_MI_H

#include <QString>
#include <QJsonObject>
#include <QJsonArray>

// Minimal GDB/MI parser
class GdbMI
{
public:
    // Parse a GDB/MI output record
    static QJsonObject parseOutputRecord(const QString &record);

    // Parse a GDB/MI result record
    static QJsonObject parseResultRecord(const QString &record);

    // Parse a GDB/MI async record
    static QJsonObject parseAsyncRecord(const QString &record);

private:
    // Helper functions for parsing
    static QString parseCString(const QString &str, int &index);
    static QJsonArray parseTuple(const QString &str, int &index);
    static QJsonArray parseList(const QString &str, int &index);
    static QJsonObject parseResult(const QString &str, int &index);
};

#endif // GDB_MI_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
