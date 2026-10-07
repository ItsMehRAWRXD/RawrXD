#ifndef QSTRING_H
#define QSTRING_H
#include <string>
#include <algorithm>
class QString {
public:
    QString() = default;
    QString(const char* s) : str_(s ? s : "") {}
    QString(const std::string& s) : str_(s) {}
    operator std::string() const { return str_; }
    operator const char*() const { return str_.c_str(); }
    const char* toStdString() const { return str_.c_str(); }
    static QString fromStdString(const std::string& s) { return QString(s.c_str()); }
    bool isEmpty() const { return str_.empty(); }
    bool isNull() const { return str_.empty(); }
    int size() const { return static_cast<int>(str_.size()); }
    int length() const { return static_cast<int>(str_.size()); }
    bool contains(const QString& other) const { return str_.find(other.str_) != std::string::npos; }
    QString toLower() const { std::string r = str_; std::transform(r.begin(), r.end(), r.begin(), ::tolower); return r.c_str(); }
    QString toUpper() const { std::string r = str_; std::transform(r.begin(), r.end(), r.begin(), ::toupper); return r.c_str(); }
    QString trimmed() const { return str_.c_str(); }
    QString left(int n) const { return str_.substr(0, n).c_str(); }
    QString right(int n) const { return str_.substr(str_.size() - n, n).c_str(); }
    QString mid(int pos, int n = -1) const { return n >= 0 ? str_.substr(pos, n).c_str() : str_.substr(pos).c_str(); }
    int indexOf(const QString& s, int from = 0) const { auto p = str_.find(s.str_, from); return p == std::string::npos ? -1 : static_cast<int>(p); }
    int lastIndexOf(const QString& s, int from = -1) const { auto p = str_.rfind(s.str_, from == -1 ? std::string::npos : from); return p == std::string::npos ? -1 : static_cast<int>(p); }
    bool startsWith(const QString& s) const { return str_.substr(0, s.str_.size()) == s.str_; }
    bool endsWith(const QString& s) const { return str_.size() >= s.str_.size() && str_.substr(str_.size() - s.str_.size()) == s.str_; }
    QString arg(int n) const { return str_.c_str(); }
    QString arg(const QString& a) const { return str_.c_str(); }
    QString arg(const QString& a1, const QString& a2) const { return str_.c_str(); }
    QString arg(int a1, int a2) const { return str_.c_str(); }
    QString& append(const QString& s) { str_ += s.str_; return *this; }
    QString& prepend(const QString& s) { str_ = s.str_ + str_; return *this; }
    QString& insert(int pos, const QString& s) { str_.insert(pos, s.str_); return *this; }
    QString& remove(int pos, int n) { str_.erase(pos, n); return *this; }
    QString& replace(const QString& before, const QString& after) { auto p = str_.find(before.str_); if (p != std::string::npos) str_.replace(p, before.str_.size(), after.str_); return *this; }
    bool operator==(const QString& o) const { return str_ == o.str_; }
    bool operator!=(const QString& o) const { return str_ != o.str_; }
    bool operator<(const QString& o) const { return str_ < o.str_; }
    bool operator>(const QString& o) const { return str_ > o.str_; }
    bool operator<=(const QString& o) const { return str_ <= o.str_; }
    bool operator>=(const QString& o) const { return str_ >= o.str_; }
    bool isNull() const { return str_.empty(); }
    bool isNull() const { return str_.empty(); }
    const char* toLatin1() const { return str_.c_str(); }
    const char* toUtf8() const { return str_.c_str(); }
    QString& setNum(int n) { str_ = std::to_string(n); return *this; }
    QString& setNum(double n) { str_ = std::to_string(n); return *this; }
    int toInt(bool* ok = nullptr, int base = 10) const { try { size_t idx; long v = std::stol(str_, &idx, base); if (ok) *ok = (idx == str_.size()); return static_cast<int>(v); } catch (...) { if (ok) *ok = false; return 0; } }
    double toDouble(bool* ok = nullptr) const { try { size_t idx; double v = std::stod(str_, &idx); if (ok) *ok = (idx == str_.size()); return v; } catch (...) { if (ok) *ok = false; return 0.0; } }
    bool toBool() const { return str_ == "true" || str_ == "1"; }
    static QString number(int n) { return std::to_string(n).c_str(); }
    static QString number(double n) { return std::to_string(n).c_str(); }
    static QString number(double n, char f, int prec) { char buf[64]; snprintf(buf, sizeof(buf), "%.*f", prec, n); return buf; }
private:
    std::string str_;
};
inline bool operator==(const QString& l, const char* r) { return l == QString(r); }
inline bool operator!=(const QString& l, const char* r) { return l != QString(r); }
inline bool operator==(const char* l, const QString& r) { return QString(l) == r; }
inline bool operator!=(const char* l, const QString& r) { return QString(l) != r; }
inline bool operator<(const QString& l, const char* r) { return l < QString(r); }
inline bool operator>(const QString& l, const char* r) { return l > QString(r); }
inline bool operator<=(const QString& l, const char* r) { return l <= QString(r); }
inline bool operator>=(const QString& l, const char* r) { return l >= QString(r); }
inline QString operator+(const QString& l, const QString& r) { QString s = l; s.append(r); return s; }
inline QString operator+(const QString& l, const char* r) { QString s = l; s.append(r); return s; }
inline QString operator+(const char* l, const QString& r) { QString s = l; s.append(r); return s; }
#endif
