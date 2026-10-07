#ifndef QJSON_H
#define QJSON_H
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <variant>
#include <memory>
namespace Qt {
enum ConnectionType { AutoConnection, DirectConnection, QueuedConnection, BlockingQueuedConnection, UniqueConnection = 0x80 };
enum WindowFlags { Window = 0x00000001 };
enum AlignmentFlag { AlignLeft = 0x0001, AlignRight = 0x0002, AlignHCenter = 0x0004, AlignVCenter = 0x0080 };
enum ItemDataRole { DisplayRole = 0, UserRole = 0x0100 };
using Alignment = int;
using WindowType = int;
}
class QJsonValue {
public:
    enum Type { Null = 0, Bool, Double, String, Array, Object, Undefined };
    QJsonValue() : type_(Null) {}
    QJsonValue(bool b) : type_(Bool), value_(b) {}
    QJsonValue(int i) : type_(Double), value_(static_cast<double>(i)) {}
    QJsonValue(double d) : type_(Double), value_(d) {}
    QJsonValue(const char* s) : type_(String), value_(std::string(s ? s : "")) {}
    QJsonValue(const std::string& s) : type_(String), value_(s) {}
    Type type() const { return type_; }
    bool isNull() const { return type_ == Null; }
    bool isBool() const { return type_ == Bool; }
    bool isDouble() const { return type_ == Double; }
    bool isString() const { return type_ == String; }
    bool isArray() const { return type_ == Array; }
    bool isObject() const { return type_ == Object; }
    bool isUndefined() const { return type_ == Undefined; }
    bool toBool() const { return std::get<bool>(value_); }
    double toDouble() const { return std::get<double>(value_); }
    int toInt() const { return static_cast<int>(std::get<double>(value_)); }
    std::string toString() const { return std::get<std::string>(value_); }
    QJsonValue operator[](const std::string& key) const;
    QJsonValue operator[](int i) const;
private:
    Type type_;
    std::variant<bool, double, std::string, std::vector<QJsonValue>, std::map<std::string, QJsonValue>> value_;
};
class QJsonObject {
public:
    using Iterator = std::map<std::string, QJsonValue>::iterator;
    using ConstIterator = std::map<std::string, QJsonValue>::const_iterator;
    QJsonObject() = default;
    QJsonValue operator[](const std::string& key) const { auto it = data.find(key); return it != data.end() ? it->second : QJsonValue(); }
    QJsonValue& operator[](const std::string& key) { return data[key]; }
    bool contains(const std::string& key) const { return data.count(key); }
    int size() const { return static_cast<int>(data.size()); }
    bool empty() const { return data.empty(); }
    Iterator begin() { return data.begin(); }
    Iterator end() { return data.end(); }
    ConstIterator begin() const { return data.cbegin(); }
    ConstIterator end() const { return data.cend(); }
    ConstIterator find(const std::string& key) const { return data.find(key); }
    Iterator find(const std::string& key) { return data.find(key); }
    void insert(const std::string& key, const QJsonValue& val) { data[key] = val; }
    void remove(const std::string& key) { data.erase(key); }
    std::vector<std::string> keys() const { std::vector<std::string> r; for (auto& kv : data) r.push_back(kv.first); return r; }
    std::map<std::string, QJsonValue> data;
};
class QJsonArray {
public:
    using Iterator = std::vector<QJsonValue>::iterator;
    using ConstIterator = std::vector<QJsonValue>::const_iterator;
    QJsonArray() = default;
    QJsonValue operator[](int i) const { return data.at(i); }
    QJsonValue& operator[](int i) { return data.at(i); }
    int size() const { return static_cast<int>(data.size()); }
    bool empty() const { return data.empty(); }
    void append(const QJsonValue& v) { data.push_back(v); }
    void prepend(const QJsonValue& v) { data.insert(data.begin(), v); }
    void insert(int i, const QJsonValue& v) { data.insert(data.begin() + i, v); }
    void removeAt(int i) { data.erase(data.begin() + i); }
    void removeFirst() { if (!data.empty()) data.erase(data.begin()); }
    void removeLast() { if (!data.empty()) data.pop_back(); }
    Iterator begin() { return data.begin(); }
    Iterator end() { return data.end(); }
    ConstIterator begin() const { return data.cbegin(); }
    ConstIterator end() const { return data.cend(); }
    std::vector<QJsonValue> data;
};
inline QJsonValue QJsonValue::operator[](const std::string& key) const {
    if (type_ == Object) return std::get<std::map<std::string, QJsonValue>>(value_).at(key);
    if (type_ == Array) return std::get<std::vector<QJsonValue>>(value_).at(0);
    return QJsonValue();
}
inline QJsonValue QJsonValue::operator[](int i) const {
    if (type_ == Array) return std::get<std::vector<QJsonValue>>(value_).at(i);
    if (type_ == Object) return std::get<std::map<std::string, QJsonValue>>(value_).begin()->second;
    return QJsonValue();
}
#endif
