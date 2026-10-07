#ifndef QOBJECT_H
#define QOBJECT_H
#define Q_OBJECT
#define Q_SIGNALS public
#define Q_SLOTS
#define signals Q_SIGNALS
#define slots Q_SLOTS
#define emit
#define Q_INVOKABLE
#define Q_PROPERTY(...)
#define Q_CLASSINFO(...)
#define Q_DISABLE_COPY(...)
#define Q_DECLARE_METATYPE(...)
#define Q_DECLARE_FLAGS(...)
#define Q_DECLARE_OPERATORS_FOR_FLAGS(...)
#define Q_DECLARE_PRIVATE(...)
#define Q_DECLARE_PUBLIC(...)
#define Q_OBJECT_CHECK(...)
#define Q_SCRIPTABLE
#define Q_REQUIRED_RESULT
class QObject {
public:
    QObject() = default;
    virtual ~QObject() = default;
    QObject(QObject* parent) : parent_(parent) {}
    QObject* parent() const { return parent_; }
    bool inherits(const char* className) const { return false; }
    const char* metaObject() const { return nullptr; }
    void* qt_metacast(const char* clname) { return nullptr; }
    int qt_metacall(QMetaObject::Call, int, void**) { return 0; }
    struct Connection {};
    static bool connect(const QObject*, const char*, const QObject*, const char*, Qt::ConnectionType) { return true; }
    static bool disconnect(const QObject*, const char*, const QObject*, const char*) { return true; }
    static QString tr(const char*, const char* = nullptr, int = -1) { return {}; }
private:
    QObject* parent_{nullptr};
};
#endif
