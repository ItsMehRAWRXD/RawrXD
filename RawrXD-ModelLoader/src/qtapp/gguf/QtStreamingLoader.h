#pragma once
#include <QObject>
#include <QString>
#include <QByteArray>
#include <QVector>

// Thin Qt adapter over core StreamingGGUFLoader to emit signals.
class QtStreamingLoader : public QObject {
    Q_OBJECT
public:
    explicit QtStreamingLoader(QObject* parent = nullptr);

    Q_INVOKABLE bool open(const QString& filepath);
    Q_INVOKABLE void close();
    Q_INVOKABLE bool loadZone(const QString& zoneName, quint64 maxMemoryMB = 512);
    Q_INVOKABLE bool unloadZone(const QString& zoneName);
    Q_INVOKABLE bool getTensorData(const QString& tensorName, QByteArray& outData);

signals:
    void opened(const QString& file, quint64 fileSize);
    void closed();
    void zoneLoaded(const QString& zoneName, quint64 bytesLoaded);
    void zoneUnloaded(const QString& zoneName);
    void tensorChunk(const QString& tensorName, QByteArray chunk);
    void error(const QString& message);
    void memoryStats(quint64 currentMB, quint64 maxMB);

private:
    // Pointer to core loader (opaque to Qt).
    void* m_loader{nullptr};
    quint64 m_maxZoneMB{512};
};
