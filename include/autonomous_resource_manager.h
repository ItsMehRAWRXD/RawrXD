#pragma once

#include <QObject>
#include <QString>
#include <cstdint>

class AutonomousResourceManager : public QObject {
    Q_OBJECT
    
public:
    explicit AutonomousResourceManager(QObject* parent = nullptr);
    
    // Monitor system resources
    struct SystemResources {
        uint64_t available_memory;
        uint32_t cpu_usage_percent;
        uint32_t gpu_usage_percent;
        uint64_t disk_space_available;
    };
    
    SystemResources getCurrentResources();
    
    // Autonomous decisions based on resources
    bool canLoadModel(const QString& modelPath, const SystemResources& resources);
    uint32_t getOptimalThreadCount();
    bool shouldUseCompression(const SystemResources& resources) const;
    Q_INVOKABLE bool shouldUseCompression() const;
    
    static AutonomousResourceManager* instance();
    
signals:
    void resourcesLow(const SystemResources& resources);
    void resourcesOptimal();
    
private:
    SystemResources m_lastResources;
};