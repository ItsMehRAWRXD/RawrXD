#pragma once

#include <QObject>
#include <QString>
#include <QFileInfo>
#include <memory>
#include "compression_interface.h"

class AutonomousModelManager : public QObject {
    Q_OBJECT
    
public:
    explicit AutonomousModelManager(QObject* parent = nullptr);
    
    // Autonomous model loading with compression optimization
    bool loadModelAutonomously(const QString& modelPath);
    
    // Autonomous compression selection based on:
    // - Available memory
    // - CPU capabilities (AVX2, SSE2)
    // - Model size
    // - User preferences
    std::shared_ptr<ICompressionProvider> selectOptimalCompression();
    
    // Monitor and adapt compression settings
    void adaptCompressionSettings(const CompressionStats& stats);
    
signals:
    void modelLoaded(const QString& path, const CompressionStats& stats);
    void compressionOptimized(const QString& method, double ratio);
    
private:
    std::shared_ptr<ICompressionProvider> m_compressionProvider;
    CompressionStats m_stats;
};