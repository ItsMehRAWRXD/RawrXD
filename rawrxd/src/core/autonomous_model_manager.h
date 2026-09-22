#pragma once
// ============================================================================
// autonomous_model_manager.h
// ============================================================================
// Reconstructed header from recovered .cpp usage patterns.
// Provides minimal forward-declared types + full AutonomousModelManager class.
//
// NOTE: ICompressionProvider / CompressionFactory are minimal stubs
//       sufficient for the current usage in autonomous_model_manager.cpp.
//       Full implementations can be swapped in later.
// ============================================================================

#include <QObject>
#include <QString>
#include <QJsonArray>
#include <QJsonObject>
#include <memory>
#include <string>

// Minimal compression provider interface
class ICompressionProvider {
public:
    virtual ~ICompressionProvider() = default;
    virtual bool IsSupported() const = 0;
    virtual std::string GetActiveKernel() const = 0;
};

// Minimal factory
class CompressionFactory {
public:
    static std::shared_ptr<ICompressionProvider> Create(int level);
private:
    CompressionFactory() = delete;
};

struct CompressionStats {
    uint64_t decompression_calls = 0;
    double avg_compression_ratio = 0.0;
};

struct SystemAnalysis {
    qint64 availableRAM = 0;
    qint64 availableDiskSpace = 0;
    int cpuCores = 0;
    bool hasGPU = false;
    QString gpuType;
    qint64 gpuMemory = 0;
};

struct ModelRecommendation {
    QString modelId;
    QString name;
    double suitabilityScore = 0.0;
    QString reasoning;
    QString taskType;
    qint64 estimatedMemoryUsage = 0;
    qint64 estimatedDownloadSize = 0;
};

class AutonomousModelManager : public QObject {
    Q_OBJECT

public:
    explicit AutonomousModelManager(QObject* parent = nullptr);
    ~AutonomousModelManager();

    bool loadModelAutonomously(const QString& modelPath);
    std::shared_ptr<ICompressionProvider> selectOptimalCompression();
    void adaptCompressionSettings(const CompressionStats& stats);
    QJsonArray getAvailableModels();
    ModelRecommendation autoDetectBestModel(const QString& taskType, const QString& language);
    SystemAnalysis analyzeSystemCapabilities();
    ModelRecommendation recommendModelForCodebase(const QString& projectPath);

signals:
    void modelLoaded(const QString& modelPath, const CompressionStats& stats);
    void compressionOptimized(const QString& strategy, double ratio);

private:
    std::shared_ptr<ICompressionProvider> m_compressionProvider;
    CompressionStats m_stats;
    SystemAnalysis currentSystem;
    QJsonArray availableModels;
};
