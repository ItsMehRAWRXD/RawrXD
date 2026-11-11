#pragma once
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantMap>
#include <vector>
#include <memory>

namespace SoloIDE {

struct ModelInfo {
    QString name;
    QString identifier;
    size_t vramRequiredGB;
    bool requiresDualGPU;
};

class MultiModalModelRouter : public QObject {
    Q_OBJECT
public:
    explicit MultiModalModelRouter(QObject* parent = nullptr);
    ~MultiModalModelRouter() override;

    // Model enumeration
    std::vector<ModelInfo> availableModels() const;
    
    // Model lifecycle
    bool loadModel(const QString& identifier);
    void unloadModel();
    bool isModelLoaded() const { return m_loaded; }
    QString activeModelId() const { return m_activeModelId; }

    // Inference routing
    void routeInference(const QVariantMap& request);
    bool isDualGpuLinkBroken() const;
    
    // GPU detection
    int physicalDeviceCount() const;
    size_t primaryVramGB() const;
    size_t secondaryVramGB() const;

signals:
    void modelLoaded(const QString& identifier);
    void modelLoadFailed(const QString& identifier, const QString& reason);
    void inferenceStarted(const QString& source);
    void inferenceCompleted(double tps, bool hadError);
    void fallbackActivated(const QString& reason);

private:
    void probeHardware();
    void routeToPrimaryGpuOnly(const QVariantMap& request);
    void routeToDualGpuPipeline(const QVariantMap& request);

    bool m_loaded = false;
    QString m_activeModelId;
    int m_deviceCount = 0;
    size_t m_primaryVramGB = 0;
    size_t m_secondaryVramGB = 0;
    bool m_p2pLinkBroken = true;
};

} // namespace SoloIDE
