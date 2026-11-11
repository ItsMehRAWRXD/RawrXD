#include "MultiModalModelRouter.hpp"
#include "../Core/Bus.hpp"
#include <QElapsedTimer>
#include <QDebug>
#include <cstdio>
#include <cstdlib>

// ---------------------------------------------------------------------------
// Weak-linked Vulkan probe symbols (same pattern as gpu_enforcement.cpp)
// ---------------------------------------------------------------------------
extern "C" {
    int  ggml_backend_vk_get_device_count(void);
    void ggml_backend_vk_get_device_memory(int device, size_t* free, size_t* total);
}

#if defined(_MSC_VER)
extern "C" int  rxd_solo_vk_count_stub(void) { return 0; }
extern "C" void rxd_solo_vk_mem_stub(int, size_t* f, size_t* t) { if (f) *f = 0; if (t) *t = 0; }
#pragma comment(linker, "/alternatename:ggml_backend_vk_get_device_count=rxd_solo_vk_count_stub")
#pragma comment(linker, "/alternatename:ggml_backend_vk_get_device_memory=rxd_solo_vk_mem_stub")
#endif

namespace SoloIDE {

MultiModalModelRouter::MultiModalModelRouter(QObject* parent)
    : QObject(parent)
{
    probeHardware();
}

MultiModalModelRouter::~MultiModalModelRouter() = default;

// ---------------------------------------------------------------------------
// Hardware probe
// ---------------------------------------------------------------------------
void MultiModalModelRouter::probeHardware() {
    m_deviceCount = ggml_backend_vk_get_device_count();
    qDebug() << "[Router] Vulkan devices detected:" << m_deviceCount;

    if (m_deviceCount >= 1) {
        size_t freeMem = 0, totalMem = 0;
        ggml_backend_vk_get_device_memory(0, &freeMem, &totalMem);
        m_primaryVramGB = totalMem / (1024ULL * 1024ULL * 1024ULL);
        qDebug() << "[Router] GPU0 VRAM:" << m_primaryVramGB << "GB";
    }

    if (m_deviceCount >= 2) {
        size_t freeMem = 0, totalMem = 0;
        ggml_backend_vk_get_device_memory(1, &freeMem, &totalMem);
        m_secondaryVramGB = totalMem / (1024ULL * 1024ULL * 1024ULL);
        qDebug() << "[Router] GPU1 VRAM:" << m_secondaryVramGB << "GB";

        // P2P link is broken if secondary reports 0 VRAM or matches primary
        m_p2pLinkBroken = (m_secondaryVramGB == 0) || (m_secondaryVramGB == m_primaryVramGB);
    } else {
        m_p2pLinkBroken = true;
    }

    if (m_p2pLinkBroken) {
        qDebug() << "[Router] P2P link broken or secondary GPU absent — single-GPU fallback active";
    }
}

bool MultiModalModelRouter::isDualGpuLinkBroken() const {
    return m_p2pLinkBroken;
}

int MultiModalModelRouter::physicalDeviceCount() const {
    return m_deviceCount;
}

size_t MultiModalModelRouter::primaryVramGB() const {
    return m_primaryVramGB;
}

size_t MultiModalModelRouter::secondaryVramGB() const {
    return m_secondaryVramGB;
}

// ---------------------------------------------------------------------------
// Model enumeration
// ---------------------------------------------------------------------------
std::vector<ModelInfo> MultiModalModelRouter::availableModels() const {
    return {
        {"Sovereign Dual-GPU Cluster",  "sovereign-dual",   64, true},
        {"R9700 Local Primary",         "r9700-primary",    48, false},
        {"7800XT Local Secondary",      "7800xt-secondary", 16, false},
        {"Cloud Fallback Engine",       "cloud-fallback",   0,  false}
    };
}

// ---------------------------------------------------------------------------
// Model lifecycle
// ---------------------------------------------------------------------------
bool MultiModalModelRouter::loadModel(const QString& identifier) {
    qDebug() << "[Router] Loading model:" << identifier;

    // Check if this model requires dual-GPU but link is broken
    auto models = availableModels();
    for (const auto& m : models) {
        if (m.identifier == identifier && m.requiresDualGPU && m_p2pLinkBroken) {
            QString reason = "Dual-GPU P2P link unavailable — falling back to single-GPU mode";
            qWarning() << "[Router]" << reason;
            fallbackActivated(reason);
            // Still load, but route will use fallback
            break;
        }
    }

    m_activeModelId = identifier;
    m_loaded = true;
    emit modelLoaded(identifier);
    return true;
}

void MultiModalModelRouter::unloadModel() {
    m_loaded = false;
    m_activeModelId.clear();
}

// ---------------------------------------------------------------------------
// Inference routing with broken-link safety
// ---------------------------------------------------------------------------
void MultiModalModelRouter::routeInference(const QVariantMap& request) {
    Q_UNUSED(request);

    auto* bus = IntegrationBus::instance();

    BusMessage startMsg{Channel::GPUInferenceStart, "Router", "UI", QVariant(), 0};
    bus->publish(startMsg);

    QElapsedTimer timer;
    timer.start();

    try {
        if (m_p2pLinkBroken) {
            routeToPrimaryGpuOnly(request);
        } else {
            routeToDualGpuPipeline(request);
        }
    } catch (...) {
        qWarning() << "[Router] Inference exception caught — emitting error";
        QVariantMap errPayload;
        errPayload["tps"] = 0.0;
        errPayload["error"] = true;
        BusMessage errMsg{Channel::GPUInferenceDone, "Router", "UI", QVariant(errPayload), 0};
        bus->publish(errMsg);
        return;
    }

    double elapsed = static_cast<double>(timer.elapsed()) / 1000.0;
    double tps = (elapsed > 0.0) ? (100.0 / elapsed) : 0.0; // simulated 100 tokens

    QVariantMap payload;
    payload["tps"] = tps;
    payload["error"] = false;
    BusMessage doneMsg{Channel::GPUInferenceDone, "Router", "UI", QVariant(payload), 0};
    bus->publish(doneMsg);

    emit inferenceCompleted(tps, false);
}

void MultiModalModelRouter::routeToPrimaryGpuOnly(const QVariantMap& request) {
    Q_UNUSED(request);
    qDebug() << "[Router] Routing to primary GPU (R9700) — single-GPU mode";
    // In production: dispatch to ggml_vulkan backend device 0
    // For now, simulated compute
}

void MultiModalModelRouter::routeToDualGpuPipeline(const QVariantMap& request) {
    Q_UNUSED(request);
    qDebug() << "[Router] Routing to dual-GPU pipeline (R9700 + 7800XT)";
    // In production: split 22/10 layers across devices 0 and 1
    // For now, simulated compute
}

} // namespace SoloIDE
