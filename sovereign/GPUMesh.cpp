#include "sovereign/GPUMesh.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <chrono>
#include <map>

namespace GPUMesh {
    static std::vector<uint32_t> g_deviceIds;
    static std::mutex g_mutex;
    static DispatchCallback g_dispatchCb;
    static std::map<uint32_t, float> g_deviceUtilization;

    void Init(const std::vector<uint32_t>& deviceIds) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_deviceIds = deviceIds;

        nlohmann::json msg = {
            {"type", "gpu_mesh_init"},
            {"devices", deviceIds},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_GPUMeshInit, {
            {"device_count", deviceIds.size()},
            {"devices", deviceIds}
        });

        Fabric::Instance().RegisterHandler("gpu_mesh_q", OnFabricMessage);
        Fabric::Instance().RegisterHandler("gpu_mesh_k", OnFabricMessage);
        Fabric::Instance().RegisterHandler("gpu_mesh_v", OnFabricMessage);
        Fabric::Instance().RegisterHandler("gpu_mesh_attention", OnFabricMessage);
        Fabric::Instance().RegisterHandler("gpu_mesh_ffn", OnFabricMessage);
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_deviceIds.clear();
        g_deviceUtilization.clear();
    }

    void DispatchQ(const float* input, size_t size, uint32_t targetDevice) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "gpu_mesh_q"},
            {"device", targetDevice},
            {"size", size},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        auto t1 = std::chrono::high_resolution_clock::now();
        float duration = std::chrono::duration<float, std::milli>(t1 - t0).count();

        DispatchRecord rec{targetDevice, GPUStage::Q_DISPATCH, Beaconism::GetTimestamp(), size, duration};
        if (g_dispatchCb) g_dispatchCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GPUMeshDispatch, {
            {"device", targetDevice},
            {"stage", "Q"},
            {"size", size},
            {"duration_ms", duration}
        });
    }

    void DispatchK(const float* input, size_t size, uint32_t targetDevice) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "gpu_mesh_k"},
            {"device", targetDevice},
            {"size", size},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        auto t1 = std::chrono::high_resolution_clock::now();
        float duration = std::chrono::duration<float, std::milli>(t1 - t0).count();

        DispatchRecord rec{targetDevice, GPUStage::K_DISPATCH, Beaconism::GetTimestamp(), size, duration};
        if (g_dispatchCb) g_dispatchCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GPUMeshDispatch, {
            {"device", targetDevice},
            {"stage", "K"},
            {"size", size},
            {"duration_ms", duration}
        });
    }

    void DispatchV(const float* input, size_t size, uint32_t targetDevice) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "gpu_mesh_v"},
            {"device", targetDevice},
            {"size", size},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        auto t1 = std::chrono::high_resolution_clock::now();
        float duration = std::chrono::duration<float, std::milli>(t1 - t0).count();

        DispatchRecord rec{targetDevice, GPUStage::V_DISPATCH, Beaconism::GetTimestamp(), size, duration};
        if (g_dispatchCb) g_dispatchCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GPUMeshDispatch, {
            {"device", targetDevice},
            {"stage", "V"},
            {"size", size},
            {"duration_ms", duration}
        });
    }

    void DispatchAttention(uint32_t targetDevice) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "gpu_mesh_attention"},
            {"device", targetDevice},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        auto t1 = std::chrono::high_resolution_clock::now();
        float duration = std::chrono::duration<float, std::milli>(t1 - t0).count();

        DispatchRecord rec{targetDevice, GPUStage::ATTENTION, Beaconism::GetTimestamp(), 0, duration};
        if (g_dispatchCb) g_dispatchCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GPUMeshDispatch, {
            {"device", targetDevice},
            {"stage", "Attention"},
            {"duration_ms", duration}
        });
    }

    void DispatchFFN(const float* input, size_t size, uint32_t targetDevice) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        nlohmann::json msg = {
            {"type", "gpu_mesh_ffn"},
            {"device", targetDevice},
            {"size", size},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        auto t1 = std::chrono::high_resolution_clock::now();
        float duration = std::chrono::duration<float, std::milli>(t1 - t0).count();

        DispatchRecord rec{targetDevice, GPUStage::FFN, Beaconism::GetTimestamp(), size, duration};
        if (g_dispatchCb) g_dispatchCb(rec);

        Beaconism::Emit(Beaconism::BEACON_GPUMeshDispatch, {
            {"device", targetDevice},
            {"stage", "FFN"},
            {"size", size},
            {"duration_ms", duration}
        });
    }

    void RegisterDispatchCallback(DispatchCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_dispatchCb = cb;
    }

    void UnregisterDispatchCallback() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_dispatchCb = nullptr;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "gpu_mesh_q" || type == "gpu_mesh_k" || type == "gpu_mesh_v" ||
            type == "gpu_mesh_attention" || type == "gpu_mesh_ffn") {
            uint32_t device = msg.value("device", 0);
            g_deviceUtilization[device] = std::min(1.0f, g_deviceUtilization[device] + 0.1f);
        }
    }

    std::vector<uint32_t> GetActiveDevices() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_deviceIds;
    }

    float GetDeviceUtilization(uint32_t deviceId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_deviceUtilization.find(deviceId);
        return (it != g_deviceUtilization.end()) ? it->second : 0.0f;
    }

    void GPUMesh::OnTick() {
        // Periodic GPU mesh maintenance stub
    }

    bool GPUMesh::IsAlive() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return !g_deviceIds.empty();
    }
}
