// ============================================================================
// gguf_d3d12_bridge_stub.cpp - Stub implementation for GGUFD3D12Bridge
// ============================================================================
// This provides minimal stub implementations for D3D12 GPU dispatch functions
// that are referenced but not yet fully implemented.
// ============================================================================

#include <windows.h>
#include <d3d12.h>
#include <string>
#include <vector>
#include <wrl/client.h>

namespace RawrXD {

struct TensorInfo {
    std::string name;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
};

class GGUFD3D12Bridge {
public:
    GGUFD3D12Bridge() = default;
    ~GGUFD3D12Bridge() = default;

    bool Initialize(ID3D12Device* device, ID3D12CommandQueue* queue) {
        (void)device;
        (void)queue;
        OutputDebugStringA("[GGUFD3D12Bridge] Initialize stub called\n");
        return true;
    }

    void Shutdown() {
        OutputDebugStringA("[GGUFD3D12Bridge] Shutdown stub called\n");
    }

    bool LoadShadersFromDirectory(const std::string& path) {
        (void)path;
        OutputDebugStringA("[GGUFD3D12Bridge] LoadShadersFromDirectory stub called\n");
        return true;
    }

    bool UploadGGUFTensor(const TensorInfo& info, const std::vector<uint8_t>& data,
                          Microsoft::WRL::ComPtr<ID3D12Resource>& outResource) {
        (void)info;
        (void)data;
        (void)outResource;
        OutputDebugStringA("[GGUFD3D12Bridge] UploadGGUFTensor stub called\n");
        return true;
    }

    bool DispatchMatVecQ4(ID3D12Resource* input, ID3D12Resource* weights,
                          ID3D12Resource* output, uint32_t rows, uint32_t cols) {
        (void)input;
        (void)weights;
        (void)output;
        (void)rows;
        (void)cols;
        OutputDebugStringA("[GGUFD3D12Bridge] DispatchMatVecQ4 stub called\n");
        return true;
    }

    bool DispatchRMSNorm(ID3D12Resource* input, ID3D12Resource* output,
                         uint32_t count, float epsilon) {
        (void)input;
        (void)output;
        (void)count;
        (void)epsilon;
        OutputDebugStringA("[GGUFD3D12Bridge] DispatchRMSNorm stub called\n");
        return true;
    }

    bool DispatchSoftmax(ID3D12Resource* buffer, uint32_t count) {
        (void)buffer;
        (void)count;
        OutputDebugStringA("[GGUFD3D12Bridge] DispatchSoftmax stub called\n");
        return true;
    }

    bool ReadbackBuffer(ID3D12Resource* resource, void* data, uint64_t size) {
        (void)resource;
        (void)data;
        (void)size;
        OutputDebugStringA("[GGUFD3D12Bridge] ReadbackBuffer stub called\n");
        return true;
    }
};

} // namespace RawrXD
