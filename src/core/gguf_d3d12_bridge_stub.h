// ============================================================================
// gguf_d3d12_bridge_stub.h - Stub header for GGUFD3D12Bridge
// ============================================================================
#pragma once

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
    GGUFD3D12Bridge();
    ~GGUFD3D12Bridge();

    bool Initialize(ID3D12Device* device, ID3D12CommandQueue* queue);
    void Shutdown();

    bool LoadShadersFromDirectory(const std::string& path);
    bool UploadGGUFTensor(const TensorInfo& info, const std::vector<uint8_t>& data,
                          Microsoft::WRL::ComPtr<ID3D12Resource>& outResource);
    bool DispatchMatVecQ4(ID3D12Resource* input, ID3D12Resource* weights,
                          ID3D12Resource* output, uint32_t rows, uint32_t cols);
    bool DispatchRMSNorm(ID3D12Resource* input, ID3D12Resource* output,
                         uint32_t count, float epsilon);
    bool DispatchSoftmax(ID3D12Resource* buffer, uint32_t count);
    bool ReadbackBuffer(ID3D12Resource* resource, void* data, uint64_t size);
};

} // namespace RawrXD
