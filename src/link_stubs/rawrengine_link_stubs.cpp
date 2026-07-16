// RawrEngine Link Stubs
// Auto-generated link stubs for RawrEngine.exe

#include <string>
#include <vector>

// CoTFallbackSystem stubs
class CoTFallbackSystem {
public:
    static CoTFallbackSystem& instance() {
        static CoTFallbackSystem inst;
        return inst;
    }
    
    struct PatchResult {
        bool success = true;
        int code = 0;
    };
    
    PatchResult enableCoT() { return PatchResult{}; }
    PatchResult disableCoT(const std::string&) { return PatchResult{}; }
    bool isCoTAvailable() const { return false; }
    
private:
    CoTFallbackSystem() = default;
};

// GPUDispatchGate stubs
namespace RawrXD {
class GPUDispatchGate {
public:
    GPUDispatchGate() = default;
    ~GPUDispatchGate() = default;
    
    bool Initialize() { return false; }
    bool MatVecQ4(const float*, const float*, float*, unsigned int, unsigned int, bool) { return false; }
};
} // namespace RawrXD

// NativeGGUFLoader stubs
struct NativeGGUFTensorInfo {
    std::string name;
    size_t size = 0;
};

struct NativeGGUFMetadata {
    std::string key;
    std::string value;
};

class NativeGGUFLoader {
public:
    NativeGGUFLoader() = default;
    ~NativeGGUFLoader() = default;
    
    bool Open(const std::string&) { return false; }
    void Close() {}
    bool ParseHeader() { return false; }
    bool ParseMetadata() { return false; }
    bool ParseTensorInfo() { return false; }
    bool IsMemoryMapped() const { return false; }
    size_t GetMappedSize() const { return 0; }
    
    const std::vector<NativeGGUFTensorInfo>& GetTensors() const {
        static std::vector<NativeGGUFTensorInfo> empty;
        return empty;
    }
    
    const std::vector<NativeGGUFMetadata>& GetMetadata() const {
        static std::vector<NativeGGUFMetadata> empty;
        return empty;
    }
};

// ExportPrometheus stub
extern "C" void ExportPrometheus(const char*) {}

// Force instantiation to ensure symbols are exported
namespace {
    // These ensure the class methods are actually compiled and exported
    CoTFallbackSystem& _cot_ref = CoTFallbackSystem::instance();
    RawrXD::GPUDispatchGate _gpu_gate;
    NativeGGUFLoader _gguf_loader;
}
