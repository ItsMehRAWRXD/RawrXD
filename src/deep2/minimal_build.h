#pragma once

// Forward declarations for Vulkan types needed by q4_0_gpu_parity_test
struct VkBuffer_T;
struct VkDeviceMemory_T;
struct VkDeviceSize;
typedef struct VkBuffer_T* VkBuffer;
typedef void* VkDeviceMemory;

// Minimal DeviceBuf struct - subset needed for q4_0_gpu_parity_test
struct DeviceBuf {
    void* buffer = nullptr;
    void* memory = nullptr;
    size_t size = 0;
    int memoryFlags = 0;
    uint64_t id = 0;
    explicit operator bool() const noexcept {
        return buffer != nullptr && memory != nullptr && size != 0;
    }
};

// Minimal VulkanCompute forward declaration
namespace Deep2 {
    class VulkanCompute {
    public:
        VulkanCompute(uint32_t physicalOrdinal = 0);
        ~VulkanCompute();
        
        bool initialize();
        void cleanup();
        
        struct PhysicalInfo {
            const char* name = "";
            bool computeReady = false;
        };
        PhysicalInfo physicalInfo() { return PhysicalInfo(); }
        bool computeReady() { return false; }
        
        // Minimal DispatchGemvQuant declaration
        bool DispatchGemvQuant(int type, void* weightBuf, size_t weightBytes,
                               void* inputBuf, void* outputBuf, uint32_t rows, uint32_t cols, uint32_t cacheKey) {
            return false;
        }
    };
}

// Q4_0 block reference dequantization (from test file)
#pragma pack(push, 1)
struct block_q4_0 {
    float d;              // FP16 scale (4 bytes)
    uint8_t qs[8];        // 16 nibbles packed into 8 bytes
    uint8_t padding[6];   // Padding to 18 bytes
};
static_assert(sizeof(block_q4_0) == 18, "block_q4_0 must be 18 bytes");
#pragma pack(pop)

static void dequantize_row_q4_0_reference(const block_q4_0* blocks, float* output, size_t num_blocks) {
    for (size_t b = 0; b < num_blocks; ++b) {
        const block_q4_0& block = blocks[b];
        float scale = block.d;
        for (int i = 0; i < 8; ++i) {
            uint8_t byte = block.qs[i];
            int low_nibble = byte & 0x0F;
            float low_weight = (low_nibble - 8) * scale;
            output[b * 16 + i * 2 + 0] = low_weight;
            int high_nibble = (byte >> 4) & 0x0F;
            float high_weight = (high_nibble - 8) * scale;
            output[b * 16 + i * 2 + 1] = high_weight;
        }
    }
}