// ============================================================================
// Deep2.h - Deep2 Engine Interface
// High-performance inference engine for MoE models
// Zero dependencies - pure x64 MASM + C++
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>

// ============================================================================
// Platform Detection
// ============================================================================
#ifdef _WIN32
    #define DEEP2_API extern "C" __declspec(dllexport)
#else
    #define DEEP2_API extern "C"
#endif

// ============================================================================
// Assembly Kernel Declarations
// ============================================================================
extern "C" {
    // Vector dot product: out = sum(a[i] * b[i])
    // n must be multiple of 8 (AVX2 processes 8 floats at a time)
    void Deep2_VecDotProduct(float* a, float* b, float* out, size_t n);
    
    // SwiGLU activation: out = (x * sigmoid(x)) * y
    // n must be multiple of 8
    void Deep2_SwiGLU(float* x, float* y, float* out, size_t n);
    
    // RMS Normalization
    // n must be multiple of 8
    void Deep2_RMSNorm(float* x, float* out, size_t n, float eps);
}

// ============================================================================
// Deep2 Engine Class
// ============================================================================
namespace Deep2 {

    // Engine configuration
    struct Config {
        size_t hiddenDim = 7168;        // Hidden dimension size
        size_t numExperts = 256;        // Number of MoE experts
        size_t expertsPerToken = 8;     // Active experts per token
        size_t numLayers = 61;          // Number of transformer layers
        float eps = 1e-6f;              // Epsilon for numerical stability
        bool useAVX2 = true;            // Enable AVX2 optimizations
        bool useAVX512 = false;         // Enable AVX512 (if available)
    };
    
    // Expert routing result
    struct ExpertRouting {
        int32_t expertIds[8];           // Top-k expert indices
        float weights[8];               // Routing weights
        int32_t numExperts;             // Actual number of experts selected
    };
    
    // Inference context
    class Context {
    public:
        Context();
        ~Context();
        
        // Initialize with configuration
        bool Initialize(const Config& config);
        
        // Check if engine is ready
        bool IsReady() const { return m_initialized; }
        
        // Run forward pass
        void Forward(const float* input, float* output, size_t tokenCount);
        
        // Expert routing
        void RouteExperts(const float* input, ExpertRouting* routing, size_t count);
        
        // Get last error message
        const char* GetLastError() const { return m_lastError; }
        
    private:
        bool m_initialized = false;
        Config m_config;
        char m_lastError[256] = {0};
        
        // Aligned buffers for AVX operations
        float* m_scratchBuffer = nullptr;
        size_t m_scratchSize = 0;
        
        bool AllocateBuffers();
        void FreeBuffers();
    };
    
    // Utility functions
    namespace Utils {
        // Allocate 32-byte aligned memory for AVX
        float* AlignedAlloc(size_t count);
        void AlignedFree(float* ptr);
        
        // Check CPU features
        bool HasAVX2();
        bool HasAVX512();
        
        // Copy with alignment check
        void AlignedCopy(float* dst, const float* src, size_t count);
        
        // Initialize random weights (for testing)
        void InitRandom(float* data, size_t count, float scale = 0.02f);
        
        // Zero memory
        void Zero(float* data, size_t count);
    }
    
    // Performance metrics
    namespace Perf {
        struct Metrics {
            uint64_t cyclesStart = 0;
            uint64_t cyclesEnd = 0;
            double elapsedMs = 0.0;
            
            void Start();
            void Stop();
            double GetCycles() const { return static_cast<double>(cyclesEnd - cyclesStart); }
        };
        
        // Read Time-Stamp Counter
        uint64_t ReadTSC();
        
        // Calibrate TSC to milliseconds
        double TSCtoMs(uint64_t cycles);
    }
}

// ============================================================================
// Legacy C Interface (for backward compatibility)
// ============================================================================
extern "C" {
    // Engine lifecycle
    DEEP2_API void* Deep2_CreateEngine();
    DEEP2_API void Deep2_DestroyEngine(void* engine);
    DEEP2_API int Deep2_Initialize(void* engine, const Deep2::Config* config);
    
    // Inference
    DEEP2_API void Deep2_Forward(void* engine, const float* input, float* output, size_t count);
    DEEP2_API void Deep2_RouteExperts(void* engine, const float* input, Deep2::ExpertRouting* routing, size_t count);
    
    // Utilities
    DEEP2_API int Deep2_HasAVX2();
    DEEP2_API int Deep2_HasAVX512();
    DEEP2_API float* Deep2_AlignedAlloc(size_t count);
    DEEP2_API void Deep2_AlignedFree(float* ptr);
}
