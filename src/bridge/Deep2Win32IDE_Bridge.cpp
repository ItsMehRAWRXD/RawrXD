//==============================================================================
// Deep2Win32IDE_Bridge.cpp
// Bridge between Deep2 Inference Engine and Win32IDE Native UI
// Phase 15B: Real Executable Build - Cyclonic Flow Integration
//
// This module connects the Deep2Engine (model inference) to the Win32IDE
// native windowing system via memory-mapped ring buffers (RXIP protocol).
// No Qt. No Electron. Pure Win32 + MASM64.
//==============================================================================

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>

// Deep2 Engine headers
#include "../deep2/Deep2Engine.h"
#include "../deep2/Deep2InferenceGateway.h"

// Win32IDE headers
#include "Win32IDE_Helpers.h"
#include "Integration_Wiring.h"

// ASM bridge (MASM64)
extern "C" {
    // From canonical_moonshot_engine.asm
    ULONG64 __cdecl RawrXD_Host_Engine_Pipeline_Core(
        ULONG64 targetTierIndex,
        LPVOID  payloadStateContext
    );
}

namespace Deep2 {
namespace Bridge {

//==============================================================================
// Constants
//==============================================================================
static constexpr DWORD RXIP_MAGIC = 0x50495852;  // 'RXIP'
static constexpr size_t RING_BUFFER_SIZE = 256 * 1024;  // 256KB ring buffer
static constexpr size_t MAX_TOKENS_PER_BATCH = 64;
static constexpr UINT WM_USER_DEEP2_TOKEN = WM_USER + 200;
static constexpr UINT WM_USER_DEEP2_COMPLETE = WM_USER + 201;

//==============================================================================
// RXIP Frame Structure (matches rawr_ipc.asm)
//==============================================================================
#pragma pack(push, 1)
struct RXIPFrame {
    DWORD magic;      // 0x50495852
    DWORD type;       // Frame type
    DWORD size;       // Payload size
    DWORD crc;        // XOR32 checksum
    // Payload follows
};
#pragma pack(pop)

enum FrameType : DWORD {
    FRAME_AI_INVOKE   = 0x01,
    FRAME_AI_RESULT   = 0x02,
    FRAME_STATUS_REQ  = 0x03,
    FRAME_STATUS_RESP = 0x04,
    FRAME_TOKEN_STREAM= 0x05,
    FRAME_TOKEN_EOS   = 0x06,
};

//==============================================================================
// TokenStreamRingBuffer
// Lock-free SPSC ring buffer for token streaming
//==============================================================================
struct TokenStreamRingBuffer {
    alignas(64) std::atomic<uint32_t> writePos{0};
    alignas(64) std::atomic<uint32_t> readPos{0};
    alignas(64) uint8_t buffer[RING_BUFFER_SIZE];
    
    // Cyclonic flow invariant: never block, never allocate
    bool WriteToken(const std::string& token) {
        uint32_t wp = writePos.load(std::memory_order_relaxed);
        uint32_t rp = readPos.load(std::memory_order_acquire);
        
        size_t tokenLen = token.length();
        size_t frameSize = sizeof(RXIPFrame) + tokenLen;
        
        // Check if we have space (simplified - real impl would handle wrap)
        if (wp + frameSize > rp + RING_BUFFER_SIZE) {
            return false;  // Ring full - flow pressure signal
        }
        
        // Write frame header
        RXIPFrame* frame = reinterpret_cast<RXIPFrame*>(&buffer[wp % RING_BUFFER_SIZE]
        );
        frame->magic = RXIP_MAGIC;
        frame->type = FRAME_TOKEN_STREAM;
        frame->size = static_cast<DWORD>(tokenLen);
        frame->crc = ComputeCrc32(token);
        
        // Write payload
        memcpy(&buffer[(wp + sizeof(RXIPFrame)) % RING_BUFFER_SIZE], 
               token.data(), tokenLen);
        
        writePos.store(wp + frameSize, std::memory_order_release);
        return true;
    }
    
    bool ReadToken(std::string& token) {
        uint32_t rp = readPos.load(std::memory_order_relaxed);
        uint32_t wp = writePos.load(std::memory_order_acquire);
        
        if (rp >= wp) {
            return false;  // Empty
        }
        
        RXIPFrame* frame = reinterpret_cast<RXIPFrame*>(&buffer[rp % RING_BUFFER_SIZE]
        );
        
        if (frame->magic != RXIP_MAGIC) {
            return false;  // Corruption
        }
        
        token.assign(
            reinterpret_cast<char*>(&buffer[(rp + sizeof(RXIPFrame)) % RING_BUFFER_SIZE]),
            frame->size
        );
        
        readPos.store(rp + sizeof(RXIPFrame) + frame->size, std::memory_order_release);
        return true;
    }
    
private:
    static DWORD ComputeCrc32(const std::string& data) {
        DWORD crc = 0;
        for (char c : data) {
            crc ^= static_cast<DWORD>(c);
        }
        return crc;
    }
};

//==============================================================================
// Deep2Win32IDE_Bridge
// Singleton bridge connecting Deep2 inference to Win32IDE UI
//==============================================================================
class Deep2Win32IDE_Bridge {
public:
    static Deep2Win32IDE_Bridge& Instance() {
        static Deep2Win32IDE_Bridge instance;
        return instance;
    }
    
    // Initialize the bridge
    bool Initialize(HWND ideWindow) {
        if (initialized_) return true;
        
        ideWindow_ = ideWindow;
        
        // Initialize Deep2 inference gateway
        if (!Deep2InferenceGateway::Instance().Initialize()) {
            OutputDebugStringA("[Deep2Bridge] Failed to initialize inference gateway\n");
            return false;
        }
        
        // Create token streaming thread
        streamThread_ = CreateThread(
            nullptr, 0,
            TokenStreamThreadProc,
            this, 0, &streamThreadId_
        );
        
        if (!streamThread_) {
            return false;
        }
        
        // Set thread priority for cyclonic flow
        SetThreadPriority(streamThread_, THREAD_PRIORITY_TIME_CRITICAL);
        
        initialized_ = true;
        OutputDebugStringA("[Deep2Bridge] Initialized successfully\n");
        return true;
    }
    
    // Shutdown
    void Shutdown() {
        if (!initialized_) return;
        
        shutdown_.store(true, std::memory_order_release);
        
        if (streamThread_) {
            WaitForSingleObject(streamThread_, 5000);
            CloseHandle(streamThread_);
            streamThread_ = nullptr;
        }
        
        Deep2InferenceGateway::Instance().Shutdown();
        initialized_ = false;
    }
    
    // Load a model
    bool LoadModel(const std::string& modelPath) {
        return Deep2InferenceGateway::Instance().LoadModel(modelPath);
    }
    
    // Start token generation (cyclonic flow entry point)
    bool StartGeneration(const std::string& prompt, 
                         const SamplingConfig& config,
                         HWND targetWindow) {
        if (!initialized_) return false;
        
        // Store generation parameters
        currentPrompt_ = prompt;
        currentConfig_ = config;
        targetWindow_ = targetWindow;
        
        // Signal the stream thread
        generationActive_.store(true, std::memory_order_release);
        
        return true;
    }
    
    // Check if generation is active
    bool IsGenerating() const {
        return generationActive_.load(std::memory_order_acquire);
    }
    
    // Get performance metrics
    float GetTokensPerSecond() const {
        return currentTps_;
    }
    
    // Get the ring buffer for external readers
    TokenStreamRingBuffer* GetRingBuffer() {
        return &ringBuffer_;
    }

private:
    Deep2Win32IDE_Bridge() = default;
    ~Deep2Win32IDE_Bridge() { Shutdown(); }
    
    Deep2Win32IDE_Bridge(const Deep2Win32IDE_Bridge&) = delete;
    Deep2Win32IDE_Bridge& operator=(const Deep2Win32IDE_Bridge&) = delete;
    
    // Token streaming thread - cyclonic flow
    static DWORD WINAPI TokenStreamThreadProc(LPVOID param) {
        auto* bridge = static_cast<Deep2Win32IDE_Bridge*>(param);
        bridge->TokenStreamLoop();
        return 0;
    }
    
    void TokenStreamLoop() {
        OutputDebugStringA("[Deep2Bridge] Token stream thread started\n");
        
        while (!shutdown_.load(std::memory_order_acquire)) {
            if (!generationActive_.load(std::memory_order_acquire)) {
                Sleep(1);  // 1ms idle - no busy wait
                continue;
            }
            
            // Execute generation via Deep2 gateway
            AIRequest request;
            request.operation = AIRequest::OpStream;
            request.prefix = currentPrompt_;
            request.maxTokens = currentConfig_.maxTokens;
            request.temperature = currentConfig_.temperature;
            request.topP = currentConfig_.topP;
            
            // Stream callback - writes to ring buffer
            request.streamCallback = [this](const std::string& token, bool finished) {
                // Write token to ring buffer (cyclonic flow - never blocks)
                if (!ringBuffer_.WriteToken(token)) {
                    // Ring buffer full - signal pressure
                    OutputDebugStringA("[Deep2Bridge] Ring buffer pressure signal\n");
                }
                
                // Notify IDE window
                if (targetWindow_ && IsWindow(targetWindow_)) {
                    PostMessage(targetWindow_, WM_USER_DEEP2_TOKEN, 
                               reinterpret_cast<WPARAM>(token.data()),
                               token.length());
                }
                
                if (finished) {
                    generationActive_.store(false, std::memory_order_release);
                    if (targetWindow_ && IsWindow(targetWindow_)) {
                        PostMessage(targetWindow_, WM_USER_DEEP2_COMPLETE, 0, 0);
                    }
                }
            };
            
            auto response = Deep2InferenceGateway::Instance().ProcessRequest(request);
            
            if (!response.success) {
                OutputDebugStringA("[Deep2Bridge] Generation failed: ");
                OutputDebugStringA(response.error.c_str());
                OutputDebugStringA("\n");
                generationActive_.store(false, std::memory_order_release);
            }
            
            // Update TPS metric
            currentTps_ = response.tokensPerSecond;
        }
        
        OutputDebugStringA("[Deep2Bridge] Token stream thread exiting\n");
    }
    
    // State
    HWND ideWindow_ = nullptr;
    HWND targetWindow_ = nullptr;
    HANDLE streamThread_ = nullptr;
    DWORD streamThreadId_ = 0;
    
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<bool> generationActive_{false};
    std::atomic<float> currentTps_{0.0f};
    
    TokenStreamRingBuffer ringBuffer_;
    
    // Current generation state
    std::string currentPrompt_;
    SamplingConfig currentConfig_;
};

} // namespace Bridge
} // namespace Deep2

//==============================================================================
// C API for Win32IDE integration
//==============================================================================

extern "C" {

// Initialize the bridge
__declspec(dllexport) BOOL Deep2Bridge_Initialize(HWND ideWindow) {
    return Deep2::Bridge::Deep2Win32IDE_Bridge::Instance().Initialize(ideWindow) 
           ? TRUE : FALSE;
}

// Shutdown
__declspec(dllexport) void Deep2Bridge_Shutdown() {
    Deep2::Bridge::Deep2Win32IDE_Bridge::Instance().Shutdown();
}

// Load model
__declspec(dllexport) BOOL Deep2Bridge_LoadModel(LPCSTR modelPath) {
    return Deep2::Bridge::Deep2Win32IDE_Bridge::Instance().LoadModel(modelPath) 
           ? TRUE : FALSE;
}

// Start generation
__declspec(dllexport) BOOL Deep2Bridge_StartGeneration(
    LPCSTR prompt,
    float temperature,
    float topP,
    int maxTokens,
    HWND targetWindow
) {
    Deep2::SamplingConfig config;
    config.temperature = temperature;
    config.topP = topP;
    config.maxTokens = maxTokens;
    
    return Deep2::Bridge::Deep2Win32IDE_Bridge::Instance().StartGeneration(
        prompt, config, targetWindow
    ) ? TRUE : FALSE;
}

// Check if generating
__declspec(dllexport) BOOL Deep2Bridge_IsGenerating() {
    return Deep2::Bridge::Deep2Win32IDE_Bridge::Instance().IsGenerating() 
           ? TRUE : FALSE;
}

// Get TPS
__declspec(dllexport) float Deep2Bridge_GetTokensPerSecond() {
    return Deep2::Bridge::Deep2Win32IDE_Bridge::Instance().GetTokensPerSecond();
}

// Execute Tib-Bit transition (MASM64)
__declspec(dllexport) ULONG64 Deep2Bridge_ExecuteTibBit(
    ULONG64 tierIndex,
    LPVOID stateContext
) {
    return RawrXD_Host_Engine_Pipeline_Core(tierIndex, stateContext);
}

} // extern "C"
