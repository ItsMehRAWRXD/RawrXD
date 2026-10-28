// ============================================================================
// Win32IDE_LoRAKernelBridge.cpp — LoRA MASM Kernel Integration
// ============================================================================
// GATED_OMIT LORA_KERNEL_STUB_GATE_001 / WIN32IDE_STUB_GATE_003:
// Not in RawrXD-Win32IDE product link. ApplyLoRA ASM not product-wired.
// initialize()/IsReady must fail-closed — no "simulating trained LoRA" PASS.
// Header presence / worker scaffolding != RUNTIME_REACHED / PASS.

#include "Win32IDE.h"
#include "Win32IDE_AgentBridge.hpp"
#include <windows.h>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <cstdio>

// MASM Kernel Declaration
extern "C" {
    // ApplyLoRA_Minimal.asm entry point
    // RCX=base_output, RDX=input, R8=result, R9=beacon, [RSP+40]=token_count
    uint64_t ApplyLoRA_Optimized(
        float* base_output,
        float* input,
        float* result,
        void* beacon_state,
        uint64_t token_count
    );
}

namespace RawrXD::LoRAKernelBridge {

// ============================================================================
// LoRA Context Structure (64-byte aligned, matches MASM)
// ============================================================================
struct alignas(64) LoRAContext {
    uint64_t magic = 0x4141524F4C;      // "LORAA"
    uint32_t rank = 8;
    uint32_t hidden_dim = 768;
    uint32_t input_dim = 768;
    uint32_t reserved = 0;
    float* matrix_A = nullptr;
    float* matrix_B = nullptr;
    float alpha = 1.0f;
    float scale = 1.0f;
    uint64_t status_flags = 0;
};

// ============================================================================
// Work Item for Async Processing
// ============================================================================
struct LoRAWorkItem {
    std::vector<float> input_buffer;
    std::vector<float> output_buffer;
    HWND target_hwnd;
    uint32_t request_id;
    std::chrono::steady_clock::time_point submit_time;
};

// ============================================================================
// LoRA Kernel Bridge Singleton
// ============================================================================
class LoRAKernelBridge {
public:
    static LoRAKernelBridge& instance() {
        static LoRAKernelBridge inst;
        return inst;
    }

    // Initialize the kernel bridge
    bool initialize();
    
    // Shutdown and cleanup
    void shutdown();
    
    // Submit work to the kernel (thread-safe)
    bool submitWork(const std::vector<float>& input, HWND target_hwnd, uint32_t request_id);
    
    // Check if kernel is ready
    bool isReady() const { return m_initialized && m_kernel_ready; }

private:
    LoRAKernelBridge() = default;
    ~LoRAKernelBridge() { shutdown(); }

    // Worker thread function
    void workerLoop();
    
    // Process a single work item
    void processWorkItem(LoRAWorkItem& item);
    
    // Signal UI thread on completion
    void signalCompletion(HWND hwnd, uint32_t request_id, const std::vector<float>& result);

    // Member variables
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_kernel_ready{false};
    
    std::thread m_worker_thread;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::queue<LoRAWorkItem> m_work_queue;
    
    // LoRA context and matrices
    LoRAContext m_context;
    std::vector<float> m_matrix_A;
    std::vector<float> m_matrix_B;
};

// ============================================================================
// IMPLEMENTATION
// ============================================================================

bool LoRAKernelBridge::initialize() {
    // Fail-closed: simulated weights + worker start was fake-success theater.
    // Real path requires product-linked ApplyLoRA ASM + non-omit CMake wire.
    OutputDebugStringA(
        "[LoRAKernelBridge] GATED_STUB SYNTHETIC=partial "
        "LORA_KERNEL_STUB_GATE_001 ApplyLoRA NOT_PRODUCT_WIRED NOT_PASS\n");
    m_kernel_ready = false;
    m_initialized = false;
    return false;
}

void LoRAKernelBridge::shutdown() {
    if (!m_initialized) return;
    
    m_running = false;
    m_queue_cv.notify_all();
    
    if (m_worker_thread.joinable()) {
        m_worker_thread.join();
    }
    
    m_kernel_ready = false;
    m_initialized = false;
    
    OutputDebugStringA("[LoRAKernelBridge] Shutdown complete\n");
}

bool LoRAKernelBridge::submitWork(const std::vector<float>& input, HWND target_hwnd, uint32_t request_id) {
    if (!m_initialized || !m_kernel_ready) {
        OutputDebugStringA("[LoRAKernelBridge] ERROR: Not initialized\n");
        return false;
    }
    
    LoRAWorkItem item;
    item.input_buffer = input;
    item.output_buffer.resize(input.size());
    item.target_hwnd = target_hwnd;
    item.request_id = request_id;
    item.submit_time = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_work_queue.push(std::move(item));
    }
    
    m_queue_cv.notify_one();
    return true;
}

void LoRAKernelBridge::workerLoop() {
    OutputDebugStringA("[LoRAKernelBridge] Worker thread started\n");
    
    while (m_running) {
        LoRAWorkItem item;
        
        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(lock, [this] { return !m_work_queue.empty() || !m_running; });
            
            if (!m_running) break;
            
            item = std::move(m_work_queue.front());
            m_work_queue.pop();
        }
        
        // Process the work item
        processWorkItem(item);
    }
    
    OutputDebugStringA("[LoRAKernelBridge] Worker thread stopped\n");
}

void LoRAKernelBridge::processWorkItem(LoRAWorkItem& item) {
    auto start_time = std::chrono::steady_clock::now();
    
    // Allocate aligned output buffer
    float* result_buffer = (float*)_aligned_malloc(item.input_buffer.size() * sizeof(float), 32);
    if (!result_buffer) {
        OutputDebugStringA("[LoRAKernelBridge] ERROR: Failed to allocate result buffer\n");
        return;
    }
    
    // Call the MASM kernel
    // For minimal version: just copies input to result
    uint64_t ret = ApplyLoRA_Optimized(
        nullptr,                                    // base_output (unused)
        const_cast<float*>(item.input_buffer.data()), // input
        result_buffer,                              // result
        &m_context,                                 // beacon/context
        1                                           // token_count
    );
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    if (ret == 0) {
        // Copy result back
        item.output_buffer.assign(result_buffer, result_buffer + item.input_buffer.size());
        
        // Signal UI thread
        signalCompletion(item.target_hwnd, item.request_id, item.output_buffer);
        
        char msg[256];
        snprintf(msg, sizeof(msg), "[LoRAKernelBridge] Processed request %u in %lld us\n", 
                 item.request_id, duration.count());
        OutputDebugStringA(msg);
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "[LoRAKernelBridge] Kernel error %llu for request %u\n", 
                 ret, item.request_id);
        OutputDebugStringA(msg);
    }
    
    _aligned_free(result_buffer);
}

void LoRAKernelBridge::signalCompletion(HWND hwnd, uint32_t request_id, const std::vector<float>& result) {
    if (!hwnd || !IsWindow(hwnd)) return;
    
    // Post message to UI thread
    // WM_APP + 210 = LoRA completion notification (avoiding 200 which is used for startup)
    // WPARAM = request_id
    // LPARAM = pointer to result data (UI thread must copy and free)
    
    // Allocate result copy for UI thread
    auto* result_copy = new std::vector<float>(result);
    
    if (!PostMessage(hwnd, WM_APP + 210, request_id, reinterpret_cast<LPARAM>(result_copy))) {
        // Failed to post - clean up
        delete result_copy;
        OutputDebugStringA("[LoRAKernelBridge] ERROR: Failed to post completion message\n");
    }
}

// ============================================================================
// C API for Integration with AgentBridge
// ============================================================================

extern "C" {

// Initialize the LoRA kernel bridge
__declspec(dllexport) bool LoRAKernel_Initialize() {
    return LoRAKernelBridge::instance().initialize();
}

// Shutdown the LoRA kernel bridge
__declspec(dllexport) void LoRAKernel_Shutdown() {
    LoRAKernelBridge::instance().shutdown();
}

// Submit work to the kernel
__declspec(dllexport) bool LoRAKernel_Submit(
    const float* input_buffer,
    size_t buffer_size,
    HWND target_hwnd,
    uint32_t request_id
) {
    if (!input_buffer || buffer_size == 0) return false;
    
    std::vector<float> input(input_buffer, input_buffer + buffer_size);
    return LoRAKernelBridge::instance().submitWork(input, target_hwnd, request_id);
}

// Check if kernel is ready
__declspec(dllexport) bool LoRAKernel_IsReady() {
    return LoRAKernelBridge::instance().isReady();
}

} // extern "C"

} // namespace RawrXD::LoRAKernelBridge
