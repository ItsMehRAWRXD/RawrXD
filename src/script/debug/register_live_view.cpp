// ============================================================================
// register_live_view.cpp — RawrXD-Script VM Register Live View Implementation
// ============================================================================

#include "register_live_view.hpp"

#include <sstream>
#include <iomanip>
#include <chrono>

namespace RawrXD {
namespace Script {
namespace Debug {

// ============================================================================
// Global Instance
// ============================================================================

static std::unique_ptr<RegisterLiveView> g_registerLiveView;

RegisterLiveView* GetRegisterLiveView() {
    return g_registerLiveView.get();
}

bool InitializeRegisterLiveView(Script::Interpreter* interpreter) {
    if (!g_registerLiveView) {
        g_registerLiveView = std::make_unique<RegisterLiveView>();
    }
    return g_registerLiveView->Initialize(interpreter);
}

void ShutdownRegisterLiveView() {
    if (g_registerLiveView) {
        g_registerLiveView->Shutdown();
        g_registerLiveView.reset();
    }
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

RegisterLiveView::RegisterLiveView() = default;

RegisterLiveView::~RegisterLiveView() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool RegisterLiveView::Initialize(Script::Interpreter* interpreter) {
    if (!interpreter) return false;
    
    m_interpreter = interpreter;
    m_running = true;
    
    // Initialize state
    {
        std::lock_guard<std::mutex> lk(m_stateMutex);
        m_currentState.values.fill(0);
        m_currentState.types.fill("undefined");
        m_currentState.modified.fill(false);
        m_currentState.pc = 0;
        m_currentState.sp = 0;
        m_currentState.flags = 0;
        m_currentState.timestamp = 0;
    }
    
    return true;
}

void RegisterLiveView::Shutdown() {
    StopPolling();
    m_running = false;
    m_interpreter = nullptr;
}

// ============================================================================
// Polling
// ============================================================================

void RegisterLiveView::StartPolling(int intervalMs) {
    if (m_polling) return;
    
    m_pollIntervalMs = intervalMs;
    m_polling = true;
    m_pollThread = std::thread(&RegisterLiveView::PollLoop, this);
}

void RegisterLiveView::StopPolling() {
    m_polling = false;
    if (m_pollThread.joinable()) {
        m_pollThread.join();
    }
}

void RegisterLiveView::PollLoop() {
    while (m_polling && m_running) {
        auto state = Refresh();
        
        // Notify watchers
        for (int i = 0; i < 16; i++) {
            if (state.modified[i] && m_watchCallbacks[i]) {
                m_watchCallbacks[i](state);
            }
        }
        
        // Notify global callback
        if (m_updateCallback) {
            m_updateCallback(state);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(m_pollIntervalMs));
    }
}

// ============================================================================
// State Reading
// ============================================================================

RegisterState RegisterLiveView::Refresh() {
    auto newState = ReadInterpreterState();
    
    std::lock_guard<std::mutex> lk(m_stateMutex);
    
    // Detect modifications
    for (int i = 0; i < 16; i++) {
        newState.modified[i] = (newState.values[i] != m_currentState.values[i]);
    }
    
    m_currentState = newState;
    return m_currentState;
}

RegisterState RegisterLiveView::ReadInterpreterState() {
    RegisterState state;
    
    if (!m_interpreter) {
        state.values.fill(0);
        state.types.fill("unavailable");
        state.modified.fill(false);
        state.pc = 0;
        state.sp = 0;
        state.flags = 0;
        state.timestamp = 0;
        return state;
    }
    
    // TODO: Read actual interpreter state
    // For now, return sample data
    for (int i = 0; i < 16; i++) {
        // Sample NaN-boxed values
        if (i < 4) {
            // Integers
            state.values[i] = 0x7FF9000000000000ULL | (static_cast<uint64_t>(i * 10) << 32);
            state.types[i] = "number";
        } else if (i < 8) {
            // Doubles
            state.values[i] = 0x7FF8000000000000ULL | (i * 0x1000000000000);
            state.types[i] = "number";
        } else if (i == 8) {
            // Boolean true
            state.values[i] = 0x7FF9000000000001ULL;
            state.types[i] = "boolean";
        } else if (i == 9) {
            // Null
            state.values[i] = 0x7FF9000000000002ULL;
            state.types[i] = "object";
        } else {
            // Undefined
            state.values[i] = 0x7FF9000000000003ULL;
            state.types[i] = "undefined";
        }
        state.modified[i] = false;
    }
    
    state.pc = 0x1000;
    state.sp = 0x7FFF0000;
    state.flags = 0;
    state.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return state;
}

// ============================================================================
// Formatting
// ============================================================================

std::string RegisterLiveView::FormatValue(uint64_t nanBoxedValue) {
    // Check for special values
    const uint64_t QNAN_MASK = 0x7FF9000000000000ULL;
    const uint64_t DOUBLE_MASK = 0x7FF8000000000000ULL;
    
    if ((nanBoxedValue & QNAN_MASK) == QNAN_MASK) {
        // Integer or special
        uint32_t intVal = static_cast<uint32_t>(nanBoxedValue >> 32);
        
        // Check for special values
        switch (intVal) {
            case 0: return "0";
            case 1: return "true";
            case 2: return "null";
            case 3: return "undefined";
            default: return std::to_string(static_cast<int32_t>(intVal));
        }
    } else if ((nanBoxedValue & DOUBLE_MASK) == DOUBLE_MASK) {
        // Double - extract and format
        // This is simplified - real implementation would properly decode
        return "<double>";
    }
    
    // Pointer or other
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << nanBoxedValue;
    return oss.str();
}

std::string RegisterLiveView::FormatType(uint64_t nanBoxedValue) {
    return DetectType(nanBoxedValue);
}

std::string RegisterLiveView::FormatHex(uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return oss.str();
}

std::string RegisterLiveView::FormatBinary(uint64_t value) {
    std::string result = "0b";
    for (int i = 63; i >= 0; i--) {
        result += (value & (1ULL << i)) ? '1' : '0';
        if (i % 8 == 0 && i > 0) result += '_';
    }
    return result;
}

std::string RegisterLiveView::DetectType(uint64_t value) {
    const uint64_t QNAN_MASK = 0x7FF9000000000000ULL;
    const uint64_t DOUBLE_MASK = 0x7FF8000000000000ULL;
    
    if ((value & QNAN_MASK) == QNAN_MASK) {
        uint32_t intVal = static_cast<uint32_t>(value >> 32);
        switch (intVal) {
            case 1: return "boolean";
            case 2: return "object";
            case 3: return "undefined";
            default: return "number";
        }
    } else if ((value & DOUBLE_MASK) == DOUBLE_MASK) {
        return "number";
    }
    
    // Check for object tags
    if ((value & 0x7) == 0x1) return "object";
    if ((value & 0x7) == 0x2) return "string";
    if ((value & 0x7) == 0x3) return "symbol";
    
    return "unknown";
}

// ============================================================================
// Callbacks
// ============================================================================

void RegisterLiveView::SetUpdateCallback(UpdateCallback callback) {
    m_updateCallback = callback;
}

void RegisterLiveView::WatchRegister(int regIndex, UpdateCallback callback) {
    if (regIndex >= 0 && regIndex < 16) {
        m_watchCallbacks[regIndex] = callback;
    }
}

void RegisterLiveView::UnwatchRegister(int regIndex) {
    if (regIndex >= 0 && regIndex < 16) {
        m_watchCallbacks[regIndex] = nullptr;
    }
}

RegisterState RegisterLiveView::GetCurrentState() const {
    std::lock_guard<std::mutex> lk(m_stateMutex);
    return m_currentState;
}

} // namespace Debug
} // namespace Script
} // namespace RawrXD
