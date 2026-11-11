/*===========================================================================
 * GhostText_PyreBridge.cpp
 * 
 * Implementation of Pyre → IDE Ghost Text bridge
 *===========================================================================*/

#include "GhostText_PyreBridge.hpp"
#include <string>

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * Singleton Implementation
 *=========================================================================*/
GhostText_PyreBridge& GhostText_PyreBridge::Instance() {
    static GhostText_PyreBridge instance;
    return instance;
}

PyreStopFlag& PyreStopFlag::Instance() {
    static PyreStopFlag instance;
    return instance;
}

/*===========================================================================
 * Initialization / Shutdown
 *=========================================================================*/
bool GhostText_PyreBridge::Initialize(HWND hEditor) {
    if (initialized_.load(std::memory_order_acquire)) {
        return true; // Already initialized
    }
    
    if (!hEditor || !IsWindow(hEditor)) {
        return false;
    }
    
    editor_hwnd_ = hEditor;
    batch_pos_ = 0;
    batch_buffer_[0] = '\0';
    
    // Clear stop flag
    stop_requested_.store(false, std::memory_order_relaxed);
    PyreStopFlag::Instance().Reset();
    
    // Disable undo for performance during streaming
    SendMessage(editor_hwnd_, EM_SETUNDOLIMIT, 0, 0);
    
    initialized_.store(true, std::memory_order_release);
    return true;
}

void GhostText_PyreBridge::Shutdown() {
    if (!initialized_.load(std::memory_order_acquire)) {
        return;
    }
    
    // Flush any remaining tokens
    if (batch_pos_ > 0) {
        ThawEditor();
        BatchUpdateEditor(batch_buffer_, batch_pos_);
        batch_pos_ = 0;
    }
    
    // Re-enable undo
    if (editor_hwnd_ && IsWindow(editor_hwnd_)) {
        SendMessage(editor_hwnd_, EM_SETUNDOLIMIT, (WPARAM)-1, 0);
    }
    
    editor_hwnd_ = nullptr;
    initialized_.store(false, std::memory_order_release);
}

bool GhostText_PyreBridge::IsInitialized() const {
    return initialized_.load(std::memory_order_acquire);
}

/*===========================================================================
 * Producer API (Pyre Thread)
 *=========================================================================*/
bool GhostText_PyreBridge::SubmitToken(const char* token, uint32_t length,
                                        uint32_t tokenId, float confidence) {
    if (!initialized_.load(std::memory_order_acquire)) {
        return false;
    }
    
    // Check stop flag first (fast path)
    if (stop_requested_.load(std::memory_order_relaxed)) {
        return false;
    }
    
    GhostToken gt;
    gt.tokenId = tokenId;
    gt.confidence = confidence;
    
    if (token && length > 0) {
        if (length >= GhostToken::MAX_TOKEN_LEN) {
            length = GhostToken::MAX_TOKEN_LEN - 1;
        }
        memcpy(gt.data, token, length);
        gt.data[length] = '\0';
        gt.length = length;
    } else {
        gt.length = 0;
        gt.data[0] = '\0';
    }
    
    const bool pushed = ring_buffer_.try_push(gt);
    
    // Update telemetry
    if (pushed) {
        telemetry_.tokensSubmitted++;
        const size_t currentSize = ring_buffer_.size_approx();
        if (currentSize > telemetry_.ringBufferHighWater) {
            telemetry_.ringBufferHighWater = static_cast<uint32_t>(currentSize);
        }
    } else {
        telemetry_.tokensDropped++;
    }
    
    return pushed;
}

/*===========================================================================
 * Consumer API (UI Thread @ 60Hz)
 *=========================================================================*/
void GhostText_PyreBridge::ConsumeAndUpdate() {
    if (!initialized_.load(std::memory_order_acquire) || !editor_hwnd_) {
        return;
    }
    
    // Freeze editor for batch update
    FreezeEditor();
    
    // Drain ring buffer into batch buffer
    GhostToken tokens[BATCH_MAX];
    size_t count = ring_buffer_.try_pop_batch(tokens, BATCH_MAX);
    
    if (count > 0) {
        // Accumulate tokens into batch buffer
        for (size_t i = 0; i < count; ++i) {
            const GhostToken& tok = tokens[i];
            if (tok.length > 0 && batch_pos_ + tok.length < BATCH_BUFFER_SIZE - 1) {
                memcpy(batch_buffer_ + batch_pos_, tok.data, tok.length);
                batch_pos_ += tok.length;
            }
        }
        
        telemetry_.tokensConsumed += count;
        telemetry_.batchesProcessed++;
    }
    
    // Flush batch buffer if it gets large enough
    if (batch_pos_ >= 256 || ring_buffer_.empty()) {
        if (batch_pos_ > 0) {
            BatchUpdateEditor(batch_buffer_, batch_pos_);
            batch_pos_ = 0;
            batch_buffer_[0] = '\0';
        }
    }
    
    // Thaw editor
    ThawEditor();
}

void GhostText_PyreBridge::DrainToEditor() {
    if (!initialized_.load(std::memory_order_acquire) || !editor_hwnd_) {
        return;
    }
    
    FreezeEditor();
    
    // Drain all available tokens
    GhostToken tokens[BATCH_MAX];
    size_t totalConsumed = 0;
    
    while (true) {
        size_t count = ring_buffer_.try_pop_batch(tokens, BATCH_MAX);
        if (count == 0) break;
        
        for (size_t i = 0; i < count; ++i) {
            const GhostToken& tok = tokens[i];
            if (tok.length > 0) {
                // Direct insert for drain (not batched)
                SendMessage(editor_hwnd_, EM_REPLACESEL, FALSE, 
                           reinterpret_cast<LPARAM>(tok.data));
            }
        }
        totalConsumed += count;
    }
    
    // Flush any accumulated batch
    if (batch_pos_ > 0) {
        BatchUpdateEditor(batch_buffer_, batch_pos_);
        batch_pos_ = 0;
    }
    
    ThawEditor();
    
    telemetry_.tokensConsumed += totalConsumed;
}

/*===========================================================================
 * Stop/Cancel API
 *=========================================================================*/
void GhostText_PyreBridge::RequestStop() {
    stop_requested_.store(true, std::memory_order_relaxed);
    PyreStopFlag::Instance().RequestStop();
}

void GhostText_PyreBridge::ClearStop() {
    stop_requested_.store(false, std::memory_order_relaxed);
    PyreStopFlag::Instance().Reset();
}

bool GhostText_PyreBridge::IsStopRequested() const {
    return stop_requested_.load(std::memory_order_relaxed);
}

void GhostText_PyreBridge::ClearBuffer() {
    // Drain all tokens
    GhostToken dummy;
    while (ring_buffer_.try_pop()) {
        // Discard
    }
    batch_pos_ = 0;
    batch_buffer_[0] = '\0';
}

/*===========================================================================
 * Editor Helpers
 *=========================================================================*/
void GhostText_PyreBridge::FreezeEditor() {
    if (editor_hwnd_) {
        SendMessage(editor_hwnd_, WM_SETREDRAW, FALSE, 0);
    }
}

void GhostText_PyreBridge::ThawEditor() {
    if (editor_hwnd_) {
        SendMessage(editor_hwnd_, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(editor_hwnd_, nullptr, FALSE);
    }
}

void GhostText_PyreBridge::BatchUpdateEditor(const char* batch_text, size_t length) {
    if (!editor_hwnd_ || length == 0) return;
    
    // Null-terminate for safety
    char temp[BATCH_BUFFER_SIZE];
    if (length >= BATCH_BUFFER_SIZE) length = BATCH_BUFFER_SIZE - 1;
    memcpy(temp, batch_text, length);
    temp[length] = '\0';
    
    // Insert at current selection
    SendMessage(editor_hwnd_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(temp));
}

/*===========================================================================
 * Telemetry
 *=========================================================================*/
GhostText_PyreBridge::Telemetry GhostText_PyreBridge::GetTelemetry() const {
    return telemetry_;
}

void GhostText_PyreBridge::ResetTelemetry() {
    telemetry_ = Telemetry{};
}

} // namespace IDE
} // namespace RawrXD
