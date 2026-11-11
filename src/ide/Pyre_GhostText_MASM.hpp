/*===========================================================================
 * Pyre_GhostText_MASM.hpp
 * 
 * C++ wrapper for MASM Ghost Text bridge functions
 * 
 * Usage:
 *   // Initialize before generation
 *   PyreGhost_Init(hEditor);
 *   
 *   // In Pyre generation loop (MASM side)
 *   ; Check if we should stop
 *   call PyreGhost_CheckStop
 *   test al, al
 *   jnz .generation_done
 *   
 *   ; Submit token
 *   mov rcx, tokenPtr
 *   mov edx, tokenLen
 *   call PyreGhost_SubmitToken
 *   
 *   // Shutdown after generation
 *   PyreGhost_Shutdown();
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <cstdint>

// Extern "C" linkage for MASM functions
extern "C" {

/**
 * Initialize the Ghost Text bridge
 * @param hEditor RichEdit control HWND
 * @return true on success
 */
bool PyreGhost_Init(HWND hEditor);

/**
 * Submit a token to the Ghost Text ring buffer
 * Thread-safe, lock-free (called from Pyre worker thread)
 * @param token UTF-8 token text
 * @param length Token length in bytes
 * @param tokenId Optional token ID
 * @param confidence Optional confidence score (0.0-1.0)
 * @return true if token accepted, false if buffer full
 */
bool PyreGhost_SubmitToken(const char* token, uint32_t length, 
                           uint32_t tokenId = 0, float confidence = 1.0f);

/**
 * Submit a single character (simplified API)
 * @param c Character to submit
 * @return true if accepted
 */
bool PyreGhost_SubmitChar(char c);

/**
 * Check if generation should stop (hot path)
 * Called every token from Pyre inner loop
 * @return true if stop requested
 */
bool PyreGhost_CheckStop();

/**
 * Request Pyre generation to stop
 * Can be called from any thread
 */
void PyreGhost_RequestStop();

/**
 * Shutdown the Ghost Text bridge
 * Flushes remaining tokens to editor
 */
void PyreGhost_Shutdown();

/**
 * Get submission statistics
 * @param out_tokensSubmitted Number of tokens successfully submitted
 * @param out_tokensDropped Number of tokens dropped (buffer full)
 */
void PyreGhost_GetStats(uint64_t* out_tokensSubmitted, uint64_t* out_tokensDropped);

/**
 * Reset statistics counters
 */
void PyreGhost_ClearStats();

/**
 * Callback for Pyre generation loop
 * Checks stop flag and submits token in one call
 * @param tokenText Generated token text
 * @param tokenLength Token length
 * @param tokenId Token ID
 * @return true to continue generation, false to stop
 */
bool PyreGhost_OnTokenGenerated(const char* tokenText, uint32_t tokenLength, 
                                 uint32_t tokenId);

} // extern "C"

namespace RawrXD {
namespace IDE {

/**
 * RAII wrapper for Pyre Ghost Text session
 */
class PyreGhostSession {
public:
    explicit PyreGhostSession(HWND hEditor) : active_(false) {
        active_ = PyreGhost_Init(hEditor);
    }
    
    ~PyreGhostSession() {
        if (active_) {
            PyreGhost_Shutdown();
        }
    }
    
    // Non-copyable
    PyreGhostSession(const PyreGhostSession&) = delete;
    PyreGhostSession& operator=(const PyreGhostSession&) = delete;
    
    // Movable
    PyreGhostSession(PyreGhostSession&& other) noexcept 
        : active_(other.active_) {
        other.active_ = false;
    }
    
    PyreGhostSession& operator=(PyreGhostSession&& other) noexcept {
        if (this != &other) {
            if (active_) {
                PyreGhost_Shutdown();
            }
            active_ = other.active_;
            other.active_ = false;
        }
        return *this;
    }
    
    bool IsActive() const { return active_; }
    
    void RequestStop() { PyreGhost_RequestStop(); }
    bool CheckStop() { return PyreGhost_CheckStop(); }
    
    bool SubmitToken(const char* token, uint32_t length, 
                    uint32_t tokenId = 0, float confidence = 1.0f) {
        return PyreGhost_SubmitToken(token, length, tokenId, confidence);
    }

private:
    bool active_;
};

} // namespace IDE
} // namespace RawrXD
