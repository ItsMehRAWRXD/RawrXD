// ============================================================================
// neural_bridge_stubs.cpp - Stub implementations for neural bridge functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

void asm_neural_init() {
    OutputDebugStringA("[NeuralBridge] asm_neural_init stub called\n");
}

void asm_neural_acquire_eeg() {
    OutputDebugStringA("[NeuralBridge] asm_neural_acquire_eeg stub called\n");
}

void asm_neural_fft_decompose() {
    OutputDebugStringA("[NeuralBridge] asm_neural_fft_decompose stub called\n");
}

void asm_neural_extract_csp() {
    OutputDebugStringA("[NeuralBridge] asm_neural_extract_csp stub called\n");
}

void asm_neural_classify_intent() {
    OutputDebugStringA("[NeuralBridge] asm_neural_classify_intent stub called\n");
}

void asm_neural_detect_event() {
    OutputDebugStringA("[NeuralBridge] asm_neural_detect_event stub called\n");
}

void asm_neural_encode_command() {
    OutputDebugStringA("[NeuralBridge] asm_neural_encode_command stub called\n");
}

void asm_neural_gen_phosphene() {
    OutputDebugStringA("[NeuralBridge] asm_neural_gen_phosphene stub called\n");
}

void asm_neural_haptic_pulse() {
    OutputDebugStringA("[NeuralBridge] asm_neural_haptic_pulse stub called\n");
}

void asm_neural_calibrate() {
    OutputDebugStringA("[NeuralBridge] asm_neural_calibrate stub called\n");
}

void asm_neural_adapt() {
    OutputDebugStringA("[NeuralBridge] asm_neural_adapt stub called\n");
}

void* asm_neural_get_stats() {
    OutputDebugStringA("[NeuralBridge] asm_neural_get_stats stub called\n");
    return nullptr;
}

void asm_neural_shutdown() {
    OutputDebugStringA("[NeuralBridge] asm_neural_shutdown stub called\n");
}

} // extern "C"
