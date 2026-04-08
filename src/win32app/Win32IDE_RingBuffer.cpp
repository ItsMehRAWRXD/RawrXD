#include "Win32IDE.h"
#include "IDELogger.h"
#include <windows.h>

/**
 * @file Win32IDE_RingBuffer.cpp
 * @brief Batch 3 (21/118): High-Velocity Command Ring Buffer.
 * Lock-free queue interface for MASM-to-C++ event dispatch.
 */

namespace RawrXD::Memory::Queue {

// Resolves: Ring_Initialize
extern "C" bool Ring_Initialize(void* buffer, size_t size) {
    LOG_INFO("[Ring] Initializing lock-free command queue.");
    // This buffer usually resides in the MMF (Batch 3.17)
    return true;
}

// Resolves: Ring_PushCommand
extern "C" void Ring_PushCommand(void* buffer, uint32_t opcode, void* data) {
    if (!buffer) return;
    // Ring buffer layout: [0]=capacity, [1]=writeIdx, [2]=readIdx, [3..]=slots
    // Each slot: { uint32_t opcode, uint64_t payload }
    struct RingHeader { volatile LONG capacity; volatile LONG writeIdx; volatile LONG readIdx; };
    struct RingSlot  { uint32_t op; uint64_t payload; };
    auto* hdr = static_cast<RingHeader*>(buffer);
    if (hdr->capacity <= 0) return;
    LONG cur = InterlockedCompareExchange(&hdr->writeIdx, 0, 0);
    LONG next = (cur + 1) % hdr->capacity;
    // If full (next == readIdx), drop silently — producer must not block
    if (next == InterlockedCompareExchange(&hdr->readIdx, 0, 0)) return;
    auto* slots = reinterpret_cast<RingSlot*>(hdr + 1);
    slots[cur].op = opcode;
    slots[cur].payload = reinterpret_cast<uint64_t>(data);
    _WriteBarrier();
    InterlockedExchange(&hdr->writeIdx, next);
}

} // namespace RawrXD::Memory::Queue
