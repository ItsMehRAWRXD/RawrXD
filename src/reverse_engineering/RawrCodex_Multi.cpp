/**
 * @file RawrCodex_Multi.cpp
 * @brief Multi-Architecture RE Engine C++ Implementation
 * @description C++ wrapper implementation for RawrCodex multi-architecture support
 * 
 * @version 1.0.0
 */

#include "RawrCodex_Multi.hpp"
#include <cstring>
#include <cstdio>

namespace RawrXD {
namespace RE {

// ============================================================================
// MultiDisassembler Implementation
// ============================================================================

MultiDisassembler::MultiDisassembler(void* ctx, ArchType arch)
    : m_ctx(ctx)
    , m_arch(arch)
    , m_valid(false) {
    m_valid = RawrDisasm_Multi_Init(ctx, static_cast<uint32_t>(arch)) != 0;
}

bool MultiDisassembler::Disassemble(uint64_t va, const uint8_t* bytes, MultiInstruction& out) {
    if (!m_valid) return false;
    
    std::memset(&out, 0, sizeof(out));
    uint32_t size = RawrDisasm_Multi_Decode(m_ctx, va, bytes, &out);
    return size > 0;
}

// ============================================================================
// MultiEmulator Implementation
// ============================================================================

MultiEmulator::MultiEmulator(ArchType arch, uint64_t memSize)
    : m_state(nullptr) {
    m_state = RawrEmu_Multi_Create(static_cast<uint32_t>(arch), memSize);
}

MultiEmulator::~MultiEmulator() {
    if (m_state) {
        RawrEmu_Multi_Destroy(m_state);
    }
}

bool MultiEmulator::Step() {
    if (!m_state) return false;
    return RawrEmu_Multi_Step(m_state) != 0;
}

uint64_t MultiEmulator::Run() {
    if (!m_state) return 0;
    return RawrEmu_Multi_Run(m_state);
}

bool MultiEmulator::ReadMemory(uint64_t addr, void* data, size_t size) {
    // Would need to implement memory read via RawrCodex API
    (void)addr;
    (void)data;
    (void)size;
    return false;
}

bool MultiEmulator::WriteMemory(uint64_t addr, const void* data, size_t size) {
    // Would need to implement memory write via RawrCodex API
    (void)addr;
    (void)data;
    (void)size;
    return false;
}

bool MultiEmulator::SetPC(uint64_t addr) {
    // Would need to implement PC set via RawrCodex API
    (void)addr;
    return false;
}

uint64_t MultiEmulator::GetPC() const {
    // Would need to implement PC get via RawrCodex API
    return 0;
}

void MultiEmulator::SetStopAddress(uint64_t addr) {
    // Would need to implement via RawrCodex API
    (void)addr;
}

void MultiEmulator::SetMaxInstructions(uint64_t count) {
    // Would need to implement via RawrCodex API
    (void)count;
}

// ============================================================================
// MultiPatternScanner Implementation
// ============================================================================

MultiPatternScanner::MultiPatternScanner(void* ctx)
    : m_ctx(ctx) {
}

uint64_t MultiPatternScanner::Scan(
    const uint8_t* pattern,
    const uint8_t* mask,
    uint32_t length,
    PatternCallback callback) {
    
    return RawrPattern_Multi_Scan(m_ctx, pattern, mask, length, callback);
}

uint64_t MultiPatternScanner::ScanString(const char* patternStr, PatternCallback callback) {
    // Parse pattern string like "48 89 ?? 50"
    uint8_t pattern[256];
    uint8_t mask[256];
    uint32_t length = 0;
    
    const char* p = patternStr;
    while (*p && length < 256) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        
        if (*p == '?') {
            // Wildcard
            pattern[length] = 0;
            mask[length] = 0;
            p++;
            if (*p == '?') p++;  // Skip second ?
        } else {
            // Hex byte
            unsigned int byte;
            if (sscanf_s(p, "%02x", &byte) == 1) {
                pattern[length] = static_cast<uint8_t>(byte);
                mask[length] = 0xFF;
            }
            p += 2;
        }
        length++;
    }
    
    return Scan(pattern, mask, length, callback);
}

} // namespace RE
} // namespace RawrXD
