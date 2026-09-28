// ============================================================================
// JITAssembler.cpp — RawrXD Native JIT Emitter Implementation
// ============================================================================

#include "JITAssembler.hpp"
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace Backend {

// ============================================================================
// Platform Memory
// ============================================================================

uint8_t* JITAssembler::allocateExecutable(size_t size) {
#ifdef _WIN32
    return static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
#else
    // POSIX placeholder
    return nullptr;
#endif
}

void JITAssembler::freeExecutable(uint8_t* ptr) {
#ifdef _WIN32
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
#else
    (void)ptr;
#endif
}

void JITAssembler::makeExecutable(uint8_t* ptr, size_t size) {
#ifdef _WIN32
    DWORD oldProtect = 0;
    VirtualProtect(ptr, size, PAGE_EXECUTE_READ, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), ptr, size);
#else
    (void)ptr; (void)size;
#endif
}

// ============================================================================
// Construction / Lifecycle
// ============================================================================

JITAssembler::JITAssembler() = default;
JITAssembler::~JITAssembler() = default;

JITAssembler::JITFunction::~JITFunction() {
    if (code) {
        JITAssembler::freeExecutable(code);
    }
}

void JITAssembler::reset() {
    m_code.clear();
    m_pendingFixups.clear();
    m_labelOffsets.clear();
    m_encoder.reset();
}

// ============================================================================
// Labeling
// ============================================================================

uint32_t JITAssembler::label(const std::string& name) {
    return m_encoder.createLabel(name);
}

void JITAssembler::bind(uint32_t labelId) {
    m_encoder.bindLabel(labelId, m_code.size());
    m_labelOffsets[labelId] = m_code.size();
}

// ============================================================================
// Emission
// ============================================================================

void JITAssembler::emit(const InstructionIR& inst) {
    EncodedInstruction result = m_encoder.encode(inst);
    size_t baseOffset = m_code.size();
    m_code.insert(m_code.end(), result.bytes.begin(), result.bytes.end());
    for (auto fixup : result.fixups) {
        fixup.codeOffset += baseOffset;
        m_pendingFixups.push_back(fixup);
    }
}

// ============================================================================
// Finalization
// ============================================================================

JITAssembler::JITFunction JITAssembler::finalize() {
    JITFunction result;
    if (m_code.empty()) {
        return result;
    }

    size_t allocSize = m_code.size();
    // Round up to page granularity for safety
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t page = si.dwPageSize;
    allocSize = (allocSize + page - 1) & ~(page - 1);
#endif

    uint8_t* mem = allocateExecutable(allocSize);
    if (!mem) {
        return result;
    }

    std::memcpy(mem, m_code.data(), m_code.size());

    // Resolve internal label fixups
    for (const auto& fixup : m_pendingFixups) {
        if (fixup.labelId == 0) {
            // RipRel32 with no label — displacement already correct relative to buffer
            continue;
        }
        auto it = m_labelOffsets.find(fixup.labelId);
        if (it == m_labelOffsets.end()) {
            // Unbound label — cannot resolve
            continue;
        }
        size_t targetOffset = it->second;

        if (fixup.kind == FixupKind::Rel32) {
            int32_t rel = static_cast<int32_t>(targetOffset - (fixup.codeOffset + 4));
            mem[fixup.codeOffset + 0] = static_cast<uint8_t>(rel & 0xFF);
            mem[fixup.codeOffset + 1] = static_cast<uint8_t>((rel >> 8) & 0xFF);
            mem[fixup.codeOffset + 2] = static_cast<uint8_t>((rel >> 16) & 0xFF);
            mem[fixup.codeOffset + 3] = static_cast<uint8_t>((rel >> 24) & 0xFF);
        } else if (fixup.kind == FixupKind::Rel8) {
            int8_t rel = static_cast<int8_t>(targetOffset - (fixup.codeOffset + 1));
            mem[fixup.codeOffset] = static_cast<uint8_t>(rel);
        } else if (fixup.kind == FixupKind::RipRel32) {
            int32_t rel = static_cast<int32_t>(targetOffset - (fixup.codeOffset + 4) + fixup.addend);
            mem[fixup.codeOffset + 0] = static_cast<uint8_t>(rel & 0xFF);
            mem[fixup.codeOffset + 1] = static_cast<uint8_t>((rel >> 8) & 0xFF);
            mem[fixup.codeOffset + 2] = static_cast<uint8_t>((rel >> 16) & 0xFF);
            mem[fixup.codeOffset + 3] = static_cast<uint8_t>((rel >> 24) & 0xFF);
        }
    }

    makeExecutable(mem, allocSize);

    result.code = mem;
    result.size = m_code.size();
    result.entryAddr = reinterpret_cast<uint64_t>(mem);
    return result;
}

} // namespace Backend
} // namespace RawrXD
