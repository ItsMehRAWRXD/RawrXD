#pragma once
// ============================================================================
// JITAssembler.hpp — RawrXD Native JIT Emitter
// ============================================================================
// Produces executable x64 code from InstructionIR using InstructionEncoderX64,
// then allocates RX memory and resolves internal label fixups.
//
// Windows: VirtualAlloc/VirtualProtect + FlushInstructionCache
// No external compiler/assembler required.
// ============================================================================

#include "../../compiler_backend/InstructionEncoderX64.hpp"
#include "../../compiler_backend/rawr_backend_types.hpp"
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>

namespace RawrXD {
namespace Backend {

class JITAssembler {
public:
    struct JITFunction {
        uint8_t* code = nullptr;
        size_t size = 0;
        uint64_t entryAddr = 0;

        JITFunction() = default;
        ~JITFunction();

        // Disable copy; enable move (transfer ownership)
        JITFunction(const JITFunction&) = delete;
        JITFunction& operator=(const JITFunction&) = delete;
        JITFunction(JITFunction&& other) noexcept
            : code(other.code), size(other.size), entryAddr(other.entryAddr) {
            other.code = nullptr;
        }
        JITFunction& operator=(JITFunction&& other) noexcept {
            if (this != &other) {
                if (code) JITAssembler::freeExecutable(code);
                code = other.code;
                size = other.size;
                entryAddr = other.entryAddr;
                other.code = nullptr;
            }
            return *this;
        }

        // C++ callable wrapper: assumes System V / Windows x64 calling convention
        template<typename R, typename... Args>
        R call(Args... args) const {
            using Fn = R(*)(Args...);
            Fn fn = reinterpret_cast<Fn>(entryAddr);
            return fn(args...);
        }
    };

    JITAssembler();
    ~JITAssembler();

    // Reset encoder and internal state for new function
    void reset();

    // Append a single IR instruction (encodes + records fixups)
    void emit(const InstructionIR& inst);

    // Create a label at current offset
    uint32_t label(const std::string& name = "");
    // Bind a label to current code offset
    void bind(uint32_t labelId);

    // Finalize: allocate executable memory, copy bytes, resolve fixups
    JITFunction finalize();

    // Current code size in bytes (unfinalized)
    size_t codeSize() const { return m_code.size(); }

private:
    InstructionEncoderX64 m_encoder;
    std::vector<uint8_t> m_code;
    std::vector<Fixup> m_pendingFixups;
    std::unordered_map<uint32_t, size_t> m_labelOffsets; // labelId -> code offset
    uint32_t m_nextLabelId = 1;

    static uint8_t* allocateExecutable(size_t size);
    static void freeExecutable(uint8_t* ptr);
    static void makeExecutable(uint8_t* ptr, size_t size);
};

} // namespace Backend
} // namespace RawrXD
