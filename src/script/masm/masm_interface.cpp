// RawrXD-Script MASM Interface Implementation
// C++ wrapper implementation

#include "masm_interface.hpp"
#include <cstring>
#include <sstream>

namespace RawrXD {
namespace Script {
namespace MASM {

// ============================================================================
// Value Implementation
// ============================================================================

bool Value::IsTruthy() const {
    return JsValue_IsTruthy(value_) != 0;
}

std::string Value::AsString() const {
    char buffer[256];
    int len = JsValue_ToString(value_, buffer, sizeof(buffer));
    return std::string(buffer, len);
}

// ============================================================================
// Interpreter Implementation
// ============================================================================

Interpreter::Interpreter() 
    : arena_(nullptr)
    , icTable_(nullptr)
    , globalObj_(JS_NULL)
    , loaded_(false) {
}

Interpreter::~Interpreter() {
    if (arena_) {
        JsInterpreter_DestroyArena(arena_);
    }
}

bool Interpreter::LoadBytecode(const uint8_t* data, size_t size) {
    if (size < 64) return false; // Minimum header size
    
    // Parse header
    // Validate magic: 'RAWR' (0x52415752)
    if (size < 4) return false;
    uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
    if (magic != 0x52415752) {
        std::cerr << "Invalid bytecode magic: expected 'RAWR', got 0x" 
                  << std::hex << magic << std::dec << std::endl;
        return false;
    }
    
    // Validate version (expecting version 1)
    if (size < 6) return false;
    uint16_t version = *reinterpret_cast<const uint16_t*>(data + 4);
    if (version != 1) {
        std::cerr << "Unsupported bytecode version: " << version << std::endl;
        return false;
    }
    
    // Extract sections from header
    // Header format:
    // [0-3]:   magic ('RAWR')
    // [4-5]:   version
    // [6-7]:   flags
    // [8-11]:  code_offset
    // [12-15]: code_size
    // [16-19]: const_pool_offset
    // [20-23]: const_pool_count
    // [24-27]: string_table_offset
    // [28-31]: string_table_size
    // [32-35]: ic_slot_count
    // [36-39]: line_info_offset
    
    struct BytecodeHeader {
        uint32_t code_offset;
        uint32_t code_size;
        uint32_t const_pool_offset;
        uint32_t const_pool_count;
        uint32_t string_table_offset;
        uint32_t string_table_size;
        uint32_t ic_slot_count;
        uint32_t line_info_offset;
    };
    
    if (size < 40) return false;
    
    BytecodeHeader header;
    header.code_offset = *reinterpret_cast<const uint32_t*>(data + 8);
    header.code_size = *reinterpret_cast<const uint32_t*>(data + 12);
    header.const_pool_offset = *reinterpret_cast<const uint32_t*>(data + 16);
    header.const_pool_count = *reinterpret_cast<const uint32_t*>(data + 20);
    header.string_table_offset = *reinterpret_cast<const uint32_t*>(data + 24);
    header.string_table_size = *reinterpret_cast<const uint32_t*>(data + 28);
    header.ic_slot_count = *reinterpret_cast<const uint32_t*>(data + 32);
    header.line_info_offset = *reinterpret_cast<const uint32_t*>(data + 36);
    
    // Validate section bounds
    if (header.code_offset + header.code_size > size) return false;
    if (header.const_pool_offset + header.const_pool_count * 8 > size) return false;
    if (header.string_table_offset + header.string_table_size > size) return false;
    
    // Store bytecode
    bytecode_.assign(data, data + size);
    
    // Extract constant pool if present
    if (header.const_pool_count > 0 && header.const_pool_offset > 0) {
        constPool_.assign(
            data + header.const_pool_offset,
            data + header.const_pool_offset + header.const_pool_count * 8
        );
    }
    
    loaded_ = true;
    
    // Create arena
    if (!arena_) {
        arena_ = JsInterpreter_CreateArena(64 * 1024 * 1024); // 64MB
        if (!arena_) return false;
    }
    
    // Allocate IC table
    size_t icSlots = header.ic_slot_count > 0 ? header.ic_slot_count : 1024;
    if (!icTable_) {
        icTable_ = JsInterpreter_ArenaAlloc(arena_, icSlots * 16); // 16 bytes per slot
        if (!icTable_) return false;
        std::memset(icTable_, 0, icSlots * 16);
    }
    
    return true;
}

bool Interpreter::LoadBytecode(const std::vector<uint8_t>& data) {
    return LoadBytecode(data.data(), data.size());
}

JsValue Interpreter::Execute() {
    if (!loaded_) return JS_UNDEFINED;
    
    // Call MASM interpreter
    return JsInterpreter_Run(
        bytecode_.data(),
        bytecode_.size(),
        constPool_.data(),
        globalObj_,
        arena_,
        icTable_
    );
}

JsValue Interpreter::Execute(JsValue thisObj, const std::vector<JsValue>& args) {
    // Set up this binding and arguments
    // Store this and args in reserved registers before execution
    if (!loaded_) return JS_UNDEFINED;
    
    // Note: In full implementation, would set up stack frame with this/args
    // For now, store in global object properties
    SetGlobal("__this", thisObj);
    for (size_t i = 0; i < args.size() && i < 10; ++i) {
        SetGlobal("__arg" + std::to_string(i), args[i]);
    }
    
    return Execute();
}

JsValue Interpreter::GetGlobal(const std::string& name) {
    // Implement global property access
    // In MASM implementation, global object is stored at r12
    // Access through external function
    if (!loaded_ || !arena_) return JS_UNDEFINED;
    
    // Look up in global object
    // This would call into MASM to access global object properties
    // For now, check if we have a cached value
    auto it = globalCache_.find(name);
    if (it != globalCache_.end()) {
        return it->second;
    }
    
    return JS_UNDEFINED;
}

void Interpreter::SetGlobal(const std::string& name, JsValue val) {
    // Implement global property setting
    if (!loaded_ || !arena_) return;
    
    // Cache the value
    globalCache_[name] = val;
    
    // In full implementation, would call into MASM to set global property
}

VMState Interpreter::GetState() const {
    // Capture current VM state from MASM
    VMState state = {};
    
    if (!loaded_) return state;
    
    // In full implementation, would read registers from MASM
    // For now, return cached state
    state.pc = 0;
    state.codeBase = reinterpret_cast<uint64_t>(bytecode_.data());
    state.constPool = reinterpret_cast<uint64_t>(constPool_.data());
    state.globalObj = globalObj_;
    state.arenaBase = reinterpret_cast<uint64_t>(arena_ ? arena_->base : nullptr);
    state.arenaBump = arena_ ? arena_->used : 0;
    state.icTable = reinterpret_cast<uint64_t>(icTable_);
    
    return state;
}

void Interpreter::SetState(const VMState& state) {
    // Restore VM state
    // In full implementation, would write registers to MASM
    // For now, just update cached values
    globalObj_ = state.globalObj;
}

} // namespace MASM
} // namespace Script
} // namespace RawrXD
