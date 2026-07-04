// RawrXD-Script Bytecode Implementation
// Phase 1: Working Implementation

#include "bytecode.hpp"
#include <string>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace RawrXD {
namespace Script {
namespace Bytecode {

// Opcode name table
const char* GetOpcodeName(Opcode op) {
    switch (op) {
        case Opcode::OP_LOAD_CONST: return "LOAD_CONST";
        case Opcode::OP_LOAD_INT: return "LOAD_INT";
        case Opcode::OP_LOAD_DOUBLE: return "LOAD_DOUBLE";
        case Opcode::OP_LOAD_STRING: return "LOAD_STRING";
        case Opcode::OP_LOAD_NULL: return "LOAD_NULL";
        case Opcode::OP_LOAD_UNDEFINED: return "LOAD_UNDEFINED";
        case Opcode::OP_LOAD_TRUE: return "LOAD_TRUE";
        case Opcode::OP_LOAD_FALSE: return "LOAD_FALSE";
        case Opcode::OP_LOAD_ZERO: return "LOAD_ZERO";
        case Opcode::OP_LOAD_ONE: return "LOAD_ONE";
        case Opcode::OP_MOVE: return "MOVE";
        case Opcode::OP_SWAP: return "SWAP";
        case Opcode::OP_ADD: return "ADD";
        case Opcode::OP_SUB: return "SUB";
        case Opcode::OP_MUL: return "MUL";
        case Opcode::OP_DIV: return "DIV";
        case Opcode::OP_MOD: return "MOD";
        case Opcode::OP_NEG: return "NEG";
        case Opcode::OP_INC: return "INC";
        case Opcode::OP_DEC: return "DEC";
        case Opcode::OP_BIT_AND: return "BIT_AND";
        case Opcode::OP_BIT_OR: return "BIT_OR";
        case Opcode::OP_BIT_XOR: return "BIT_XOR";
        case Opcode::OP_BIT_NOT: return "BIT_NOT";
        case Opcode::OP_SHL: return "SHL";
        case Opcode::OP_SHR: return "SHR";
        case Opcode::OP_SHR_U: return "SHR_U";
        case Opcode::OP_EQ: return "EQ";
        case Opcode::OP_NEQ: return "NEQ";
        case Opcode::OP_LT: return "LT";
        case Opcode::OP_LTE: return "LTE";
        case Opcode::OP_GT: return "GT";
        case Opcode::OP_GTE: return "GTE";
        case Opcode::OP_STRICT_EQ: return "STRICT_EQ";
        case Opcode::OP_STRICT_NEQ: return "STRICT_NEQ";
        case Opcode::OP_JMP: return "JMP";
        case Opcode::OP_JMP_COND: return "JMP_COND";
        case Opcode::OP_JMP_NOT_COND: return "JMP_NOT_COND";
        case Opcode::OP_CALL: return "CALL";
        case Opcode::OP_CALL_NATIVE: return "CALL_NATIVE";
        case Opcode::OP_RETURN: return "RETURN";
        case Opcode::OP_THROW: return "THROW";
        case Opcode::OP_GET_PROP: return "GET_PROP";
        case Opcode::OP_SET_PROP: return "SET_PROP";
        case Opcode::OP_GET_ELEM: return "GET_ELEM";
        case Opcode::OP_SET_ELEM: return "SET_ELEM";
        case Opcode::OP_CREATE_ARRAY: return "CREATE_ARRAY";
        case Opcode::OP_CREATE_OBJECT: return "CREATE_OBJECT";
        case Opcode::OP_CREATE_FUNC: return "CREATE_FUNC";
        case Opcode::OP_BIND_THIS: return "BIND_THIS";
        case Opcode::OP_TYPEOF: return "TYPEOF";
        case Opcode::OP_INSTANCEOF: return "INSTANCEOF";
        case Opcode::OP_IN: return "IN";
        case Opcode::OP_DEBUG_BREAK: return "DEBUG_BREAK";
        case Opcode::OP_DEBUG_LOG: return "DEBUG_LOG";
        case Opcode::OP_NOP: return "NOP";
        default: return "UNKNOWN";
    }
}

OpcodeCategory GetOpcodeCategory(Opcode op) {
    uint8_t code = static_cast<uint8_t>(op);
    if (code <= 0x0F) return OpcodeCategory::Constant;
    if (code <= 0x1F) return OpcodeCategory::Register;
    if (code <= 0x2F) return OpcodeCategory::Arithmetic;
    if (code <= 0x3F) return OpcodeCategory::Bitwise;
    if (code <= 0x4F) return OpcodeCategory::Comparison;
    if (code <= 0x5F) return OpcodeCategory::ControlFlow;
    if (code <= 0x6F) return OpcodeCategory::Object;
    if (code <= 0x7F) return OpcodeCategory::Array;
    if (code <= 0x8F) return OpcodeCategory::Function;
    if (code <= 0x9F) return OpcodeCategory::Iteration;
    if (code <= 0xAF) return OpcodeCategory::Async;
    if (code <= 0xBF) return OpcodeCategory::Optimized;
    if (code >= 0xF0) return OpcodeCategory::Debug;
    return OpcodeCategory::Other;
}

// BytecodeModule implementation
BytecodeModule::BytecodeModule() 
    : ic_slot_count_(0), strict_mode_(false) {
    std::memset(&header_, 0, sizeof(header_));
}

void BytecodeModule::AppendInstruction(const Instruction& inst) {
    code_.push_back(inst);
}

void BytecodeModule::AppendInstructions(const std::vector<Instruction>& insts) {
    code_.insert(code_.end(), insts.begin(), insts.end());
}

uint32_t BytecodeModule::AddConstant(const Constant& constant) {
    uint32_t index = static_cast<uint32_t>(constant_pool_.size());
    constant_pool_.push_back(constant);
    return index;
}

uint32_t BytecodeModule::AddString(const std::string& str) {
    // Check if string already exists
    uint32_t existing = FindString(str);
    if (existing != UINT32_MAX) {
        return existing;
    }
    
    // Add new string
    uint32_t offset = static_cast<uint32_t>(string_table_.size());
    string_table_.insert(string_table_.end(), str.begin(), str.end());
    string_table_.push_back('\0');  // Null terminate
    
    return offset;
}

const Constant& BytecodeModule::GetConstant(uint32_t index) const {
    return constant_pool_[index];
}

std::string BytecodeModule::GetString(uint32_t index) const {
    // Find null terminator
    size_t end = index;
    while (end < string_table_.size() && string_table_[end] != '\0') {
        end++;
    }
    return std::string(string_table_.begin() + index, string_table_.begin() + end);
}

uint32_t BytecodeModule::AllocateICSlot() {
    return ic_slot_count_++;
}

void BytecodeModule::AddLineInfo(uint32_t bytecode_offset, uint32_t line, uint32_t col) {
    debug_info_.line_table.push_back({bytecode_offset, line, col});
}

uint32_t BytecodeModule::FindString(const std::string& str) const {
    // Simple linear search - could be optimized with hash table
    size_t pos = 0;
    while (pos < string_table_.size()) {
        // Find null terminator
        size_t end = pos;
        while (end < string_table_.size() && string_table_[end] != '\0') {
            end++;
        }
        
        // Compare
        if (end - pos == str.size()) {
            bool match = true;
            for (size_t i = 0; i < str.size(); i++) {
                if (string_table_[pos + i] != str[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return static_cast<uint32_t>(pos);
            }
        }
        
        pos = end + 1;  // Skip null terminator
    }
    
    return UINT32_MAX;
}

// Serialization
std::vector<uint8_t> BytecodeModule::Serialize() const {
    std::vector<uint8_t> result;
    
    // Calculate offsets
    size_t header_size = sizeof(BytecodeHeader);
    size_t code_offset = header_size;
    size_t const_offset = code_offset + code_.size() * sizeof(Instruction);
    size_t string_offset = const_offset + constant_pool_.size() * sizeof(Constant);
    size_t line_offset = string_offset + string_table_.size();
    
    // Align to 8 bytes
    auto align8 = [](size_t val) { return (val + 7) & ~7; };
    line_offset = align8(line_offset);
    
    // Build header
    BytecodeHeader header;
    header.magic = kBytecodeMagic;
    header.version = kBytecodeVersion;
    header.flags = strict_mode_ ? BC_FLAG_STRICT_MODE : 0;
    header.code_offset = static_cast<uint32_t>(code_offset);
    header.code_size = static_cast<uint32_t>(code_.size() * sizeof(Instruction));
    header.const_pool_offset = static_cast<uint32_t>(const_offset);
    header.const_pool_count = static_cast<uint32_t>(constant_pool_.size());
    header.string_table_offset = static_cast<uint32_t>(string_offset);
    header.string_table_size = static_cast<uint32_t>(string_table_.size());
    header.ic_slot_count = ic_slot_count_;
    header.line_info_offset = static_cast<uint32_t>(line_offset);
    
    // Reserve space
    size_t total_size = line_offset;
    if (!debug_info_.line_table.empty()) {
        total_size += debug_info_.line_table.size() * sizeof(LineInfoEntry);
    }
    result.resize(total_size);
    
    // Write header
    std::memcpy(result.data(), &header, sizeof(header));
    
    // Write code
    std::memcpy(result.data() + code_offset, code_.data(), code_.size() * sizeof(Instruction));
    
    // Write constants
    std::memcpy(result.data() + const_offset, constant_pool_.data(), 
                constant_pool_.size() * sizeof(Constant));
    
    // Write strings
    std::memcpy(result.data() + string_offset, string_table_.data(), string_table_.size());
    
    // Write line info
    if (!debug_info_.line_table.empty()) {
        std::memcpy(result.data() + line_offset, debug_info_.line_table.data(),
                    debug_info_.line_table.size() * sizeof(LineInfoEntry));
    }
    
    return result;
}

bool BytecodeModule::Deserialize(const uint8_t* data, size_t size) {
    if (size < sizeof(BytecodeHeader)) return false;
    
    // Read header
    std::memcpy(&header_, data, sizeof(BytecodeHeader));
    
    // Validate
    if (header_.magic != kBytecodeMagic) return false;
    if (header_.version != kBytecodeVersion) return false;
    
    // Read code
    size_t code_count = header_.code_size / sizeof(Instruction);
    code_.resize(code_count);
    std::memcpy(code_.data(), data + header_.code_offset, header_.code_size);
    
    // Read constants
    constant_pool_.resize(header_.const_pool_count);
    std::memcpy(constant_pool_.data(), data + header_.const_pool_offset,
                header_.const_pool_count * sizeof(Constant));
    
    // Read strings
    string_table_.resize(header_.string_table_size);
    std::memcpy(string_table_.data(), data + header_.string_table_offset,
                header_.string_table_size);
    
    // Read line info
    if (header_.line_info_offset > 0 && header_.line_info_offset < size) {
        size_t line_count = (size - header_.line_info_offset) / sizeof(LineInfoEntry);
        debug_info_.line_table.resize(line_count);
        std::memcpy(debug_info_.line_table.data(), data + header_.line_info_offset,
                    line_count * sizeof(LineInfoEntry));
    }
    
    ic_slot_count_ = header_.ic_slot_count;
    strict_mode_ = (header_.flags & BC_FLAG_STRICT_MODE) != 0;
    
    return true;
}

bool BytecodeModule::LoadFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    return Deserialize(data.data(), data.size());
}

bool BytecodeModule::SaveToFile(const std::string& filename) const {
    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;
    
    auto data = Serialize();
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    return file.good();
}

// Disassembly
std::string BytecodeModule::Disassemble() const {
    std::ostringstream out;
    
    out << "RawrXD-Script Bytecode Disassembly\n";
    out << "=================================\n\n";
    
    out << "Header:\n";
    out << "  Magic: 0x" << std::hex << header_.magic << std::dec << "\n";
    out << "  Version: " << header_.version << "\n";
    out << "  Flags: " << header_.flags << "\n";
    out << "  Code Size: " << header_.code_size << " bytes\n";
    out << "  Constants: " << header_.const_pool_count << "\n";
    out << "  Strings: " << header_.string_table_size << " bytes\n";
    out << "  IC Slots: " << header_.ic_slot_count << "\n\n";
    
    out << "Instructions:\n";
    for (size_t i = 0; i < code_.size(); i++) {
        const Instruction& inst = code_[i];
        Opcode op = static_cast<Opcode>(inst.opcode);
        
        out << std::setw(4) << i << ": ";
        out << std::left << std::setw(20) << GetOpcodeName(op) << " ";
        out << "r" << (int)inst.dest_reg;
        
        auto cat = GetOpcodeCategory(op);
        if (cat == OpcodeCategory::Arithmetic || 
            cat == OpcodeCategory::Comparison ||
            cat == OpcodeCategory::Bitwise) {
            out << ", r" << (int)inst.src_a << ", r" << (int)inst.src_b;
        }
        
        out << "\n";
    }
    
    return out.str();
}

} // namespace Bytecode
} // namespace Script
} // namespace RawrXD
