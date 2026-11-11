//=============================================================================
// codex_native_bridge.h - Header for Codex Native Bridge
//=============================================================================

#ifndef CODEX_NATIVE_BRIDGE_H
#define CODEX_NATIVE_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// Version
//=============================================================================

#define CODEX_BRIDGE_VERSION "1.0.0"
#define CODEX_BRIDGE_VERSION_MAJOR 1
#define CODEX_BRIDGE_VERSION_MINOR 0
#define CODEX_BRIDGE_VERSION_PATCH 0

//=============================================================================
// Constants
//=============================================================================

#define MAX_INSTRUCTIONS 65536
#define MAX_LINE_LENGTH 1024
#define MAX_OPERAND_LENGTH 256
#define MAX_MNEMONIC_LENGTH 32

//=============================================================================
// Structures
//=============================================================================

typedef struct {
    uint64_t address;
    uint8_t bytes[15];      // Max x64 instruction length
    int byte_count;
    char mnemonic[32];
    char operands[128];
} CodexInstruction;

typedef struct {
    CodexInstruction* instructions;
    int count;
    int capacity;
} CodexInstructionList;

//=============================================================================
// Bridge Functions
//=============================================================================

// Convert Codex JSON disassembly to native assembler format
// Returns: number of instructions converted, or -1 on error
int codex_to_native_asm(const char* codex_json, const char* output_asm);

// Convert native assembler format to Codex JSON
// Returns: 0 on success, -1 on error
// Output is allocated and returned in codex_json_out (caller must free)
int native_asm_to_codex_format(const char* asm_file, char** codex_json_out);

// Parse a single Codex instruction from JSON
int parse_codex_instruction(const char* json_line, CodexInstruction* inst);

// Convert a single instruction to native format
int convert_instruction_to_native(const CodexInstruction* inst, char* output, size_t buf_size);

//=============================================================================
// Utility Functions
//=============================================================================

// Get version string
const char* codex_bridge_get_version(void);

// Get last error message
const char* codex_bridge_get_last_error(void);

// Clear error state
void codex_bridge_clear_error(void);

//=============================================================================
// Integration Helpers
//=============================================================================

// Check if a mnemonic is supported by the native assembler
int is_mnemonic_supported(const char* mnemonic);

// Get native assembler syntax for an instruction
const char* get_native_syntax(const char* codex_mnemonic);

#ifdef __cplusplus
}
#endif

#endif // CODEX_NATIVE_BRIDGE_H
