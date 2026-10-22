// The C front end.
//
// Compiles C source to x64 assembly in the dialect the first-party
// assembler reads.

#ifndef RAWR_COMPILER_C_STAGE2_H
#define RAWR_COMPILER_C_STAGE2_H

#include "rawrstd/string.h"

namespace rawr {

/// @brief Compile a C source file to x64 assembly.
///
/// Writes the assembly to asm_path. Returns false and fills error with the
/// reason when the source cannot be read, cannot be parsed, or cannot be
/// written.
bool c_compile_to_asm(const char* source_path, const char* asm_path,
                       rawrstd::String* error);

} // namespace rawr

#endif // RAWR_COMPILER_C_STAGE2_H
