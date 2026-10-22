// c_ast_lower.h — the production front end path.
//
// The RawrXD C compiler has one canonical path:
//
//     source -> C10 preprocessor -> C11 parser -> AST -> x64 lowering
//                  -> .asm -> rawr_asm -> .obj -> rawrxd_link -> .exe
//
// This file holds the last two steps: the lowering of the C11 tree into the
// assembly the certified assembler reads, and the driver that runs the
// preprocessor and the parser to produce the tree.
//
// The older front end in c_stage2.cpp is kept for regression comparison. It
// has its own parser and its own tree, and it is NOT the production path.

#ifndef RAWR_COMPILER_C_AST_LOWER_H
#define RAWR_COMPILER_C_AST_LOWER_H

#include "rawrstd/string.h"

namespace rawr {

/// @brief Compiles a C source file to x64 assembly.
///
/// Runs the preprocessor and the parser, lowers the tree, and writes the
/// assembly. Returns false and fills error with the reason when the source
/// cannot be compiled: a diagnostic, never invalid machine code.
bool c_ast_compile_to_asm(const char* source_path, const char* asm_path,
                           rawrstd::String* error);

} // namespace rawr

#endif // RAWR_COMPILER_C_AST_LOWER_H
