#pragma once

// test_masm.h - Header for MASM assembly functions

#ifdef __cplusplus
extern "C" {
#endif

// Simple function that adds two numbers
// Implemented in test_masm.asm (x86) or test_masm_x64.asm (x64)
int AddNumbers(int a, int b);

#ifdef __cplusplus
}
#endif

// Example usage in C++:
// #include "test_masm.h"
// int result = AddNumbers(5, 3);  // Returns 8