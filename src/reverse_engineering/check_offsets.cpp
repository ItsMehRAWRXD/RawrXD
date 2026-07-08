#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "RawrCodex_Multi_v2.hpp"

using namespace RawrCodex;

int main() {
    printf("RawInstruction offsets:\n");
    printf("  va: %zu\n", offsetof(RawInstruction, va));
    printf("  length: %zu\n", offsetof(RawInstruction, length));
    printf("  arch: %zu\n", offsetof(RawInstruction, arch));
    printf("  bytes: %zu\n", offsetof(RawInstruction, bytes));
    printf("  encoding: %zu\n", offsetof(RawInstruction, encoding));
    printf("  sizeof(RawInstruction): %zu\n", sizeof(RawInstruction));
    
    printf("\nSemanticInstruction offsets:\n");
    printf("  mnemonic: %zu\n", offsetof(SemanticInstruction, mnemonic));
    printf("  instrClass: %zu\n", offsetof(SemanticInstruction, instrClass));
    printf("  arch: %zu\n", offsetof(SemanticInstruction, arch));
    printf("  sizeof(SemanticInstruction): %zu\n", sizeof(SemanticInstruction));
    
    printf("\nDecodedInstruction offsets:\n");
    printf("  raw: %zu\n", offsetof(DecodedInstruction, raw));
    printf("  semantic: %zu\n", offsetof(DecodedInstruction, semantic));
    printf("  sizeof(DecodedInstruction): %zu\n", sizeof(DecodedInstruction));
    
    return 0;
}