// ============================================================================
// speciator_stubs.cpp - Stub implementations for speciator engine functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

void asm_speciator_init() {
    OutputDebugStringA("[Speciator] asm_speciator_init stub called\n");
}

void asm_speciator_create_genome() {
    OutputDebugStringA("[Speciator] asm_speciator_create_genome stub called\n");
}

void asm_speciator_evaluate() {
    OutputDebugStringA("[Speciator] asm_speciator_evaluate stub called\n");
}

void asm_speciator_crossover() {
    OutputDebugStringA("[Speciator] asm_speciator_crossover stub called\n");
}

void asm_speciator_mutate() {
    OutputDebugStringA("[Speciator] asm_speciator_mutate stub called\n");
}

void asm_speciator_select() {
    OutputDebugStringA("[Speciator] asm_speciator_select stub called\n");
}

void asm_speciator_speciate() {
    OutputDebugStringA("[Speciator] asm_speciator_speciate stub called\n");
}

void asm_speciator_gen_variant() {
    OutputDebugStringA("[Speciator] asm_speciator_gen_variant stub called\n");
}

void asm_speciator_compete() {
    OutputDebugStringA("[Speciator] asm_speciator_compete stub called\n");
}

void asm_speciator_migrate() {
    OutputDebugStringA("[Speciator] asm_speciator_migrate stub called\n");
}

void* asm_speciator_get_stats() {
    OutputDebugStringA("[Speciator] asm_speciator_get_stats stub called\n");
    return nullptr;
}

void asm_speciator_shutdown() {
    OutputDebugStringA("[Speciator] asm_speciator_shutdown stub called\n");
}

} // extern "C"
