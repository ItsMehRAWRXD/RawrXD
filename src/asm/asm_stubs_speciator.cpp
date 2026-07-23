// asm_stubs_speciator.cpp - Stub implementations for speciator_engine.asm exports
// Provides C++ fallbacks when MASM kernels are not available

#include <cstdint>
#include <cstring>

extern "C" {

int asm_speciator_init() {
    return 0;
}

int asm_speciator_create_genome(void* genomeOut, uint32_t complexity) {
    (void)genomeOut; (void)complexity;
    return 0;
}

int asm_speciator_evaluate(const void* genome, const void* fitnessFn, double* scoreOut) {
    (void)genome; (void)fitnessFn; (void)scoreOut;
    return 0;
}

int asm_speciator_crossover(const void* parentA, const void* parentB, void* childOut) {
    (void)parentA; (void)parentB; (void)childOut;
    return 0;
}

int asm_speciator_mutate(void* genome, uint32_t mutationRate) {
    (void)genome; (void)mutationRate;
    return 0;
}

int asm_speciator_select(const void* population, uint32_t popSize, void* selectedOut, uint32_t selectCount) {
    (void)population; (void)popSize; (void)selectedOut; (void)selectCount;
    return 0;
}

int asm_speciator_speciate(const void* population, uint32_t popSize, void* speciesOut) {
    (void)population; (void)popSize; (void)speciesOut;
    return 0;
}

int asm_speciator_gen_variant(const void* baseGenome, void* variantOut, uint32_t variantType) {
    (void)baseGenome; (void)variantOut; (void)variantType;
    return 0;
}

int asm_speciator_compete(const void* speciesA, const void* speciesB, double* fitnessDelta) {
    (void)speciesA; (void)speciesB; (void)fitnessDelta;
    return 0;
}

int asm_speciator_migrate(const void* emigrants, uint32_t count, void* immigrantsOut) {
    (void)emigrants; (void)count; (void)immigrantsOut;
    return 0;
}

void* asm_speciator_get_stats() {
    return nullptr;
}

int asm_speciator_shutdown() {
    return 0;
}

} // extern "C"
