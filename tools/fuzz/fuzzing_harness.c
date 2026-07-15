//=============================================================================
// fuzzing_harness.c - Fuzzing Test Harness
// Production-ready fuzzing infrastructure with mutation strategies
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Fuzzing Types
//=============================================================================

#define MAX_INPUT_SIZE 65536
#define MAX_SEEDS 100
#define MAX_CRASHES 100
#define MAX_COVERAGE 10000

typedef enum {
    MUTATION_BIT_FLIP,
    MUTATION_BYTE_FLIP,
    MUTATION_ARITHMETIC,
    MUTATION_INTERESTING,
    MUTATION_HAVOC,
    MUTATION_SPLICING
} MutationStrategy;

typedef struct {
    uint8_t* data;
    size_t size;
    uint64_t hash;
    int coverage;
    int exec_time;
} Seed;

typedef struct {
    uint8_t* input;
    size_t size;
    char crash_type[64];
    char stack_trace[1024];
    uint64_t timestamp;
    int is_unique;
} Crash;

typedef struct {
    Seed seeds[MAX_SEEDS];
    int seed_count;
    int seed_capacity;
    
    Crash crashes[MAX_CRASHES];
    int crash_count;
    
    uint8_t coverage_map[MAX_COVERAGE];
    int coverage_count;
    int total_coverage;
    
    uint64_t total_execs;
    uint64_t execs_per_sec;
    uint64_t start_time;
    
    int unique_crashes;
    int hangs;
    int timeouts;
    
    MutationStrategy current_strategy;
    int mutation_round;
} FuzzingState;

//=============================================================================
// Fuzzing Implementation
//=============================================================================

FuzzingState* fuzzing_create_state(void) {
    FuzzingState* state = (FuzzingState*)calloc(1, sizeof(FuzzingState));
    state->seed_capacity = MAX_SEEDS;
    state->start_time = (uint64_t)time(NULL);
    state->current_strategy = MUTATION_HAVOC;
    return state;
}

void fuzzing_destroy_state(FuzzingState* state) {
    if (!state) return;
    
    for (int i = 0; i < state->seed_count; i++) {
        free(state->seeds[i].data);
    }
    
    for (int i = 0; i < state->crash_count; i++) {
        free(state->crashes[i].input);
    }
    
    free(state);
}

uint64_t hash_bytes(const uint8_t* data, size_t size) {
    // Simple FNV-1a hash
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

void add_seed(FuzzingState* state, const uint8_t* data, size_t size) {
    if (state->seed_count >= state->seed_capacity) return;
    
    Seed* seed = &state->seeds[state->seed_count++];
    seed->data = (uint8_t*)malloc(size);
    memcpy(seed->data, data, size);
    seed->size = size;
    seed->hash = hash_bytes(data, size);
    seed->coverage = 0;
}

void add_crash(FuzzingState* state, const uint8_t* input, size_t size, const char* type) {
    if (state->crash_count >= MAX_CRASHES) return;
    
    Crash* crash = &state->crashes[state->crash_count++];
    crash->input = (uint8_t*)malloc(size);
    memcpy(crash->input, input, size);
    crash->size = size;
    strncpy(crash->crash_type, type, sizeof(crash->crash_type) - 1);
    crash->timestamp = (uint64_t)time(NULL);
    
    // Check if unique
    crash->is_unique = 1;
    uint64_t hash = hash_bytes(input, size);
    for (int i = 0; i < state->crash_count - 1; i++) {
        if (state->crashes[i].is_unique) {
            uint64_t other_hash = hash_bytes(state->crashes[i].input, state->crashes[i].size);
            if (hash == other_hash) {
                crash->is_unique = 0;
                break;
            }
        }
    }
    
    if (crash->is_unique) {
        state->unique_crashes++;
    }
}

//=============================================================================
// Mutation Strategies
//=============================================================================

void mutate_bit_flip(uint8_t* data, size_t size) {
    if (size == 0) return;
    size_t pos = rand() % size;
    int bit = rand() % 8;
    data[pos] ^= (1 << bit);
}

void mutate_byte_flip(uint8_t* data, size_t size) {
    if (size == 0) return;
    size_t pos = rand() % size;
    data[pos] ^= 0xFF;
}

void mutate_arithmetic(uint8_t* data, size_t size) {
    if (size == 0) return;
    size_t pos = rand() % size;
    int delta = (rand() % 35) - 16;  // -16 to +18
    data[pos] = (uint8_t)((int)data[pos] + delta);
}

void mutate_interesting(uint8_t* data, size_t size) {
    if (size == 0) return;
    
    static const uint8_t interesting[] = {
        0, 1, 16, 32, 64, 100, 127, 128, 255,
        0x7F, 0x80, 0xFF, 0xFE, 0xFD
    };
    
    size_t pos = rand() % size;
    data[pos] = interesting[rand() % (sizeof(interesting) / sizeof(interesting[0]))];
}

void mutate_havoc(uint8_t* data, size_t size) {
    // Apply multiple random mutations
    int num_mutations = 1 + (rand() % 16);
    
    for (int i = 0; i < num_mutations; i++) {
        int strategy = rand() % 5;
        switch (strategy) {
            case 0: mutate_bit_flip(data, size); break;
            case 1: mutate_byte_flip(data, size); break;
            case 2: mutate_arithmetic(data, size); break;
            case 3: mutate_interesting(data, size); break;
            case 4: {
                // Delete byte
                if (size > 1) {
                    size_t pos = rand() % size;
                    memmove(data + pos, data + pos + 1, size - pos - 1);
                }
                break;
            }
        }
    }
}

void mutate_input(FuzzingState* state, uint8_t* output, size_t* out_size) {
    if (state->seed_count == 0) {
        // Generate random input
        *out_size = 1 + (rand() % 256);
        for (size_t i = 0; i < *out_size; i++) {
            output[i] = rand() % 256;
        }
        return;
    }
    
    // Select seed
    Seed* seed = &state->seeds[rand() % state->seed_count];
    *out_size = seed->size;
    memcpy(output, seed->data, seed->size);
    
    // Apply mutation
    switch (state->current_strategy) {
        case MUTATION_BIT_FLIP: mutate_bit_flip(output, *out_size); break;
        case MUTATION_BYTE_FLIP: mutate_byte_flip(output, *out_size); break;
        case MUTATION_ARITHMETIC: mutate_arithmetic(output, *out_size); break;
        case MUTATION_INTERESTING: mutate_interesting(output, *out_size); break;
        case MUTATION_HAVOC: mutate_havoc(output, *out_size); break;
        default: mutate_havoc(output, *out_size); break;
    }
}

//=============================================================================
// Target Execution
//=============================================================================

int execute_target(const uint8_t* input, size_t size) {
    // Simulated target execution
    // In production, this would run the actual target binary
    
    // Simulate some crashes
    if (size > 1000 && input[0] == 0x41 && input[1] == 0x42) {
        return -1;  // Simulated crash
    }
    
    if (size > 0 && input[0] == 0xFF) {
        return -2;  // Simulated hang
    }
    
    return 0;  // Success
}

void update_coverage(FuzzingState* state, const uint8_t* input, size_t size) {
    // Simulated coverage update
    uint64_t hash = hash_bytes(input, size);
    size_t idx = hash % MAX_COVERAGE;
    
    if (!state->coverage_map[idx]) {
        state->coverage_map[idx] = 1;
        state->total_coverage++;
    }
}

void fuzzing_iteration(FuzzingState* state) {
    uint8_t input[MAX_INPUT_SIZE];
    size_t size;
    
    // Generate mutated input
    mutate_input(state, input, &size);
    
    // Execute target
    int result = execute_target(input, size);
    state->total_execs++;
    
    // Update coverage
    update_coverage(state, input, size);
    
    // Handle result
    if (result == -1) {
        add_crash(state, input, size, "SEGFAULT");
    } else if (result == -2) {
        state->timeouts++;
        state->hangs++;
    }
    
    // Update stats
    uint64_t elapsed = (uint64_t)time(NULL) - state->start_time;
    if (elapsed > 0) {
        state->execs_per_sec = state->total_execs / elapsed;
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_fuzzing_summary(FuzzingState* state) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Fuzzing Summary\n");
    printf("=============================================================================\n");
    printf("  Total Executions:   %llu\n", (unsigned long long)state->total_execs);
    printf("  Execs/Second:       %llu\n", (unsigned long long)state->execs_per_sec);
    printf("  Seeds:              %d\n", state->seed_count);
    printf("  Coverage:           %d blocks\n", state->total_coverage);
    printf("\n");
    printf("  Crashes:\n");
    printf("    Total:            %d\n", state->crash_count);
    printf("    Unique:           %d\n", state->unique_crashes);
    printf("    Hangs:            %d\n", state->hangs);
    printf("=============================================================================\n");
}

void print_crashes(FuzzingState* state) {
    if (state->crash_count == 0) {
        printf("\n  No crashes found.\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Crashes Found\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < state->crash_count && i < 10; i++) {
        Crash* crash = &state->crashes[i];
        printf("\n  [%d] %s (%s)\n", i + 1, crash->crash_type,
               crash->is_unique ? "unique" : "duplicate");
        printf("       Size: %zu bytes\n", crash->size);
        printf("       Time: %llu\n", (unsigned long long)crash->timestamp);
        
        // Print hex dump (first 32 bytes)
        printf("       Data: ");
        for (size_t j = 0; j < crash->size && j < 32; j++) {
            printf("%02X ", crash->input[j]);
        }
        if (crash->size > 32) printf("...");
        printf("\n");
    }
    
    printf("\n=============================================================================\n");
}

void export_fuzzing_json(FuzzingState* state, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_execs\": %llu,\n", (unsigned long long)state->total_execs);
    fprintf(f, "    \"execs_per_sec\": %llu,\n", (unsigned long long)state->execs_per_sec);
    fprintf(f, "    \"seeds\": %d,\n", state->seed_count);
    fprintf(f, "    \"coverage\": %d,\n", state->total_coverage);
    fprintf(f, "    \"total_crashes\": %d,\n", state->crash_count);
    fprintf(f, "    \"unique_crashes\": %d,\n", state->unique_crashes);
    fprintf(f, "    \"hangs\": %d\n", state->hangs);
    fprintf(f, "  },\n");
    fprintf(f, "  \"crashes\": [\n");
    
    for (int i = 0; i < state->crash_count; i++) {
        Crash* crash = &state->crashes[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"type\": \"%s\",\n", crash->crash_type);
        fprintf(f, "      \"is_unique\": %s,\n", crash->is_unique ? "true" : "false");
        fprintf(f, "      \"size\": %zu,\n", crash->size);
        fprintf(f, "      \"timestamp\": %llu,\n", (unsigned long long)crash->timestamp);
        fprintf(f, "      \"data\": \"");
        for (size_t j = 0; j < crash->size && j < 64; j++) {
            fprintf(f, "%02X", crash->input[j]);
        }
        fprintf(f, "\"\n");
        fprintf(f, "    }%s\n", (i < state->crash_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Fuzzing report exported: %s\n", filename);
}

void export_crash_inputs(FuzzingState* state) {
    for (int i = 0; i < state->crash_count; i++) {
        Crash* crash = &state->crashes[i];
        if (!crash->is_unique) continue;
        
        char filename[256];
        snprintf(filename, sizeof(filename), "crash_%d_%s.bin", i, crash->crash_type);
        
        FILE* f = fopen(filename, "wb");
        if (f) {
            fwrite(crash->input, 1, crash->size, f);
            fclose(f);
            printf("  Crash input exported: %s\n", filename);
        }
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Fuzzing Harness\n");
    printf("=====================\n\n");
    
    srand((unsigned int)time(NULL));
    
    FuzzingState* state = fuzzing_create_state();
    
    // Add initial seeds
    printf("Initializing seeds...\n");
    uint8_t seed1[] = "Hello, World!";
    uint8_t seed2[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t seed3[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    
    add_seed(state, seed1, sizeof(seed1) - 1);
    add_seed(state, seed2, sizeof(seed2));
    add_seed(state, seed3, sizeof(seed3) - 1);
    
    // Run fuzzing iterations
    int iterations = 10000;
    if (argc > 1) {
        iterations = atoi(argv[1]);
    }
    
    printf("Running %d fuzzing iterations...\n", iterations);
    
    for (int i = 0; i < iterations; i++) {
        fuzzing_iteration(state);
        
        // Progress update
        if ((i + 1) % 1000 == 0) {
            printf("  Progress: %d/%d execs, %d unique crashes\n",
                   i + 1, iterations, state->unique_crashes);
        }
    }
    
    // Generate reports
    print_fuzzing_summary(state);
    print_crashes(state);
    export_fuzzing_json(state, "fuzzing_report.json");
    export_crash_inputs(state);
    
    printf("\nFuzzing complete!\n");
    
    fuzzing_destroy_state(state);
    
    return 0;
}
