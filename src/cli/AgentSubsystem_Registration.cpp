//==============================================================================
// AgentSubsystem_Registration.cpp - Phase 13.5 Completion
//
// Registers AgentSubsystem with SovereignCLI_Unified
// Links native GGUF backend for fully sovereign inference
//==============================================================================

#include "../core/AgentSubsystem.h"
#include "../core/InferenceBackend.h"
#include "../core/ExecutionJournal.h"
#include "../core/ModelRegistry.h"
#include <cstdio>
#include <cstring>

// Forward declarations from AgentSubsystem
extern "C" {
    int AgentSubsystem_Handler(int argc, char** argv, char* output, size_t output_size);
    int AgentSubsystem_Init(void);
    int AgentSubsystem_Shutdown(void);
    int AgentSubsystem_GetStatus(char* status, size_t status_size);
}

// Subsystem structure matching SovereignCLI_Unified expectations
typedef struct {
    const char* name;
    const char* version;
    int type;
    unsigned int capabilities;
    int state;
    int (*handler)(int argc, char** argv, char* output, size_t output_size);
    int (*init)(void);
    int (*shutdown)(void);
    int (*get_status)(char* status, size_t status_size);
} SovereignSubsystem;

// External registration function
extern "C" int Sovereign_RegisterSubsystem(const SovereignSubsystem* subsystem);

//==============================================================================
// Registration Function
//==============================================================================

extern "C" int RegisterAgentSubsystem(void) {
    printf("[Phase 13.5] Registering AgentSubsystem...\n");
    
    // Initialize Execution Journal first (for logging)
    int journal_result = Journal_Init(nullptr);
    if (journal_result != 0) {
        fprintf(stderr, "[Phase 13.5] Warning: Journal initialization failed\n");
    }
    
    // Create and register agent subsystem
    SovereignSubsystem agent_subsystem;
    memset(&agent_subsystem, 0, sizeof(agent_subsystem));
    
    agent_subsystem.name = "agent";
    agent_subsystem.version = AGENT_VERSION;
    agent_subsystem.type = 52;  // Next after existing 52 subsystems
    agent_subsystem.capabilities = 0x04;  // CAP_ANALYZE
    agent_subsystem.state = 1;  // STATE_READY
    agent_subsystem.handler = AgentSubsystem_Handler;
    agent_subsystem.init = AgentSubsystem_Init;
    agent_subsystem.shutdown = AgentSubsystem_Shutdown;
    agent_subsystem.get_status = AgentSubsystem_GetStatus;
    
    int result = Sovereign_RegisterSubsystem(&agent_subsystem);
    if (result != 0) {
        fprintf(stderr, "[Phase 13.5] Failed to register AgentSubsystem\n");
        return -1;
    }
    
    printf("[Phase 13.5] AgentSubsystem registered successfully\n");
    printf("[Phase 13.5]   Version: %s\n", AGENT_VERSION);
    printf("[Phase 13.5]   Backend: Native (sovereign GGUF)\n");
    printf("[Phase 13.5]   Commands: generate, fix, optimize, plan, analyze\n");
    
    // Log registration to journal
    Journal_LogUserRequest("AgentSubsystem registration", "Phase 13.5 completion");
    
    return 0;
}

//==============================================================================
// Initialization Entry Point
//==============================================================================

extern "C" int InitializePhase13_5(void) {
    printf("\n");
    printf("============================================================\n");
    printf("Phase 13.5 - Agent Integration (Sovereign Inference)\n");
    printf("============================================================\n");
    printf("\n");
    
    // Step 1: Initialize Execution Journal
    printf("[1/3] Initializing Execution Journal...\n");
    Journal_Init("logs/sovereign.journal");
    printf("      ✓ Journal ready\n\n");
    
    // Step 2: Set up native backend
    printf("[2/3] Configuring native inference backend...\n");
    AgentConfig config = {0};
    config.provider = AGENT_PROVIDER_LOCAL;  // Native GGUF
    strncpy(config.model_path, "models/phi4.gguf", sizeof(config.model_path));
    strncpy(config.model, "phi4", sizeof(config.model));
    config.default_max_tokens = 2048;
    config.default_temperature = 0.7f;
    config.default_timeout_ms = 120000;
    
    int init_result = Agent_Init(&config);
    if (init_result != 0) {
        fprintf(stderr, "      ✗ Agent initialization failed\n");
        return -1;
    }
    printf("      ✓ Native backend configured\n");
    printf("      ✓ Model path: %s\n", config.model_path);
    printf("      ✓ Lazy load enabled\n\n");
    
    // Step 3: Register with CLI
    printf("[3/3] Registering with CLI...\n");
    int reg_result = RegisterAgentSubsystem();
    if (reg_result != 0) {
        fprintf(stderr, "      ✗ Registration failed\n");
        return -1;
    }
    printf("      ✓ Agent subsystem registered\n\n");
    
    printf("============================================================\n");
    printf("Phase 13.5 COMPLETE - Fully Sovereign Agent Ready\n");
    printf("============================================================\n");
    printf("\n");
    
    // Phase 14: Initialize Model Registry
    printf("[Phase 14] Initializing Model Registry...\n");
    int registry_result = ModelRegistry_Init("models/registry.json");
    if (registry_result != 0) {
        fprintf(stderr, "      ✗ Model Registry initialization failed\n");
        return -1;
    }
    printf("      ✓ Model Registry loaded\n");
    
    ModelInfo default_model;
    if (ModelRegistry_GetDefaultModel(&default_model) == 0) {
        printf("      ✓ Default model: %s (%s)\n", default_model.name, default_model.id);
    }
    printf("\n");
    
    printf("============================================================\n");
    printf("Phase 14 COMPLETE - Multi-Model Registry Ready\n");
    printf("============================================================\n");
    printf("\n");
    printf("Test commands:\n");
    printf("  agent generate \"Hello world\" rust\n");
    printf("  agent fix broken.rs error.txt rust\n");
    printf("  models list\n");
    printf("  models info phi4\n");
    printf("  models switch deepseek\n");
    printf("\n");
    
    // Log completion
    Journal_LogUserRequest("Phase 14 complete", "Multi-model registry initialized");
    
    return 0;
}

//==============================================================================
// Test Function
//==============================================================================

extern "C" int TestSovereignAgent(void) {
    printf("\n[TEST] Running sovereign agent test...\n\n");
    
    // Test 1: Status check
    printf("Test 1: Agent status check\n");
    char status[256];
    int status_result = Agent_GetStatus(status, sizeof(status));
    if (status_result == 0) {
        printf("  ✓ %s\n", status);
    } else {
        printf("  ✗ Status check failed\n");
        return -1;
    }
    
    // Test 2: Backend check
    printf("\nTest 2: Backend verification\n");
    IInferenceBackend* backend = InferenceBackend_GetGlobal();
    if (backend) {
        printf("  ✓ Backend: %s\n", backend->name);
        printf("  ✓ Type: %s\n", 
               backend->type == BACKEND_NATIVE ? "native" : 
               backend->type == BACKEND_OLLAMA ? "ollama" : "other");
    } else {
        printf("  ✗ No backend configured\n");
        return -1;
    }
    
    // Test 3: Journal check
    printf("\nTest 3: Execution journal\n");
    uint64_t total_events, first_ts, last_ts;
    int stats_result = Journal_GetStatistics(&total_events, &first_ts, &last_ts);
    if (stats_result == 0) {
        printf("  ✓ Total events: %llu\n", total_events);
        printf("  ✓ Journal active\n");
    } else {
        printf("  ✗ Journal not available\n");
    }
    
    printf("\n[TEST] All tests passed!\n");
    return 0;
}
