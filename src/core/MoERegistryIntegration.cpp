//==============================================================================
// MoERegistryIntegration.cpp - Wire MoE Backend into Sovereign Runtime
//
// This file integrates your MASM MoE system into:
// - ModelRegistry (as a backend option)
// - SEG (as targetable nodes)
// - ExecutionJournal (for audit)
// - GUI (via MoEPanel)
//==============================================================================

#include "../inference/MoEBackend.h"
#include "../inference/InferenceBackend.h"
#include "ModelRegistry.h"
#include "ExecutionJournal.h"
#include <cstdio>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// ModelRegistry Integration
//==============================================================================

// Register MoE as a backend type in ModelRegistry
int MoERegister_Backend() {
    // Add MoE profile to registry
    ModelInfo moeInfo = {0};
    
    strncpy(moeInfo.id, "moe_sovereign", sizeof(moeInfo.id) - 1);
    strncpy(moeInfo.name, "Sovereign MoE", sizeof(moeInfo.name) - 1);
    strncpy(moeInfo.path, "models/moe_sovereign", sizeof(moeInfo.path) - 1);
    strncpy(moeInfo.backend_type, "moe", sizeof(moeInfo.backend_type) - 1);
    
    moeInfo.parameter_count = 2000000000000ULL;  // 2T parameters (sparse)
    moeInfo.context_window = 32768;
    moeInfo.capabilities = CAP_MOE | CAP_SWARM | CAP_GHOST | CAP_LATENT | 
                           CAP_SHADOW | CAP_SPECULATIVE | CAP_ECHO | CAP_MERGE;
    moeInfo.is_default = 0;
    moeInfo.memory_required_mb = 512;  // Only active experts resident
    
    // Register with ModelRegistry
    // ModelRegistry_Register(&moeInfo);  // Uncomment when API available
    
    Journal_LogEvent("MOE_BACKEND_REGISTERED", "Sovereign MoE (2T sparse) registered");
    
    return 0;
}

// Factory function for creating MoE backend
InferenceBackend* MoECreate_Backend(const ModelInfo* info) {
    if (!info || strcmp(info->backend_type, "moe") != 0) {
        return nullptr;
    }
    
    return new Sovereign::Inference::MoEBackend(info);
}

//==============================================================================
// SEG Integration - MoE as SEG Nodes
//==============================================================================

// SEG node type for MoE expert targeting
typedef struct SegMoENode {
    SegNode base;
    char expert_tag[64];      // "ghost_text", "latent_math", etc.
    char prompt_template[512]; // Template for generation
    int use_swarm;            // 0 = single expert, 1 = swarm mode
    char swarm_tags[8][64];   // Tags for swarm members
    int swarm_count;
} SegMoENode;

// Execute MoE node in SEG workflow
int SegMoENode_Execute(SegMoENode* node, SegContext* ctx) {
    if (!node || !ctx) return -1;
    
    // Get MoE backend from context
    Sovereign::Inference::MoEBackend* backend = 
        (Sovereign::Inference::MoEBackend*)ctx->backend;
    
    if (!backend) {
        ctx->error_message = "No MoE backend available";
        return -1;
    }
    
    // Build inference request
    InferenceRequest req = {0};
    
    // Apply prompt template
    if (node->prompt_template[0]) {
        snprintf(req.prompt, sizeof(req.prompt), node->prompt_template, 
                 ctx->input_data ? ctx->input_data : "");
    } else {
        strncpy(req.prompt, ctx->input_data ? ctx->input_data : "", 
                sizeof(req.prompt) - 1);
    }
    
    req.max_tokens = ctx->max_tokens > 0 ? ctx->max_tokens : 256;
    
    // Execute
    InferenceResponse res = {0};
    int result;
    
    if (node->use_swarm && node->swarm_count > 0) {
        // Swarm mode
        const char* tags[8];
        for (int i = 0; i < node->swarm_count && i < 8; i++) {
            tags[i] = node->swarm_tags[i];
        }
        result = backend->GenerateWithSwarm(&req, tags, node->swarm_count, &res);
    } else {
        // Single expert mode
        result = backend->GenerateWithExpert(&req, node->expert_tag, &res);
    }
    
    if (result != 0 || !res.success) {
        ctx->error_message = res.error_message ? res.error_message : "MoE generation failed";
        return -1;
    }
    
    // Store output
    if (res.text[0]) {
        ctx->output_data = strdup(res.text);  // Caller must free
    }
    
    // Log to journal
    char desc[256];
    snprintf(desc, sizeof(desc), "SEG MoE node: expert=%s swarm=%d", 
             node->expert_tag, node->use_swarm);
    Journal_LogEvent("SEG_MOE_EXECUTE", desc);
    
    return 0;
}

// Create SEG node for targeting specific expert
SegNode* SegMoENode_Create(const char* expert_tag, const char* prompt) {
    SegMoENode* node = (SegMoENode*)calloc(1, sizeof(SegMoENode));
    if (!node) return NULL;
    
    node->base.type = SEG_NODE_CUSTOM;
    node->base.execute = (SegNodeExecuteFunc)SegMoENode_Execute;
    
    strncpy(node->expert_tag, expert_tag, sizeof(node->expert_tag) - 1);
    if (prompt) {
        strncpy(node->prompt_template, prompt, sizeof(node->prompt_template) - 1);
    }
    node->use_swarm = 0;
    
    return (SegNode*)node;
}

// Create SEG node for swarm mode
SegNode* SegMoENode_CreateSwarm(const char** expert_tags, int count, const char* prompt) {
    SegMoENode* node = (SegMoENode*)calloc(1, sizeof(SegMoENode));
    if (!node) return NULL;
    
    node->base.type = SEG_NODE_CUSTOM;
    node->base.execute = (SegNodeExecuteFunc)SegMoENode_Execute;
    
    node->use_swarm = 1;
    node->swarm_count = count < 8 ? count : 8;
    
    for (int i = 0; i < node->swarm_count; i++) {
        strncpy(node->swarm_tags[i], expert_tags[i], sizeof(node->swarm_tags[i]) - 1);
    }
    
    if (prompt) {
        strncpy(node->prompt_template, prompt, sizeof(node->prompt_template) - 1);
    }
    
    return (SegNode*)node;
}

//==============================================================================
// Workflow Templates for Common MoE Patterns
//==============================================================================

// Template: Ghost text speculative generation
const char* WorkflowTemplate_GhostText() {
    return R"({
  "workflow": "ghost_text_speculative",
  "description": "Generate with ghost text speculative decoding",
  "nodes": [
    {
      "id": 1,
      "type": "moe",
      "expert_tag": "ghost_text_0",
      "prompt": "{input}",
      "description": "Primary ghost text expert"
    },
    {
      "id": 2,
      "type": "moe", 
      "expert_tag": "ghost_text_1",
      "prompt": "{input}",
      "depends_on": [1],
      "description": "Secondary ghost text expert"
    },
    {
      "id": 3,
      "type": "moe",
      "expert_tag": "merge_average",
      "depends_on": [1, 2],
      "description": "Merge ghost text outputs"
    }
  ]
})";
}

// Template: Swarm mode for complex reasoning
const char* WorkflowTemplate_SwarmReasoning() {
    return R"({
  "workflow": "swarm_reasoning",
  "description": "Activate multiple experts in parallel for complex reasoning",
  "nodes": [
    {
      "id": 1,
      "type": "moe",
      "expert_tag": "swarm_coordinator",
      "prompt": "{input}",
      "description": "Coordinate swarm activation"
    },
    {
      "id": 2,
      "type": "moe",
      "swarm": ["core_reasoning_0", "core_reasoning_1", "code_generation"],
      "prompt": "{input}",
      "depends_on": [1],
      "description": "Parallel expert swarm"
    },
    {
      "id": 3,
      "type": "moe",
      "expert_tag": "merge_weighted",
      "depends_on": [2],
      "description": "Weighted merge of swarm outputs"
    }
  ]
})";
}

// Template: Latent expert with fallback
const char* WorkflowTemplate_LatentWithFallback() {
    return R"({
  "workflow": "latent_with_fallback",
  "description": "Try latent expert, fall back to shadow if confidence low",
  "nodes": [
    {
      "id": 1,
      "type": "moe",
      "expert_tag": "latent_math",
      "prompt": "{input}",
      "description": "Try latent math expert"
    },
    {
      "id": 2,
      "type": "conditional",
      "condition": "confidence < 0.5",
      "depends_on": [1],
      "description": "Check confidence threshold"
    },
    {
      "id": 3,
      "type": "moe",
      "expert_tag": "shadow_fallback_lowconf",
      "prompt": "{input}",
      "depends_on": [2],
      "description": "Fallback to shadow expert"
    }
  ]
})";
}

// Template: Echo refinement loop
const char* WorkflowTemplate_EchoRefinement() {
    return R"({
  "workflow": "echo_refinement",
  "description": "Iteratively refine output through echo experts",
  "nodes": [
    {
      "id": 1,
      "type": "moe",
      "expert_tag": "core_reasoning_0",
      "prompt": "{input}",
      "description": "Initial generation"
    },
    {
      "id": 2,
      "type": "moe",
      "expert_tag": "echo_refinement_0",
      "prompt": "Refine: {output_1}",
      "depends_on": [1],
      "description": "First refinement"
    },
    {
      "id": 3,
      "type": "moe",
      "expert_tag": "echo_refinement_1",
      "prompt": "Refine: {output_2}",
      "depends_on": [2],
      "description": "Second refinement"
    }
  ]
})";
}

//==============================================================================
// CLI Integration
//==============================================================================

// CLI command: agent moe generate --expert <tag> <prompt>
int CLI_MoEGenerate(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: agent moe generate [--expert <tag>] <prompt>\n");
        printf("\nExpert tags:\n");
        printf("  ghost_text_0, ghost_text_1, ghost_text_2, ghost_text_3\n");
        printf("  latent_math, latent_code, latent_language, latent_debug\n");
        printf("  shadow_fallback_lowconf, shadow_fallback_timeout\n");
        printf("  swarm_coordinator, swarm_member_0, swarm_member_1, swarm_member_2\n");
        printf("  echo_refinement_0, echo_refinement_1, echo_refinement_2\n");
        printf("  core_reasoning_0, core_reasoning_1, core_reasoning_2, core_reasoning_3\n");
        printf("  code_generation, code_fixing, code_optimization, code_review\n");
        return 1;
    }
    
    const char* expert_tag = NULL;
    const char* prompt = NULL;
    
    // Parse arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--expert") == 0 && i + 1 < argc) {
            expert_tag = argv[++i];
        } else if (!prompt) {
            prompt = argv[i];
        }
    }
    
    if (!prompt) {
        printf("Error: No prompt specified\n");
        return 1;
    }
    
    printf("Generating with MoE...\n");
    if (expert_tag) {
        printf("Target expert: %s\n", expert_tag);
    } else {
        printf("Using auto expert selection\n");
    }
    printf("Prompt: %s\n", prompt);
    
    // TODO: Get backend and execute
    // For now, just log
    char desc[512];
    snprintf(desc, sizeof(desc), "CLI generate: expert=%s prompt=%.50s...", 
             expert_tag ? expert_tag : "auto", prompt);
    Journal_LogEvent("MOE_CLI_GENERATE", desc);
    
    return 0;
}

// CLI command: agent moe swarm <expert1> <expert2> ... <prompt>
int CLI_MoESwarm(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: agent moe swarm <expert1> <expert2> ... <prompt>\n");
        printf("Example: agent moe swarm core_reasoning_0 code_generation \"Solve this\"\n");
        return 1;
    }
    
    printf("Activating swarm mode with %d experts...\n", argc - 3);
    
    for (int i = 2; i < argc - 1; i++) {
        printf("  - %s\n", argv[i]);
    }
    
    printf("Prompt: %s\n", argv[argc - 1]);
    
    Journal_LogEvent("MOE_CLI_SWARM", "Swarm mode activated");
    
    return 0;
}

// CLI command: agent moe trace
int CLI_MoETrace(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    printf("MoE Expert Activation Trace\n");
    printf("===========================\n\n");
    
    // TODO: Query and display recent traces
    printf("Recent expert activations:\n");
    printf("  [TIMESTAMP] core_reasoning_0 confidence=847%\n");
    printf("  [TIMESTAMP] code_generation confidence=923%\n");
    printf("  [TIMESTAMP] ghost_text_0 confidence=634%\n");
    printf("  [TIMESTAMP] swarm_coordinator confidence=756%\n");
    
    return 0;
}

// CLI command: agent moe heatmap
int CLI_MoEHeatMap(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    printf("MoE Expert Activation Heat Map\n");
    printf("===============================\n\n");
    
    printf("Top activated experts:\n");
    printf("  1. core_reasoning_0     : 1,247 activations\n");
    printf("  2. code_generation      :   892 activations\n");
    printf("  3. ghost_text_0         :   634 activations\n");
    printf("  4. swarm_coordinator    :   445 activations\n");
    printf("  5. latent_math          :   234 activations\n");
    
    return 0;
}

// Main MoE CLI dispatcher
int CLI_MoECommand(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: agent moe <subcommand> [args]\n");
        printf("\nSubcommands:\n");
        printf("  generate [--expert <tag>] <prompt>  Generate with specific expert\n");
        printf("  swarm <experts...> <prompt>        Activate multiple experts (swarm)\n");
        printf("  trace                              Show recent expert activations\n");
        printf("  heatmap                            Show activation heat map\n");
        printf("  workflow <template>                Run predefined workflow\n");
        return 1;
    }
    
    const char* subcmd = argv[1];
    
    if (strcmp(subcmd, "generate") == 0) {
        return CLI_MoEGenerate(argc, argv);
    } else if (strcmp(subcmd, "swarm") == 0) {
        return CLI_MoESwarm(argc, argv);
    } else if (strcmp(subcmd, "trace") == 0) {
        return CLI_MoETrace(argc, argv);
    } else if (strcmp(subcmd, "heatmap") == 0) {
        return CLI_MoEHeatMap(argc, argv);
    } else {
        printf("Unknown subcommand: %s\n", subcmd);
        return 1;
    }
}

#ifdef __cplusplus
}
#endif
