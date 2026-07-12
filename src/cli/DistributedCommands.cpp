//==============================================================================
// DistributedCommands.cpp - Phase 15C: CLI Commands for Distributed Inference
//
// CLI commands:
//   agent cluster status              - Show cluster health
//   agent cluster benchmark           - Benchmark all nodes
//   agent cluster select <strategy>   - Set distribution strategy
//   agent generate-dist <prompt>       - Distributed generation
//==============================================================================

#include "../core/DistributedInference.h"
#include "../core/RemoteCluster.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstring>

//==============================================================================
// Command: cluster status
//==============================================================================

int CLI_ClusterStatus(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (!DistributedInference_IsInitialized()) {
        printf("Distributed inference not initialized.\n");
        printf("Run 'agent cluster init' first.\n");
        return 1;
    }
    
    printf("Distributed Inference Cluster Status\n");
    printf("=====================================\n\n");
    
    // Get cluster metrics
    float total_tps;
    uint64_t avg_latency;
    int active_reqs;
    DistributedInference_GetClusterMetrics(&total_tps, &avg_latency, &active_reqs);
    
    printf("Strategy: %s\n", DistributedInference_StrategyName(
        DistributedInference_GetStrategy()));
    printf("Total TPS: %.1f\n", total_tps);
    printf("Avg Latency: %llu ms\n", avg_latency);
    printf("Active Requests: %d\n\n", active_reqs);
    
    // Get all nodes
    RemoteNodeInfo nodes[32];
    int count;
    RemoteCluster_GetAllNodes(nodes, 32, &count);
    
    printf("Nodes (%d):\n", count);
    printf("%-20s %-12s %-10s %-12s %-10s %-12s\n",
           "ID", "Status", "TPS", "Latency", "Load", "Memory");
    printf("--------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < count; i++) {
        const char* status = "Unknown";
        switch (nodes[i].health_state) {
            case NODE_STATE_HEALTHY: status = "Healthy"; break;
            case NODE_STATE_DEGRADED: status = "Degraded"; break;
            case NODE_STATE_DOWN: status = "Down"; break;
            case NODE_STATE_MAINTENANCE: status = "Maint"; break;
        }
        
        printf("%-20s %-12s %-10.1f %-7llu ms %-5d/%-3d %-6llu MB\n",
               nodes[i].id,
               status,
               nodes[i].tokens_per_second,
               nodes[i].latency_ms,
               nodes[i].current_load,
               nodes[i].max_concurrent,
               nodes[i].memory_available_mb);
    }
    
    return 0;
}

//==============================================================================
// Command: cluster benchmark
//==============================================================================

int CLI_ClusterBenchmark(int argc, char* argv[]) {
    const char* model_id = "llama-3.2-1b";
    const char* test_prompt = "Hello, this is a benchmark test. Please generate a short response.";
    
    // Parse args
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            model_id = argv[++i];
        } else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
            test_prompt = argv[++i];
        }
    }
    
    printf("Benchmarking cluster...\n");
    printf("Model: %s\n", model_id);
    printf("Prompt: \"%s\"\n\n", test_prompt);
    
    BenchmarkResult results[16];
    int count;
    
    if (DistributedInference_BenchmarkCluster(model_id, test_prompt, 
                                               results, 16, &count) != 0) {
        printf("Benchmark failed.\n");
        return 1;
    }
    
    printf("Results:\n");
    printf("%-20s %10s %12s %12s %10s\n",
           "Node", "TPS", "Latency", "Memory", "Status");
    printf("------------------------------------------------------------------------\n");
    
    float total_tps = 0;
    int success_count = 0;
    
    for (int i = 0; i < count; i++) {
        if (results[i].success) {
            printf("%-20s %10.1f %7llu ms %8llu MB %10s\n",
                   results[i].node_id,
                   results[i].tokens_per_second,
                   results[i].latency_ms,
                   results[i].memory_used_mb,
                   "OK");
            total_tps += results[i].tokens_per_second;
            success_count++;
        } else {
            printf("%-20s %10s %12s %12s %10s\n",
                   results[i].node_id,
                   "-", "-", "-",
                   results[i].error_message);
        }
    }
    
    printf("\n");
    printf("Successful: %d/%d\n", success_count, count);
    printf("Aggregate TPS: %.1f\n", total_tps);
    
    Journal_LogUserRequest("CLI cluster benchmark", model_id);
    
    return 0;
}

//==============================================================================
// Command: cluster select
//==============================================================================

int CLI_ClusterSelect(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent cluster select <strategy>\n");
        printf("\nStrategies:\n");
        printf("  tensor    - Tensor parallelism (split tensors)\n");
        printf("  pipeline  - Pipeline parallelism (split layers)\n");
        printf("  task      - Task parallelism (multiple requests)\n");
        return 1;
    }
    
    const char* strategy_str = argv[2];
    int strategy = -1;
    
    if (strcmp(strategy_str, "tensor") == 0) {
        strategy = DISTRIBUTION_STRATEGY_TENSOR;
    } else if (strcmp(strategy_str, "pipeline") == 0) {
        strategy = DISTRIBUTION_STRATEGY_PIPELINE;
    } else if (strcmp(strategy_str, "task") == 0) {
        strategy = DISTRIBUTION_STRATEGY_TASK;
    } else {
        printf("Unknown strategy: %s\n", strategy_str);
        return 1;
    }
    
    DistributedInference_SetStrategy(strategy);
    
    printf("Strategy set to: %s\n", DistributedInference_StrategyName(strategy));
    
    Journal_LogUserRequest("CLI strategy changed", strategy_str);
    
    return 0;
}

//==============================================================================
// Command: cluster init
//==============================================================================

int CLI_ClusterInit(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    if (DistributedInference_IsInitialized()) {
        printf("Distributed inference already initialized.\n");
        return 0;
    }
    
    int strategy = DISTRIBUTION_STRATEGY_TASK;  // Default
    
    // Parse args
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--strategy") == 0 && i + 1 < argc) {
            const char* s = argv[++i];
            if (strcmp(s, "tensor") == 0) strategy = DISTRIBUTION_STRATEGY_TENSOR;
            else if (strcmp(s, "pipeline") == 0) strategy = DISTRIBUTION_STRATEGY_PIPELINE;
            else if (strcmp(s, "task") == 0) strategy = DISTRIBUTION_STRATEGY_TASK;
        }
    }
    
    if (DistributedInference_Init(strategy) != 0) {
        printf("Failed to initialize distributed inference.\n");
        return 1;
    }
    
    printf("Distributed inference initialized.\n");
    printf("Strategy: %s\n", DistributedInference_StrategyName(strategy));
    
    // Show cluster nodes
    RemoteNodeInfo nodes[32];
    int count;
    RemoteCluster_GetAllNodes(nodes, 32, &count);
    
    printf("Found %d node(s) in cluster.\n", count);
    
    Journal_LogUserRequest("CLI cluster init", "");
    
    return 0;
}

//==============================================================================
// Command: generate-dist
//==============================================================================

int CLI_GenerateDist(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent generate-dist <prompt> [options]\n");
        printf("\nOptions:\n");
        printf("  --model <id>      Model to use\n");
        printf("  --nodes <n>       Number of nodes to use\n");
        printf("  --max-tokens <n>  Maximum tokens to generate\n");
        return 1;
    }
    
    const char* prompt = argv[2];
    const char* model_id = "llama-3.2-1b";
    int num_nodes = 0;  // 0 = auto-select
    int max_tokens = 256;
    
    // Parse args
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            model_id = argv[++i];
        } else if (strcmp(argv[i], "--nodes") == 0 && i + 1 < argc) {
            num_nodes = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-tokens") == 0 && i + 1 < argc) {
            max_tokens = atoi(argv[++i]);
        }
    }
    
    // Initialize if needed
    if (!DistributedInference_IsInitialized()) {
        DistributedInference_Init(DISTRIBUTION_STRATEGY_TASK);
    }
    
    // Select nodes
    char* node_ids[16];
    int node_count = num_nodes;
    
    if (node_count == 0) {
        // Auto-select optimal nodes
        char node_buf[16][64];
        DistributedInference_SelectOptimalNodes(NULL, node_buf, 16, &node_count);
        for (int i = 0; i < node_count; i++) {
            node_ids[i] = node_buf[i];
        }
    } else {
        // Get specific nodes from cluster
        RemoteNodeInfo nodes[16];
        int available;
        RemoteCluster_GetHealthyNodes(nodes, 16, &available);
        
        if (node_count > available) {
            node_count = available;
        }
        
        static char node_buf[16][64];
        for (int i = 0; i < node_count; i++) {
            strncpy(node_buf[i], nodes[i].id, 64);
            node_ids[i] = node_buf[i];
        }
    }
    
    if (node_count == 0) {
        printf("No healthy nodes available.\n");
        return 1;
    }
    
    printf("Distributed generation:\n");
    printf("  Prompt: \"%s\"\n", prompt);
    printf("  Model: %s\n", model_id);
    printf("  Nodes: %d (", node_count);
    for (int i = 0; i < node_count; i++) {
        printf("%s%s", node_ids[i], (i < node_count - 1) ? ", " : "");
    }
    printf(")\n");
    printf("  Strategy: %s\n\n", DistributedInference_StrategyName(
        DistributedInference_GetStrategy()));
    
    // Build request
    InferenceRequest req = {0};
    strncpy(req.model_id, model_id, sizeof(req.model_id) - 1);
    strncpy(req.prompt, prompt, sizeof(req.prompt) - 1);
    req.max_tokens = max_tokens;
    
    // Progress callback
    auto on_token = [](const char* token, int node_idx, void* user_data) {
        (void)user_data;
        printf("[Node %d] %s", node_idx, token);
        fflush(stdout);
        return;
    };
    
    // Submit request
    uint64_t start = GetTickCount64();
    
    int req_id = DistributedInference_Submit(&req, 
                                              (const char**)node_ids,
                                              node_count,
                                              on_token,
                                              NULL,  // on_complete
                                              NULL); // user_data
    
    if (req_id < 0) {
        printf("Failed to submit distributed request.\n");
        return 1;
    }
    
    // Wait for completion (poll)
    DistributedRequest dreq;
    while (DistributedInference_GetStatus(req_id, &dreq) == 0) {
        if (dreq.tokens_total > 0 && dreq.tokens_generated >= dreq.tokens_total) {
            break;
        }
        Sleep(100);
    }
    
    uint64_t elapsed = GetTickCount64() - start;
    
    printf("\n\nCompleted in %llu ms\n", elapsed);
    
    Journal_LogUserRequest("CLI distributed generation", model_id);
    
    return 0;
}

//==============================================================================
// Command Router
//==============================================================================

int CLI_ClusterCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: agent cluster <subcommand> [args]\n");
        printf("\nSubcommands:\n");
        printf("  init [options]     Initialize distributed inference\n");
        printf("  status             Show cluster status\n");
        printf("  benchmark          Benchmark all nodes\n");
        printf("  select <strategy>  Set distribution strategy\n");
        return 1;
    }
    
    const char* subcmd = argv[1];
    
    if (strcmp(subcmd, "init") == 0) {
        return CLI_ClusterInit(argc, argv);
    } else if (strcmp(subcmd, "status") == 0) {
        return CLI_ClusterStatus(argc, argv);
    } else if (strcmp(subcmd, "benchmark") == 0) {
        return CLI_ClusterBenchmark(argc, argv);
    } else if (strcmp(subcmd, "select") == 0) {
        return CLI_ClusterSelect(argc, argv);
    } else {
        printf("Unknown subcommand: %s\n", subcmd);
        return 1;
    }
}
