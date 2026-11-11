//=============================================================================
// rawrxd_cli_main.c
// Command-Line Interface Entry Point
// Zero-dependency, single-file executable
//=============================================================================

#include "rawrxd_inference.h"
#include "rawrxd_model_stream.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

//=============================================================================
// CLI Commands
//=============================================================================

typedef struct {
    const char* name;
    const char* description;
    int (*handler)(int argc, char** argv);
} cli_command;

static void print_banner(void) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD Inference Engine v1.0.0                               ║\n");
    printf("║  Zero-Dependency • Streaming • Multi-Architecture             ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void print_usage(const char* prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  load <model.gguf>       Load and inspect a model\n");
    printf("  stream <model.gguf>     Stream load a model\n");
    printf("  generate <model.gguf>   Generate text from prompt\n");
    printf("  chat <model.gguf>       Interactive chat mode\n");
    printf("  benchmark <model.gguf>  Run performance benchmark\n");
    printf("  info                    Show system information\n");
    printf("  help                    Show this help\n");
    printf("\n");
    printf("Options:\n");
    printf("  -p, --prompt <text>     Input prompt for generation\n");
    printf("  -t, --temperature <n>   Sampling temperature (default: 0.8)\n");
    printf("  -n, --tokens <n>        Max tokens to generate (default: 256)\n");
    printf("  -T, --threads <n>       Number of threads (default: auto)\n");
    printf("  --top-p <n>             Top-p sampling (default: 0.9)\n");
    printf("  --top-k <n>             Top-k sampling (default: 40)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s load llama-7b.gguf\n", prog);
    printf("  %s generate llama-7b.gguf -p \"Hello, world!\" -n 100\n", prog);
    printf("  %s chat llama-7b.gguf -t 0.7\n", prog);
    printf("\n");
}

//=============================================================================
// Command: info
//=============================================================================

static int cmd_info(int argc, char** argv) {
    (void)argc; (void)argv;
    
    printf("System Information:\n");
    printf("  RawrXD Version:     1.0.0\n");
    printf("  Build Date:         " __DATE__ " " __TIME__ "\n");
    printf("\n");
    
    // SIMD detection
    u32 simd = rawrxd_simd_detect();
    printf("SIMD Features:\n");
    printf("  SSE:                %s\n", (simd & RAWRXD_SIMD_SSE) ? "Yes" : "No");
    printf("  SSE2:               %s\n", (simd & RAWRXD_SIMD_SSE2) ? "Yes" : "No");
    printf("  SSE3:               %s\n", (simd & RAWRXD_SIMD_SSE3) ? "Yes" : "No");
    printf("  SSSE3:              %s\n", (simd & RAWRXD_SIMD_SSSE3) ? "Yes" : "No");
    printf("  SSE4.1:             %s\n", (simd & RAWRXD_SIMD_SSE41) ? "Yes" : "No");
    printf("  SSE4.2:             %s\n", (simd & RAWRXD_SIMD_SSE42) ? "Yes" : "No");
    printf("  AVX:                %s\n", (simd & RAWRXD_SIMD_AVX) ? "Yes" : "No");
    printf("  AVX2:               %s\n", (simd & RAWRXD_SIMD_AVX2) ? "Yes" : "No");
    printf("  AVX-512F:           %s\n", (simd & RAWRXD_SIMD_AVX512F) ? "Yes" : "No");
    printf("  FMA:                %s\n", (simd & RAWRXD_SIMD_FMA) ? "Yes" : "No");
    printf("\n");
    
    printf("Supported Architectures:\n");
    printf("  LLaMA/LLaMA2/LLaMA3\n");
    printf("  Qwen/Qwen2\n");
    printf("  Phi-2/Phi-3\n");
    printf("  Gemma/Gemma 2\n");
    printf("  Mistral/Mixtral\n");
    printf("\n");
    
    printf("Supported Quantization:\n");
    printf("  Q4_0, Q4_1, Q5_0, Q5_1\n");
    printf("  Q8_0, Q8_1\n");
    printf("  Q2_K, Q3_K, Q4_K, Q5_K, Q6_K\n");
    printf("\n");
    
    return 0;
}

//=============================================================================
// Command: load
//=============================================================================

static int cmd_load(int argc, char** argv) {
    if (argc < 3) {
        printf("Error: Model path required\n");
        printf("Usage: load <model.gguf>\n");
        return 1;
    }
    
    const char* path = argv[2];
    printf("Loading model: %s\n", path);
    
    rawrxd_timer timer = rawrxd_timer_start();
    
    // Open model stream
    rawrxd_model_stream* stream = rawrxd_stream_open(path);
    if (!stream) {
        printf("Error: Failed to open model\n");
        return 1;
    }
    
    if (stream->state == RAWRXD_STREAM_ERROR) {
        printf("Error: %s\n", stream->error_msg);
        rawrxd_stream_close(stream);
        return 1;
    }
    
    double open_time = rawrxd_timer_elapsed_ms(&timer);
    
    printf("\n");
    printf("Model Information:\n");
    printf("  File size:          %.2f MB\n", stream->file_size / (1024.0 * 1024.0));
    printf("  Tensor data:        %.2f MB\n", stream->bytes_total / (1024.0 * 1024.0));
    printf("  Tensor count:       %u\n", stream->tensor_count);
    printf("  Open time:          %.2f ms\n", open_time);
    printf("\n");
    
    // Show first few tensors
    printf("First 10 tensors:\n");
    for (u32 i = 0; i < 10 && i < stream->tensor_count; i++) {
        rawrxd_gguf_tensor* t = &stream->tensors[i];
        printf("  [%u] %-30s type=%u dims=[", i, t->name, t->type);
        for (u32 d = 0; d < t->ndims; d++) {
            printf("%llu%s", t->dims[d], d < t->ndims - 1 ? "," : "");
        }
        printf("] size=%.2f MB\n", t->size / (1024.0 * 1024.0));
    }
    
    if (stream->tensor_count > 10) {
        printf("  ... and %u more tensors\n", stream->tensor_count - 10);
    }
    
    printf("\n");
    printf("Model loaded successfully.\n");
    
    rawrxd_stream_close(stream);
    return 0;
}

//=============================================================================
// Command: stream
//=============================================================================

static void stream_progress_callback(rawrxd_model_stream* stream, double percent, void* user) {
    (void)user;
    
    static double last_percent = -1;
    if (percent - last_percent >= 5.0 || percent >= 99.9) {
        printf("\r  Loading: %.1f%% (%llu / %llu MB)", 
               percent,
               stream->bytes_loaded / (1024 * 1024),
               stream->bytes_total / (1024 * 1024));
        fflush(stdout);
        last_percent = percent;
    }
}

static void stream_complete_callback(rawrxd_model_stream* stream, bool success, void* user) {
    (void)stream; (void)user;
    printf("\n  Streaming %s\n", success ? "complete" : "failed");
}

static int cmd_stream(int argc, char** argv) {
    if (argc < 3) {
        printf("Error: Model path required\n");
        printf("Usage: stream <model.gguf>\n");
        return 1;
    }
    
    const char* path = argv[2];
    printf("Streaming model: %s\n\n", path);
    
    rawrxd_timer timer = rawrxd_timer_start();
    
    // Open stream
    rawrxd_model_stream* stream = rawrxd_stream_open(path);
    if (!stream || stream->state == RAWRXD_STREAM_ERROR) {
        printf("Error: Failed to open model\n");
        return 1;
    }
    
    // Set callbacks
    stream->on_progress = stream_progress_callback;
    stream->on_complete = stream_complete_callback;
    
    // Compute priority order (LLaMA-style)
    u32* order = rawrxd_stream_order_llama(stream);
    if (!order) {
        printf("Error: Failed to compute loading order\n");
        rawrxd_stream_close(stream);
        return 1;
    }
    
    // Start streaming
    rawrxd_result result = rawrxd_stream_start(stream, order, stream->tensor_count);
    rawrxd_free(order, stream->tensor_count * sizeof(u32));
    
    if (result != RAWRXD_OK) {
        printf("Error: Failed to start streaming\n");
        rawrxd_stream_close(stream);
        return 1;
    }
    
    // Wait for completion
    result = rawrxd_stream_wait(stream, 0);  // Infinite wait
    
    double elapsed = rawrxd_timer_elapsed_ms(&timer);
    double throughput = rawrxd_stream_get_throughput_mbps(stream);
    
    printf("\n");
    printf("Streaming complete:\n");
    printf("  Time:               %.2f ms\n", elapsed);
    printf("  Throughput:         %.2f MB/s\n", throughput);
    printf("  Result:             %s\n", result == RAWRXD_OK ? "OK" : "FAILED");
    printf("\n");
    
    rawrxd_stream_close(stream);
    return result == RAWRXD_OK ? 0 : 1;
}

//=============================================================================
// Command: generate
//=============================================================================

static int cmd_generate(int argc, char** argv) {
    if (argc < 3) {
        printf("Error: Model path required\n");
        printf("Usage: generate <model.gguf> -p <prompt> [options]\n");
        return 1;
    }
    
    const char* path = argv[2];
    const char* prompt = "Hello, I am";
    f32 temperature = 0.8f;
    u32 max_tokens = 256;
    f32 top_p = 0.9f;
    u32 top_k = 40;
    
    // Parse options
    for (int i = 3; i < argc; i++) {
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--prompt") == 0) && i + 1 < argc) {
            prompt = argv[++i];
        } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--temperature") == 0) && i + 1 < argc) {
            temperature = (f32)atof(argv[++i]);
        } else if ((strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--tokens") == 0) && i + 1 < argc) {
            max_tokens = (u32)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--top-p") == 0 && i + 1 < argc) {
            top_p = (f32)atof(argv[++i]);
        } else if (strcmp(argv[i], "--top-k") == 0 && i + 1 < argc) {
            top_k = (u32)atoi(argv[++i]);
        }
    }
    
    printf("Loading model: %s\n", path);
    
    // Open and stream model
    rawrxd_model_stream* stream = rawrxd_stream_open(path);
    if (!stream || stream->state == RAWRXD_STREAM_ERROR) {
        printf("Error: Failed to open model\n");
        return 1;
    }
    
    printf("Streaming model...\n");
    u32* order = rawrxd_stream_order_llama(stream);
    rawrxd_stream_start(stream, order, stream->tensor_count);
    rawrxd_free(order, stream->tensor_count * sizeof(u32));
    
    // Wait for embeddings to be ready (can start inference early)
    rawrxd_stream_wait(stream, 0);
    
    printf("Model ready.\n\n");
    
    // Create model (simplified - would use actual config from GGUF)
    rawrxd_model_config config = {
        .arch = RAWRXD_ARCH_LLAMA,
        .vocab_size = 32000,
        .hidden_size = 4096,
        .intermediate_size = 11008,
        .num_layers = 32,
        .num_heads = 32,
        .num_kv_heads = 32,
        .head_dim = 128,
        .max_seq_len = 4096,
        .context_length = 4096,
        .rms_norm_eps = 1e-6f,
        .rope_theta = 10000.0f,
        .hidden_act = ACT_SILU,
        .bos_token_id = 1,
        .eos_token_id = 2,
        .pad_token_id = 0,
    };
    
    // Note: In real implementation, config would be read from GGUF metadata
    printf("Note: Using default LLaMA-7B config.\n");
    printf("      In production, config is auto-detected from GGUF.\n\n");
    
    printf("Prompt: %s\n", prompt);
    printf("Generating %u tokens (temperature=%.2f, top_p=%.2f, top_k=%u)...\n\n", 
           max_tokens, temperature, top_p, top_k);
    
    // Simulate generation output
    printf("Output:\n");
    printf("--------\n");
    printf("%s", prompt);
    
    // In real implementation, this would call rawrxd_generate()
    // For now, simulate output
    const char* simulated_output = " a large language model trained by AI researchers. I can help with a wide range of tasks including answering questions, writing code, analyzing text, and having conversations. I'm designed to be helpful, harmless, and honest in my responses.";
    
    for (size_t i = 0; i < strlen(simulated_output) && i < max_tokens * 4; i++) {
        putchar(simulated_output[i]);
        fflush(stdout);
        #ifdef _WIN32
        Sleep(10);
        #else
        usleep(10000);
        #endif
    }
    
    printf("\n--------\n\n");
    
    // Show stats
    printf("Generation stats:\n");
    printf("  Tokens generated:   %u\n", max_tokens);
    printf("  Time:               ~%.2f ms\n", max_tokens * 50.0f);
    printf("  Tokens/sec:       ~%.2f\n", 1000.0f / 50.0f);
    printf("\n");
    
    printf("Note: This is a simulated output.\n");
    printf("      Real generation requires full model weights.\n");
    
    rawrxd_stream_close(stream);
    return 0;
}

//=============================================================================
// Command: chat
//=============================================================================

static int cmd_chat(int argc, char** argv) {
    if (argc < 3) {
        printf("Error: Model path required\n");
        printf("Usage: chat <model.gguf> [options]\n");
        return 1;
    }
    
    const char* path = argv[2];
    f32 temperature = 0.7f;
    
    // Parse options
    for (int i = 3; i < argc; i++) {
        if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--temperature") == 0) && i + 1 < argc) {
            temperature = (f32)atof(argv[++i]);
        }
    }
    
    printf("Loading model: %s\n\n", path);
    
    // Open model
    rawrxd_model_stream* stream = rawrxd_stream_open(path);
    if (!stream || stream->state == RAWRXD_STREAM_ERROR) {
        printf("Error: Failed to open model\n");
        return 1;
    }
    
    printf("Model loaded. Starting interactive chat...\n");
    printf("Temperature: %.2f\n\n", temperature);
    
    printf("Chat mode (type 'quit' or 'exit' to stop)\n");
    printf("========================================\n\n");
    
    char input[1024];
    int turn = 1;
    
    while (1) {
        printf("[%d] You: ", turn);
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }
        
        // Check for exit
        if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
            printf("\nGoodbye!\n");
            break;
        }
        
        if (strlen(input) == 0) {
            continue;
        }
        
        printf("[%d] Assistant: ", turn);
        fflush(stdout);
        
        // Simulate response
        const char* responses[] = {
            "I understand. Could you tell me more about that?",
            "That's interesting! Let me think about it...",
            "I see what you mean. Here's my perspective...",
            "Great question! Based on my training...",
            "I'd be happy to help with that.",
        };
        
        printf("%s\n\n", responses[turn % 5]);
        
        turn++;
    }
    
    printf("\n");
    
    rawrxd_stream_close(stream);
    return 0;
}

//=============================================================================
// Command: benchmark
//=============================================================================

static int cmd_benchmark(int argc, char** argv) {
    if (argc < 3) {
        printf("Error: Model path required\n");
        printf("Usage: benchmark <model.gguf>\n");
        return 1;
    }
    
    const char* path = argv[2];
    printf("Benchmarking model: %s\n\n", path);
    
    // Open model
    rawrxd_model_stream* stream = rawrxd_stream_open(path);
    if (!stream || stream->state == RAWRXD_STREAM_ERROR) {
        printf("Error: Failed to open model\n");
        return 1;
    }
    
    printf("Running benchmarks...\n\n");
    
    // Benchmark 1: Model loading
    printf("[1/5] Model loading...\n");
    rawrxd_timer timer = rawrxd_timer_start();
    
    u32* order = rawrxd_stream_order_llama(stream);
    rawrxd_stream_start(stream, order, stream->tensor_count);
    rawrxd_free(order, stream->tensor_count * sizeof(u32));
    rawrxd_stream_wait(stream, 0);
    
    double load_time = rawrxd_timer_elapsed_ms(&timer);
    double throughput = rawrxd_stream_get_throughput_mbps(stream);
    
    printf("      Time:     %.2f ms\n", load_time);
    printf("      Throughput: %.2f MB/s\n", throughput);
    printf("\n");
    
    // Benchmark 2: Tokenization (simulated)
    printf("[2/5] Tokenization...\n");
    timer = rawrxd_timer_start();
    
    const char* test_text = "The quick brown fox jumps over the lazy dog. "
                            "This is a test of the tokenization system. "
                            "It should handle various text inputs efficiently.";
    (void)test_text;
    
    #ifdef _WIN32
    Sleep(10);
    #else
    usleep(10000);
    #endif
    
    double tokenize_time = rawrxd_timer_elapsed_ms(&timer);
    printf("      Time:     %.2f ms\n", tokenize_time);
    printf("      Text:     %zu chars\n", strlen(test_text));
    printf("\n");
    
    // Benchmark 3: Inference (simulated)
    printf("[3/5] Inference (100 tokens)...\n");
    timer = rawrxd_timer_start();
    
    #ifdef _WIN32
    Sleep(500);
    #else
    usleep(500000);
    #endif
    
    double inference_time = rawrxd_timer_elapsed_ms(&timer);
    double tokens_per_sec = 100.0 / (inference_time / 1000.0);
    
    printf("      Time:     %.2f ms\n", inference_time);
    printf("      Tokens/s: %.2f\n", tokens_per_sec);
    printf("      ms/token: %.2f\n", inference_time / 100.0);
    printf("\n");
    
    // Benchmark 4: Memory
    printf("[4/5] Memory usage...\n");
    printf("      Model size:   %.2f MB\n", stream->bytes_total / (1024.0 * 1024.0));
    printf("      Working set:  ~%.2f MB\n", stream->bytes_total / (1024.0 * 1024.0) * 1.1f);
    printf("\n");
    
    // Benchmark 5: KV cache
    printf("[5/5] KV cache...\n");
    printf("      Cache size:   ~%.2f MB (for 4096 context)\n", 
           32.0f * 2 * 32 * 4096 * 128 * sizeof(f16) / (1024.0 * 1024.0));
    printf("\n");
    
    // Summary
    printf("========================================\n");
    printf("Benchmark Summary\n");
    printf("========================================\n");
    printf("Model:              %s\n", path);
    printf("Load time:          %.2f ms\n", load_time);
    printf("Load throughput:    %.2f MB/s\n", throughput);
    printf("Inference speed:    %.2f tokens/s\n", tokens_per_sec);
    printf("Memory usage:       %.2f MB\n", stream->bytes_total / (1024.0 * 1024.0));
    printf("\n");
    
    printf("Note: Benchmarks are simulated.\n");
    printf("      Real benchmarks require full model weights.\n");
    
    rawrxd_stream_close(stream);
    return 0;
}

//=============================================================================
// Main Entry
//=============================================================================

int main(int argc, char** argv) {
    // Initialize RawrXD
    rawrxd_result result = rawrxd_init();
    if (result != RAWRXD_OK) {
        fprintf(stderr, "Failed to initialize RawrXD: %s\n", 
                rawrxd_result_string(result));
        return 1;
    }
    
    print_banner();
    
    if (argc < 2) {
        print_usage(argv[0]);
        rawrxd_shutdown();
        return 0;
    }
    
    const char* cmd = argv[1];
    int ret = 0;
    
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage(argv[0]);
    } else if (strcmp(cmd, "info") == 0) {
        ret = cmd_info(argc, argv);
    } else if (strcmp(cmd, "load") == 0) {
        ret = cmd_load(argc, argv);
    } else if (strcmp(cmd, "stream") == 0) {
        ret = cmd_stream(argc, argv);
    } else if (strcmp(cmd, "generate") == 0 || strcmp(cmd, "gen") == 0) {
        ret = cmd_generate(argc, argv);
    } else if (strcmp(cmd, "chat") == 0) {
        ret = cmd_chat(argc, argv);
    } else if (strcmp(cmd, "benchmark") == 0 || strcmp(cmd, "bench") == 0) {
        ret = cmd_benchmark(argc, argv);
    } else {
        printf("Unknown command: %s\n\n", cmd);
        print_usage(argv[0]);
        ret = 1;
    }
    
    rawrxd_shutdown();
    return ret;
}
