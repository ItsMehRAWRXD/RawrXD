//=============================================================================
// rawrxd_cli_main.c
// Command-Line Interface Entry Point
// Zero-dependency, single-file executable
//=============================================================================

#include "rawrxd_inference.h"
#include "rawrxd_model_stream.h"
#include "cli_numeric_policy.h"
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
    
    // Reject malformed or out-of-range values before opening the model.
    for (int i = 3; i < argc; i++) {
        const char* opt = argv[i];
        if (strcmp(opt, "-p") == 0 || strcmp(opt, "--prompt") == 0) {
            if (++i >= argc) { fprintf(stderr, "Missing prompt value\n"); return 2; }
            prompt = argv[i];
        } else if (strcmp(opt, "-t") == 0 || strcmp(opt, "--temperature") == 0) {
            if (++i >= argc || !rawrxd_parse_f32_range(argv[i], 0.0, 2.0, &temperature)) {
                fprintf(stderr, "Invalid temperature (expected 0..2)\n"); return 2;
            }
        } else if (strcmp(opt, "-n") == 0 || strcmp(opt, "--tokens") == 0) {
            if (++i >= argc || !rawrxd_parse_u32_range(argv[i], 1, 65536, &max_tokens)) {
                fprintf(stderr, "Invalid token count (expected 1..65536)\n"); return 2;
            }
        } else if (strcmp(opt, "--top-p") == 0) {
            if (++i >= argc || !rawrxd_parse_f32_range(argv[i], 0.000001, 1.0, &top_p)) {
                fprintf(stderr, "Invalid top-p (expected >0 and <=1)\n"); return 2;
            }
        } else if (strcmp(opt, "--top-k") == 0) {
            if (++i >= argc || !rawrxd_parse_u32_range(argv[i], 1, 4096, &top_k)) {
                fprintf(stderr, "Invalid top-k (expected 1..4096)\n"); return 2;
            }
        } else {
            fprintf(stderr, "Unknown generate option: %s\n", opt);
            return 2;
        }
    }

    // This entry point has no real model-backed generation implementation.
    // Never return a successful inference receipt for canned text.
    (void)path; (void)prompt; (void)temperature;
    (void)max_tokens; (void)top_p; (void)top_k;
    fprintf(stderr, "UNAVAILABLE: generate requires a wired inference backend; no tokens generated\\n");
    return 3;
}

//=============================================================================
// Command: chat
//=============================================================================

static int cmd_chat(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: chat <model.gguf> [options]\\n");
        return 1;
    }
    (void)argv;
    // The former chat path returned rotating canned responses as if inferred.
    fprintf(stderr, "UNAVAILABLE: chat requires a wired inference backend; no response generated\\n");
    return 3;
}

//=============================================================================
// Command: benchmark
//=============================================================================

static int cmd_benchmark(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: benchmark <model.gguf>\\n");
        return 1;
    }
    (void)argv;
    // Sleeping for a fixed interval is not an inference throughput benchmark.
    fprintf(stderr, "UNAVAILABLE: benchmark requires real inference timing; no TPS measured\\n");
    return 3;
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
