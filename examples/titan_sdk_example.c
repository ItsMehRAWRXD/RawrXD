/**
 * @file titan_sdk_example.c
 * @brief Minimal example of using the RawrXD Titan SDK
 * 
 * Build:
 *   cl titan_sdk_example.c /I..\include /link RawrXD_Titan.lib
 * 
 * Or dynamic loading:
 *   cl titan_sdk_example.c /I..\include
 *   (loads RawrXD_Titan.dll at runtime)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "titan_sdk.h"

/* ============================================================================
 * Streaming callback — called for each token
 * ============================================================================ */

static bool on_token(const char* token, void* user_data) {
    (void)user_data;
    printf("%s", token);
    fflush(stdout);
    return true;  /* Continue generation */
}

static void on_complete(void* user_data) {
    (void)user_data;
    printf("\n\n[Generation complete]\n");
}

static void on_error(const char* error, void* user_data) {
    (void)user_data;
    fprintf(stderr, "\n[Error: %s]\n", error);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("  RawrXD Titan SDK Example\n");
    printf("  Version: %s\n", titan_version());
    printf("=================================================================\n\n");

    /* Check version compatibility */
    if (!titan_check_version()) {
        fprintf(stderr, "Version mismatch between header and DLL!\n");
        return 1;
    }

    /* Configuration */
    TitanConfig config = titan_default_config();
    config.model_path = (argc > 1) ? argv[1] : "model.gguf";
    config.max_tokens = 256;
    config.temperature = 0.7f;
    config.verbosity = 2;

    printf("Loading model: %s\n", config.model_path);
    printf("Max tokens: %u\n", config.max_tokens);
    printf("Temperature: %.2f\n\n", config.temperature);

    /* Initialize */
    TitanContext* ctx = titan_init(&config);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize: %s\n", titan_get_last_error());
        return 1;
    }

    /* Get model info */
    TitanModelInfo info;
    if (titan_get_model_info(ctx, &info)) {
        printf("Model: %s\n", info.name);
        printf("Architecture: %s\n", info.architecture);
        printf("Parameters: %.1fB\n", info.parameter_count / 1e9f);
        printf("Context: %u tokens\n", info.context_length);
        printf("Vocab: %u tokens\n", info.vocab_size);
        printf("Quantization: %s\n", info.quantization);
        printf("Memory required: %.1f MB\n\n", info.memory_required / (1024.0f * 1024.0f));
    }

    /* Interactive loop */
    char prompt[4096];
    printf("Enter prompts (empty line to quit):\n\n");

    while (1) {
        printf("> ");
        fflush(stdout);

        if (!fgets(prompt, sizeof(prompt), stdin)) {
            break;
        }

        /* Remove trailing newline */
        size_t len = strlen(prompt);
        if (len > 0 && prompt[len - 1] == '\n') {
            prompt[len - 1] = '\0';
        }

        /* Empty line = quit */
        if (strlen(prompt) == 0) {
            break;
        }

        printf("\n");

        /* Generate with streaming */
        TitanGeneration* gen = titan_generate_streaming(
            ctx, prompt, on_token, on_complete, on_error, NULL
        );

        if (!gen) {
            fprintf(stderr, "Failed to start generation: %s\n", titan_get_last_error());
            continue;
        }

        /* Wait for completion (up to 60 seconds) */
        if (!titan_generation_wait(gen, 60000)) {
            fprintf(stderr, "Generation timed out, canceling...\n");
            titan_generation_cancel(gen);
        }

        titan_generation_free(gen);

        /* Print metrics */
        TitanMetrics metrics;
        if (titan_get_metrics(ctx, &metrics)) {
            printf("\n[Metrics: %.1f TPS, %.1f ms TTFT, %.1f MB RAM]\n",
                   metrics.tokens_per_second,
                   metrics.time_to_first_token_ms,
                   metrics.memory_usage_bytes / (1024.0f * 1024.0f));
        }

        printf("\n");
    }

    /* Cleanup */
    printf("\nShutting down...\n");
    titan_free(ctx);

    printf("Done.\n");
    return 0;
}
