//==============================================================================
// ModelDownloadCommands.cpp - Phase 15B: CLI Commands for Model Download
//
// CLI commands:
//   agent models download <url> [--name <name>] [--output <dir>]
//   agent models install <file> [--name <name>]
//   agent models search <query> [--source huggingface]
//   agent models verify <file> [--sha256 <hash>]
//==============================================================================

#include "../core/ModelDownloadSubsystem.h"
#include "../core/GGUFQuantizationDetector.h"
#include "../core/ModelRegistry.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstring>

//==============================================================================
// Command: models download
//==============================================================================

int CLI_ModelsDownload(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent models download <url|huggingface-id> [options]\n");
        printf("\nOptions:\n");
        printf("  --name <name>       Model display name\n");
        printf("  --output <dir>      Output directory (default: models/downloads)\n");
        printf("  --sha256 <hash>     Expected SHA256 for verification\n");
        printf("  --auto-install      Auto-install to registry after download\n");
        printf("  --backend <type>    Backend type: native, ollama (default: native)\n");
        printf("\nExamples:\n");
        printf("  agent models download https://example.com/model.gguf\n");
        printf("  agent models download unsloth/Llama-3.2-1B-Instruct-GGUF --auto-install\n");
        return 1;
    }
    
    const char* source = argv[2];
    
    // Initialize subsystem
    if (!ModelDownload_IsReady()) {
        ModelDownload_Init(NULL);
    }
    
    // Parse options
    DownloadConfig config = {0};
    config.resume_if_partial = 1;
    
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            strncpy(config.model_name, argv[++i], sizeof(config.model_name) - 1);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            strncpy(config.output_path, argv[++i], sizeof(config.output_path) - 1);
        } else if (strcmp(argv[i], "--sha256") == 0 && i + 1 < argc) {
            strncpy(config.expected_sha256, argv[++i], sizeof(config.expected_sha256) - 1);
        } else if (strcmp(argv[i], "--auto-install") == 0) {
            config.auto_install = 1;
        } else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            strncpy(config.backend_type, argv[++i], sizeof(config.backend_type) - 1);
        }
    }
    
    // Determine if it's a HuggingFace model ID or direct URL
    int download_id;
    if (strchr(source, '/') && !strstr(source, "://")) {
        // HuggingFace format: org/model or org/model:file.gguf
        printf("Resolving HuggingFace model: %s\n", source);
        
        if (!config.model_name[0]) {
            // Extract model name from ID
            const char* slash = strchr(source, '/');
            if (slash) {
                strncpy(config.model_name, slash + 1, sizeof(config.model_name) - 1);
            }
        }
        
        download_id = ModelDownload_StartFromHuggingFace(source, NULL, &config);
    } else {
        // Direct URL
        strncpy(config.url, source, sizeof(config.url) - 1);
        
        // Set output path if not provided
        if (!config.output_path[0]) {
            const char* filename = strrchr(source, '/');
            if (!filename) filename = source;
            else filename++;
            
            // Remove query parameters
            char clean_filename[256];
            strncpy(clean_filename, filename, sizeof(clean_filename) - 1);
            char* qmark = strchr(clean_filename, '?');
            if (qmark) *qmark = '\0';
            
            snprintf(config.output_path, sizeof(config.output_path),
                     "%s/%s", ModelDownload_GetDefaultDirectory(), clean_filename);
        }
        
        if (!config.model_name[0]) {
            // Extract from filename
            const char* filename = strrchr(config.output_path, '/');
            if (!filename) filename = strrchr(config.output_path, '\\');
            if (!filename) filename = config.output_path;
            else filename++;
            
            strncpy(config.model_name, filename, sizeof(config.model_name) - 1);
            // Remove extension
            char* dot = strrchr(config.model_name, '.');
            if (dot) *dot = '\0';
        }
        
        download_id = ModelDownload_Start(&config);
    }
    
    if (download_id < 0) {
        printf("Error: Failed to start download: %s\n", ModelDownload_GetLastError());
        return 1;
    }
    
    printf("Download started (ID: %d)\n", download_id);
    printf("Output: %s\n", config.output_path);
    printf("\n");
    
    // Progress loop
    DownloadProgress progress;
    int last_percent = -1;
    
    while (1) {
        if (ModelDownload_GetProgress(download_id, &progress) != 0) {
            break;
        }
        
        if (progress.state == DOWNLOAD_STATE_COMPLETED) {
            printf("\rDownload complete!                          \n");
            break;
        } else if (progress.state == DOWNLOAD_STATE_FAILED) {
            printf("\rDownload failed: %s\n", progress.status_message);
            return 1;
        } else if (progress.state == DOWNLOAD_STATE_CANCELLED) {
            printf("\rDownload cancelled.\n");
            return 1;
        }
        
        // Only update display when percentage changes
        if (progress.percent_complete != last_percent) {
            last_percent = progress.percent_complete;
            
            char size_str[32], total_str[32], speed_str[32];
            ModelDownload_FormatBytes(progress.bytes_downloaded, size_str, sizeof(size_str));
            ModelDownload_FormatBytes(progress.bytes_total, total_str, sizeof(total_str));
            ModelDownload_FormatSpeed(progress.bytes_per_second, speed_str, sizeof(speed_str));
            
            printf("\r[%3d%%] %s / %s at %s - %s",
                   progress.percent_complete,
                   size_str, total_str, speed_str,
                   progress.status_message);
            fflush(stdout);
        }
        
        Sleep(100);
    }
    
    // Detect quantization
    printf("\nAnalyzing model...\n");
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(config.output_path, &info) == 0) {
        printf("  Quantization: %s\n", info.quantization);
        printf("  Parameters: ");
        if (info.parameter_count >= 1000000000) {
            printf("%.1fB\n", info.parameter_count / 1000000000.0);
        } else if (info.parameter_count >= 1000000) {
            printf("%.1fM\n", info.parameter_count / 1000000.0);
        } else {
            printf("%llu\n", info.parameter_count);
        }
        printf("  Architecture: %s\n", info.architecture[0] ? info.architecture : "unknown");
        printf("  Context: %d tokens\n", info.context_length);
        
        // Auto-install if requested
        if (config.auto_install) {
            printf("\nInstalling to registry...\n");
            if (ModelDownload_InstallToRegistry(config.output_path,
                                                  config.model_name,
                                                  config.backend_type,
                                                  0) == 0) {
                printf("Model installed successfully!\n");
            } else {
                printf("Failed to install model.\n");
            }
        }
    }
    
    Journal_LogUserRequest("CLI download completed", config.model_name);
    
    return 0;
}

//==============================================================================
// Command: models install
//==============================================================================

int CLI_ModelsInstall(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent models install <file.gguf> [options]\n");
        printf("\nOptions:\n");
        printf("  --name <name>       Model display name\n");
        printf("  --backend <type>    Backend type (default: native)\n");
        printf("  --default           Set as default model\n");
        return 1;
    }
    
    const char* file_path = argv[2];
    
    // Verify file exists
    FILE* f = fopen(file_path, "rb");
    if (!f) {
        printf("Error: Cannot open file: %s\n", file_path);
        return 1;
    }
    fclose(f);
    
    // Parse options
    char model_name[128] = {0};
    char backend_type[32] = "native";
    int set_default = 0;
    
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            strncpy(model_name, argv[++i], sizeof(model_name) - 1);
        } else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            strncpy(backend_type, argv[++i], sizeof(backend_type) - 1);
        } else if (strcmp(argv[i], "--default") == 0) {
            set_default = 1;
        }
    }
    
    // Auto-detect if name not provided
    if (!model_name[0]) {
        DetectedModelInfo info;
        if (GGUFDetector_AnalyzeFile(file_path, &info) == 0 && info.model_name[0]) {
            strncpy(model_name, info.model_name, sizeof(model_name) - 1);
        } else {
            // Extract from filename
            const char* filename = strrchr(file_path, '/');
            if (!filename) filename = strrchr(file_path, '\\');
            if (!filename) filename = file_path;
            else filename++;
            
            strncpy(model_name, filename, sizeof(model_name) - 1);
            char* dot = strrchr(model_name, '.');
            if (dot) *dot = '\0';
        }
    }
    
    printf("Installing model: %s\n", model_name);
    printf("File: %s\n", file_path);
    
    // Detect metadata
    printf("\nDetecting model metadata...\n");
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(file_path, &info) == 0) {
        printf("  Quantization: %s\n", info.quantization);
        printf("  Parameters: ");
        if (info.parameter_count >= 1000000000) {
            printf("%.1fB\n", info.parameter_count / 1000000000.0);
        } else if (info.parameter_count >= 1000000) {
            printf("%.1fM\n", info.parameter_count / 1000000.0);
        } else {
            printf("%llu\n", info.parameter_count);
        }
        printf("  Architecture: %s\n", info.architecture[0] ? info.architecture : "unknown");
    }
    
    // Install
    if (ModelDownload_InstallToRegistry(file_path, model_name, backend_type, 0) != 0) {
        printf("\nError: Failed to install model.\n");
        return 1;
    }
    
    printf("\nModel installed successfully!\n");
    
    // Set as default if requested
    if (set_default) {
        // Find the model ID
        ModelInfo models[MAX_MODELS];
        int count;
        ModelRegistry_ListModels(models, MAX_MODELS, &count);
        
        for (int i = 0; i < count; i++) {
            if (strcmp(models[i].name, model_name) == 0) {
                ModelRegistry_SetDefaultModel(models[i].id);
                printf("Set as default model.\n");
                break;
            }
        }
    }
    
    Journal_LogUserRequest("CLI model installed", model_name);
    
    return 0;
}

//==============================================================================
// Command: models verify
//==============================================================================

int CLI_ModelsVerify(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: agent models verify <file.gguf> [--sha256 <hash>]\n");
        return 1;
    }
    
    const char* file_path = argv[2];
    const char* expected_hash = NULL;
    
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--sha256") == 0 && i + 1 < argc) {
            expected_hash = argv[++i];
        }
    }
    
    printf("Verifying: %s\n\n", file_path);
    
    // Check if valid GGUF
    if (!GGUFDetector_IsValidGGUF(file_path)) {
        printf("Error: File is not a valid GGUF file.\n");
        return 1;
    }
    
    printf("[OK] Valid GGUF file format\n");
    
    // Get version
    uint32_t version;
    if (GGUFDetector_GetFileVersion(file_path, &version) == 0) {
        printf("[OK] GGUF version: %d\n", version);
    }
    
    // Analyze file
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(file_path, &info) == 0) {
        printf("[OK] File structure valid\n");
        printf("\nModel Info:\n");
        printf("  Name: %s\n", info.model_name[0] ? info.model_name : "(not specified)");
        printf("  Architecture: %s\n", info.architecture[0] ? info.architecture : "unknown");
        printf("  Quantization: %s\n", info.quantization);
        printf("  Parameters: ");
        if (info.parameter_count >= 1000000000) {
            printf("%.1fB\n", info.parameter_count / 1000000000.0);
        } else if (info.parameter_count >= 1000000) {
            printf("%.1fM\n", info.parameter_count / 1000000.0);
        } else {
            printf("%llu\n", info.parameter_count);
        }
        printf("  Context Length: %d tokens\n", info.context_length);
        printf("  Embedding: %d dims\n", info.embedding_length);
        printf("  Layers: %d\n", info.num_layers);
        printf("  Heads: %d\n", info.num_heads);
        printf("  Tensors: %d (%d quantized, %d float)\n",
               info.tensor_count, info.quantized_tensors, info.float_tensors);
        
        // Memory estimate
        uint64_t mem = GGUFDetector_EstimateMemoryRequired(&info);
        char mem_str[32];
        if (mem >= 1024ULL * 1024 * 1024) {
            snprintf(mem_str, sizeof(mem_str), "%.1f GB", mem / (1024.0 * 1024 * 1024));
        } else {
            snprintf(mem_str, sizeof(mem_str), "%.1f MB", mem / (1024.0 * 1024));
        }
        printf("  Estimated Memory: %s\n", mem_str);
        
        // Quality score
        int quality = GGUFDetector_GetQualityScore(info.quant_type);
        printf("  Quality Score: %d/100\n", quality);
        printf("  Recommended Use: %s\n", GGUFDetector_GetRecommendedUse(info.quant_type));
    } else {
        printf("[ERROR] Failed to analyze file: %s\n", info.error_message);
        return 1;
    }
    
    // Verify SHA256 if provided
    if (expected_hash) {
        printf("\nVerifying SHA256...\n");
        if (ModelDownload_VerifySHA256(file_path, expected_hash) == 0) {
            printf("[OK] SHA256 verification passed\n");
        } else {
            printf("[ERROR] SHA256 verification failed!\n");
            return 1;
        }
    }
    
    printf("\nVerification complete.\n");
    
    return 0;
}

//==============================================================================
// Command: models list
//==============================================================================

int CLI_ModelsList(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    ModelInfo models[MAX_MODELS];
    int count;
    
    if (ModelRegistry_ListModels(models, MAX_MODELS, &count) != 0) {
        printf("Error: Failed to list models.\n");
        return 1;
    }
    
    if (count == 0) {
        printf("No models registered.\n");
        printf("Use 'agent models download' or 'agent models install' to add models.\n");
        return 0;
    }
    
    printf("Registered Models (%d):\n\n", count);
    printf("%-20s %-30s %-12s %-10s %-8s\n",
           "ID", "Name", "Quant", "Params", "Status");
    printf("%-20s %-30s %-12s %-10s %-8s\n",
           "--------------------", "------------------------------",
           "------------", "----------", "--------");
    
    for (int i = 0; i < count; i++) {
        const char* status = "";
        if (models[i].is_default) status = "default";
        else if (models[i].is_loaded) status = "loaded";
        
        char params_str[16];
        if (models[i].parameter_count >= 1000000000) {
            snprintf(params_str, sizeof(params_str), "%.1fB", models[i].parameter_count / 1000000000.0);
        } else if (models[i].parameter_count >= 1000000) {
            snprintf(params_str, sizeof(params_str), "%.1fM", models[i].parameter_count / 1000000.0);
        } else if (models[i].parameter_count >= 1000) {
            snprintf(params_str, sizeof(params_str), "%.1fK", models[i].parameter_count / 1000.0);
        } else {
            snprintf(params_str, sizeof(params_str), "%llu", models[i].parameter_count);
        }
        
        printf("%-20s %-30s %-12s %-10s %-8s\n",
               models[i].id,
               models[i].name,
               models[i].quantization[0] ? models[i].quantization : "-",
               params_str,
               status);
    }
    
    return 0;
}

//==============================================================================
// Command Router
//==============================================================================

int CLI_ModelsCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: agent models <subcommand> [args]\n");
        printf("\nSubcommands:\n");
        printf("  download <url>    Download a model from URL or HuggingFace\n");
        printf("  install <file>    Install a local GGUF file to registry\n");
        printf("  verify <file>       Verify a GGUF file\n");
        printf("  list              List registered models\n");
        return 1;
    }
    
    const char* subcmd = argv[1];
    
    if (strcmp(subcmd, "download") == 0) {
        return CLI_ModelsDownload(argc, argv);
    } else if (strcmp(subcmd, "install") == 0) {
        return CLI_ModelsInstall(argc, argv);
    } else if (strcmp(subcmd, "verify") == 0) {
        return CLI_ModelsVerify(argc, argv);
    } else if (strcmp(subcmd, "list") == 0) {
        return CLI_ModelsList(argc, argv);
    } else {
        printf("Unknown subcommand: %s\n", subcmd);
        printf("Use 'agent models' for help.\n");
        return 1;
    }
}
