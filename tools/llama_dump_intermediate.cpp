// llama_dump_intermediate.cpp
// Dumps intermediate tensors layer-by-layer for teacher-forced token positions
// Uses llama.cpp's graph eval callback to capture tensor outputs
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <filesystem>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include "llama.h"
#include "ggml.h"
#include "ggml-backend.h"

namespace fs = std::filesystem;

struct TensorDump {
    std::string name;
    std::vector<float> data;
    std::vector<int64_t> shape;
    int pos;
    int layer;
};

static std::vector<TensorDump> g_dumps;
static int g_current_pos = 0;
static std::string g_out_dir;
static int g_n_vocab = 128256;
static std::mutex g_dump_mutex;
static std::unordered_set<std::string> g_captured_keys;

// Reset the captured set (called between positions)
void reset_captured_set() {
    extern std::unordered_set<std::string> g_captured_keys;
    std::lock_guard<std::mutex> lock(g_dump_mutex);
    g_captured_keys.clear();
}

// Map tensor names to our simplified names
static std::string simplify_name(const char* name) {
    if (!name) return "";
    std::string n(name);
    
    // Match llama.cpp tensor names (format: name-layer)
    // e.g., attn_norm-0, Qcur-0, attn_out-0, ffn_norm-0, ffn_gate-0, ffn_up-0, ffn_swiglu-0, ffn_out-0, l_out-0
    if (n.find("embd") != std::string::npos && n.find("result") == std::string::npos && n.find("inp_") == std::string::npos) {
        return "embd";
    } else if (n.find("attn_norm") != std::string::npos) {
        return "attn_norm";
    } else if (n.find("Qcur") != std::string::npos) {
        return "q";
    } else if (n.find("Kcur") != std::string::npos) {
        return "k";
    } else if (n.find("Vcur") != std::string::npos) {
        return "v";
    } else if (n.find("attn_out") != std::string::npos || n.find("kqv_out") != std::string::npos) {
        return "attn_out";
    } else if (n.find("ffn_norm") != std::string::npos) {
        return "ffn_norm";
    } else if (n.find("ffn_gate") != std::string::npos) {
        return "gate";
    } else if (n.find("ffn_up") != std::string::npos) {
        return "up";
    } else if (n.find("ffn_swiglu") != std::string::npos) {
        return "swiglu";
    } else if (n.find("ffn_out") != std::string::npos) {
        return "ffn_out";
    } else if (n.find("l_out") != std::string::npos) {
        return "resid";
    } else if (n.find("result_norm") != std::string::npos) {
        return "out_norm";
    } else if (n.find("result_output") != std::string::npos) {
        return "logits";
    }
    return "";
}

// Extract layer index from tensor name (format: name-X where X is layer number)
static int extract_layer(const char* name) {
    if (!name) return -1;
    std::string n(name);
    
    // Look for pattern: name-X where X is the layer number
    size_t dash_pos = n.rfind('-');
    if (dash_pos != std::string::npos && dash_pos + 1 < n.length()) {
        std::string layer_str = n.substr(dash_pos + 1);
        // Check if it's a pure number
        bool all_digits = true;
        for (char c : layer_str) {
            if (!std::isdigit(c)) {
                all_digits = false;
                break;
            }
        }
        if (all_digits && !layer_str.empty()) {
            try {
                return std::stoi(layer_str);
            } catch (...) {
                return -1;
            }
        }
    }
    
    // Also check for "blk." pattern (fallback)
    size_t pos = n.find("blk.");
    if (pos != std::string::npos) {
        size_t end = n.find('.', pos + 4);
        if (end != std::string::npos) {
            std::string layer_str = n.substr(pos + 4, end - pos - 4);
            try {
                return std::stoi(layer_str);
            } catch (...) {
                return -1;
            }
        }
    }
    return -1;
}

// Callback function for ggml graph execution
static bool graph_node_callback(struct ggml_tensor * t, bool ask, void * user_data) {
    (void)user_data;
    (void)ask;
    
    if (!t || !t->data || !t->name) return true;
    
    // DEBUG: Print all tensor names to understand naming
    static int call_count = 0;
    static FILE* debug_f = nullptr;
    if (!debug_f) {
        debug_f = std::fopen("F:/rawrxd/evidence/deep2_gate_a/ref_bin/debug_callback.txt", "w");
    }
    if (debug_f && call_count < 500) {
        std::fprintf(debug_f, "CALLBACK[%d]: name=%s, type=%d, ne=[%lld,%lld,%lld,%lld]\n", 
                    call_count, t->name, t->type, t->ne[0], t->ne[1], t->ne[2], t->ne[3]);
        std::fflush(debug_f);
        call_count++;
    }
    
    std::string simple_name = simplify_name(t->name);
    if (simple_name.empty()) return true;
    
    int layer = extract_layer(t->name);
    
    // Only handle F32 tensors for now
    if (t->type != GGML_TYPE_F32) {
        return true;
    }
    
    size_t n_elements = 1;
    for (int i = 0; i < GGML_MAX_DIMS; i++) {
        if (t->ne[i] > 1) n_elements *= t->ne[i];
    }
    
    if (n_elements == 0) return true;
    
    std::vector<float> data(n_elements);
    float * src = (float *)t->data;
    std::memcpy(data.data(), src, n_elements * sizeof(float));
    
    // Shape
    std::vector<int64_t> shape;
    for (int i = 0; i < GGML_MAX_DIMS; i++) {
        if (t->ne[i] > 0) shape.push_back(t->ne[i]);
    }
    
    std::string full_name = simple_name;
    if (layer >= 0) {
        full_name += "_layer" + std::to_string(layer);
    }
    
    TensorDump dump;
    dump.name = full_name;
    dump.data = std::move(data);
    dump.shape = std::move(shape);
    dump.pos = g_current_pos;
    dump.layer = layer;
    
    std::lock_guard<std::mutex> lock(g_dump_mutex);
    g_dumps.push_back(std::move(dump));
    
    return true;
}

void print_usage(const char* argv0) {
    std::fprintf(stderr, "Usage: %s <model.gguf> <tokens_file> <output_dir> [n_vocab]\n", argv0);
    std::fprintf(stderr, "  tokens_file: text file with space-separated token IDs\n");
    std::fprintf(stderr, "  output_dir: directory to write ref_*_pos*.bin files\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char* model_path = argv[1];
    const char* tokens_file = argv[2];
    g_out_dir = argv[3];
    g_n_vocab = argc > 4 ? std::atoi(argv[4]) : 128256;

    // Read token IDs from file
    FILE* tf = std::fopen(tokens_file, "r");
    if (!tf) {
        std::fprintf(stderr, "Failed to open tokens file: %s\n", tokens_file);
        return 1;
    }
    
    std::vector<llama_token> tokens;
    llama_token tok;
    while (std::fscanf(tf, "%d", &tok) == 1) {
        tokens.push_back(tok);
    }
    std::fclose(tf);
    
    if (tokens.empty()) {
        std::fprintf(stderr, "No tokens found in file\n");
        return 1;
    }
    
    std::printf("Loaded %zu tokens from %s\n", tokens.size(), tokens_file);

    // Initialize llama.cpp
    llama_backend_init();

    // Load model
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0; // CPU only
    struct llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::fprintf(stderr, "Failed to load model: %s\n", model_path);
        return 1;
    }

    // Create context with callback
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 1024;
    ctx_params.n_batch = 1024;
    ctx_params.embeddings = true;
    ctx_params.cb_eval = graph_node_callback;
    ctx_params.cb_eval_user_data = nullptr;
    
    struct llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::fprintf(stderr, "Failed to create context\n");
        llama_model_free(model);
        return 2;
    }

    // Create output directory
    fs::create_directories(g_out_dir);

    // Process each position
    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        g_current_pos = pos;
        g_dumps.clear();

        // Create batch with single token at correct position
        llama_batch batch = llama_batch_init(1, 0, 1);
        if (!batch.token) {
            std::fprintf(stderr, "llama_batch_init failed at pos %zu\n", pos);
            return 4;
        }
        batch.n_tokens = 1;
        batch.token[0] = tokens[pos];
        batch.pos[0] = pos;
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0;
        batch.logits[0] = 1;

        // Decode
        if (llama_decode(ctx, batch) != 0) {
            std::fprintf(stderr, "llama_decode failed at pos %zu\n", pos);
            llama_batch_free(batch);
            return 5;
        }

        // Save captured intermediate tensors
        // Use a per-(pos,layer,name) counter so multiple graph stages
        // (raw GEMV [N] vs reshaped [H,D]) get distinct filenames.
        std::unordered_map<std::string,int> stage_counter;
        for (const auto& dump : g_dumps) {
            std::string base = "ref_pos" + std::to_string(pos) + "_layer" +
                               std::to_string(dump.layer) + "_" + dump.name;
            int idx = stage_counter[base]++;
            std::string fname = base;
            if (idx > 0) fname += "_stage" + std::to_string(idx);
            
            char path[512];
            std::snprintf(path, sizeof(path), "%s/%s.bin", g_out_dir.c_str(), fname.c_str());
            FILE* f = std::fopen(path, "wb");
            if (f) {
                std::fwrite(dump.data.data(), sizeof(float), dump.data.size(), f);
                std::fclose(f);
            }
        }

        // Get logits
        float* logits = llama_get_logits_ith(ctx, 0);
        if (!logits) {
            std::fprintf(stderr, "llama_get_logits_ith returned null at pos %zu\n", pos);
            llama_batch_free(batch);
            return 6;
        }

        // Save logits
        char path[512];
        std::snprintf(path, sizeof(path), "%s/ref_logits_pos%zu.bin", g_out_dir.c_str(), pos);
        FILE* f = std::fopen(path, "wb");
        if (!f) {
            std::fprintf(stderr, "Failed to open %s\n", path);
            llama_batch_free(batch);
            return 6;
        }
        size_t written = std::fwrite(logits, sizeof(float), g_n_vocab, f);
        std::fclose(f);
        if (written != (size_t)g_n_vocab) {
            std::fprintf(stderr, "Incomplete write: %zu/%d\n", written, g_n_vocab);
            return 7;
        }
        std::printf("Wrote ref_logits_pos%zu.bin (%d floats)\n", pos, g_n_vocab);

        // Get embeddings (final hidden state before LM-head)
        const float* embeddings = llama_get_embeddings_ith(ctx, 0);
        if (embeddings) {
            std::snprintf(path, sizeof(path), "%s/ref_hidden_pos%zu.bin", g_out_dir.c_str(), pos);
            f = std::fopen(path, "wb");
            if (f) {
                size_t hidden_written = std::fwrite(embeddings, sizeof(float), 3072, f);
                std::fclose(f);
                if (hidden_written == 3072) {
                    std::printf("Wrote ref_hidden_pos%zu.bin (%zu floats)\n", pos, hidden_written);
                } else {
                    std::fprintf(stderr, "Incomplete hidden write: %zu/3072\n", hidden_written);
                }
            }
        } else {
            std::fprintf(stderr, "llama_get_embeddings_ith returned null at pos %zu\n", pos);
        }

        llama_batch_free(batch);
    }

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}