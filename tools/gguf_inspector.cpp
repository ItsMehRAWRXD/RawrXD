// ═════════════════════════════════════════════════════════════════════════════
// GGUF Inspector Tool - Deep Model Architecture Analysis
// For RawrXD IDE Integration
// ═════════════════════════════════════════════════════════════════════════════

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <iostream>
#include <iomanip>

// GGUF Magic Number
static const uint32_t GGUF_MAGIC = 0x46554747; // "GGUF" in little-endian

// GGUF Version
static const uint32_t GGUF_VERSION = 3;

// GGML Types
enum ggml_type {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
    GGML_TYPE_IQ2_XXS = 16,
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ4_XS  = 22,
    GGML_TYPE_I8      = 23,
    GGML_TYPE_I16     = 24,
    GGML_TYPE_I32     = 25,
    GGML_TYPE_I64     = 26,
    GGML_TYPE_F64     = 27,
    GGML_TYPE_IQ1_M   = 28,
    GGML_TYPE_COUNT   = 29,
};

const char* ggml_type_name(ggml_type type) {
    switch (type) {
        case GGML_TYPE_F32: return "F32";
        case GGML_TYPE_F16: return "F16";
        case GGML_TYPE_Q4_0: return "Q4_0";
        case GGML_TYPE_Q4_1: return "Q4_1";
        case GGML_TYPE_Q5_0: return "Q5_0";
        case GGML_TYPE_Q5_1: return "Q5_1";
        case GGML_TYPE_Q8_0: return "Q8_0";
        case GGML_TYPE_Q8_1: return "Q8_1";
        case GGML_TYPE_Q2_K: return "Q2_K";
        case GGML_TYPE_Q3_K: return "Q3_K";
        case GGML_TYPE_Q4_K: return "Q4_K";
        case GGML_TYPE_Q5_K: return "Q5_K";
        case GGML_TYPE_Q6_K: return "Q6_K";
        case GGML_TYPE_Q8_K: return "Q8_K";
        case GGML_TYPE_IQ2_XXS: return "IQ2_XXS";
        case GGML_TYPE_IQ2_XS: return "IQ2_XS";
        case GGML_TYPE_IQ3_XXS: return "IQ3_XXS";
        case GGML_TYPE_IQ1_S: return "IQ1_S";
        case GGML_TYPE_IQ4_NL: return "IQ4_NL";
        case GGML_TYPE_IQ3_S: return "IQ3_S";
        case GGML_TYPE_IQ4_XS: return "IQ4_XS";
        case GGML_TYPE_I8: return "I8";
        case GGML_TYPE_I16: return "I16";
        case GGML_TYPE_I32: return "I32";
        case GGML_TYPE_I64: return "I64";
        case GGML_TYPE_F64: return "F64";
        case GGML_TYPE_IQ1_M: return "IQ1_M";
        default: return "UNKNOWN";
    }
}

size_t ggml_type_size(ggml_type type) {
    switch (type) {
        case GGML_TYPE_F32:  return 4;
        case GGML_TYPE_F16:  return 2;
        case GGML_TYPE_Q4_0: return 18;
        case GGML_TYPE_Q4_1: return 20;
        case GGML_TYPE_Q5_0: return 22;
        case GGML_TYPE_Q5_1: return 24;
        case GGML_TYPE_Q8_0: return 34;
        case GGML_TYPE_Q8_1: return 36;
        case GGML_TYPE_Q2_K: return 12;
        case GGML_TYPE_Q3_K: return 16;
        case GGML_TYPE_Q4_K: return 18;
        case GGML_TYPE_Q5_K: return 22;
        case GGML_TYPE_Q6_K: return 26;
        case GGML_TYPE_Q8_K: return 34;
        default: return 1;
    }
}

// GGUF Value Types
enum gguf_type {
    GGUF_TYPE_UINT8   = 0,
    GGUF_TYPE_INT8    = 1,
    GGUF_TYPE_UINT16  = 2,
    GGUF_TYPE_INT16   = 3,
    GGUF_TYPE_UINT32  = 4,
    GGUF_TYPE_INT32   = 5,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL    = 7,
    GGUF_TYPE_STRING  = 8,
    GGUF_TYPE_ARRAY   = 9,
    GGUF_TYPE_UINT64  = 10,
    GGUF_TYPE_INT64   = 11,
    GGUF_TYPE_FLOAT64 = 12,
    GGUF_TYPE_COUNT   = 13,
};

struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

struct TensorInfo {
    std::string name;
    uint32_t n_dims;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
    size_t size;
};

struct MetadataKV {
    std::string key;
    uint32_t type;
    std::vector<uint8_t> value;
    std::string str_value;
};

class GGUFInspector {
public:
    std::string filepath;
    GGUFHeader header;
    std::vector<TensorInfo> tensors;
    std::map<std::string, MetadataKV> metadata;
    size_t file_size;
    size_t data_offset;
    
    bool Load(const std::string& path);
    void PrintHeader();
    void PrintArchitecture();
    void PrintTensorSummary();
    void PrintLayerAnalysis();
    void PrintVerification();
    void PrintTensorList(int limit = 20);
    void PrintAllMetadata();
    void ExportJSON(const std::string& output_path);
    
private:
    bool ReadString(FILE* f, std::string& out);
    bool ReadValue(FILE* f, uint32_t type, std::vector<uint8_t>& value, std::string& str_value);
    size_t CalculateTensorSize(const TensorInfo& info);
    std::string FormatBytes(size_t bytes);
    std::string FormatNumber(size_t n);
    std::string EscapeJSON(const std::string& s);
};

bool GGUFInspector::Load(const std::string& path) {
    filepath = path;
    
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        std::cerr << "Failed to open: " << path << std::endl;
        return false;
    }
    
    fseek(f, 0, SEEK_END);
    file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fread(&header.magic, 4, 1, f) != 1) return false;
    if (fread(&header.version, 4, 1, f) != 1) return false;
    if (fread(&header.tensor_count, 8, 1, f) != 1) return false;
    if (fread(&header.metadata_kv_count, 8, 1, f) != 1) return false;
    
    if (header.magic != GGUF_MAGIC) {
        std::cerr << "Invalid GGUF magic: 0x" << std::hex << header.magic << std::dec << std::endl;
        fclose(f);
        return false;
    }
    
    for (uint64_t i = 0; i < header.metadata_kv_count; i++) {
        MetadataKV kv;
        if (!ReadString(f, kv.key)) { fclose(f); return false; }
        if (fread(&kv.type, 4, 1, f) != 1) { fclose(f); return false; }
        if (!ReadValue(f, kv.type, kv.value, kv.str_value)) { fclose(f); return false; }
        metadata[kv.key] = kv;
    }
    
    for (uint64_t i = 0; i < header.tensor_count; i++) {
        TensorInfo info;
        if (!ReadString(f, info.name)) { fclose(f); return false; }
        if (fread(&info.n_dims, 4, 1, f) != 1) { fclose(f); return false; }
        info.dims.resize(info.n_dims);
        for (uint32_t d = 0; d < info.n_dims; d++) {
            if (fread(&info.dims[d], 8, 1, f) != 1) { fclose(f); return false; }
        }
        if (fread(&info.type, 4, 1, f) != 1) { fclose(f); return false; }
        if (fread(&info.offset, 8, 1, f) != 1) { fclose(f); return false; }
        info.size = CalculateTensorSize(info);
        tensors.push_back(info);
    }
    
    data_offset = ftell(f);
    data_offset = (data_offset + 31) & ~31;
    
    fclose(f);
    return true;
}

void GGUFInspector::PrintHeader() {
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                    GGUF MODEL ARCHITECTURE ANALYSIS                          ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    std::cout << "File: " << filepath << std::endl;
    std::cout << "Size: " << FormatBytes(file_size) << " (" << file_size << " bytes)" << std::endl;
    std::cout << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " HEADER" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << "  Magic:           GGUF (0x" << std::hex << header.magic << std::dec << ")" << std::endl;
    std::cout << "  Version:         " << header.version << std::endl;
    std::cout << "  Tensor Count:    " << header.tensor_count << std::endl;
    std::cout << "  Metadata Count:  " << header.metadata_kv_count << std::endl;
    std::cout << "  Data Offset:     " << data_offset << std::endl;
    std::cout << std::endl;
}

void GGUFInspector::PrintArchitecture() {
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " ARCHITECTURE METADATA" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    
    const char* arch_keys[] = {
        "general.architecture",
        "general.name",
        "general.quantization_version",
        "general.file_type",
        "general.parameter_count",
        "llama.context_length",
        "llama.embedding_length",
        "llama.block_count",
        "llama.feed_forward_length",
        "llama.attention.head_count",
        "llama.attention.head_count_kv",
        "llama.attention.layer_norm_rms_epsilon",
        "llama.rope.dimension_count",
        "llama.rope.freq_base",
        "llama.expert_count",
        "llama.expert_used_count",
        "llama.vocab_size",
        nullptr
    };
    
    for (int i = 0; arch_keys[i]; i++) {
        auto it = metadata.find(arch_keys[i]);
        if (it != metadata.end()) {
            std::cout << "  " << std::left << std::setw(40) << it->first << ": " << it->second.str_value << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " MIXTURE OF EXPERTS (MoE) ANALYSIS" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    
    bool has_expert_count = metadata.find("llama.expert_count") != metadata.end();
    bool has_expert_used = metadata.find("llama.expert_used_count") != metadata.end();
    
    if (has_expert_count || has_expert_used) {
        std::cout << "  ✅ MoE Architecture DETECTED" << std::endl;
        if (has_expert_count) {
            std::cout << "     Expert Count: " << metadata["llama.expert_count"].str_value << std::endl;
        }
        if (has_expert_used) {
            std::cout << "     Experts Used: " << metadata["llama.expert_used_count"].str_value << std::endl;
        }
    } else {
        std::cout << "  ❌ Dense Architecture (No MoE detected)" << std::endl;
    }
    
    int expert_tensors = 0;
    for (const auto& t : tensors) {
        if (t.name.find("expert") != std::string::npos ||
            t.name.find("ffn_gate_exps") != std::string::npos ||
            t.name.find("ffn_up_exps") != std::string::npos ||
            t.name.find("ffn_down_exps") != std::string::npos) {
            expert_tensors++;
        }
    }
    
    if (expert_tensors > 0) {
        std::cout << "  ✅ Expert Tensors Found: " << expert_tensors << std::endl;
    } else {
        std::cout << "  ❌ No Expert Tensors Found" << std::endl;
    }
    
    std::cout << std::endl;
}

void GGUFInspector::PrintTensorSummary() {
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " TENSOR SUMMARY" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    
    std::map<uint32_t, int> type_counts;
    std::map<uint32_t, size_t> type_sizes;
    size_t total_params = 0;
    
    for (const auto& t : tensors) {
        type_counts[t.type]++;
        type_sizes[t.type] += t.size;
        size_t elements = 1;
        for (auto d : t.dims) elements *= d;
        total_params += elements;
    }
    
    std::cout << "  Total Tensors: " << tensors.size() << std::endl;
    std::cout << "  Total Parameters: " << FormatNumber(total_params) << std::endl;
    std::cout << std::endl;
    
    std::cout << "  Quantization Breakdown:" << std::endl;
    for (const auto& [type, count] : type_counts) {
        std::cout << "    " << std::left << std::setw(10) << ggml_type_name((ggml_type)type)
                  << ": " << std::setw(6) << count << " tensors, "
                  << FormatBytes(type_sizes[type]) << std::endl;
    }
    
    std::cout << std::endl;
}

void GGUFInspector::PrintLayerAnalysis() {
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " LAYER ANALYSIS" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    
    int attention_layers = 0;
    int ffn_layers = 0;
    int norm_layers = 0;
    int embedding_layers = 0;
    int output_layers = 0;
    int other_layers = 0;
    
    for (const auto& t : tensors) {
        if (t.name.find("attn") != std::string::npos || 
            t.name.find("attention") != std::string::npos) {
            attention_layers++;
        } else if (t.name.find("ffn") != std::string::npos || 
                   t.name.find("feed_forward") != std::string::npos) {
            ffn_layers++;
        } else if (t.name.find("norm") != std::string::npos) {
            norm_layers++;
        } else if (t.name.find("embed") != std::string::npos || 
                   t.name.find("token_embd") != std::string::npos) {
            embedding_layers++;
        } else if (t.name.find("output") != std::string::npos) {
            output_layers++;
        } else {
            other_layers++;
        }
    }
    
    std::cout << "  Attention Layers:  " << attention_layers << std::endl;
    std::cout << "  FFN Layers:        " << ffn_layers << std::endl;
    std::cout << "  Norm Layers:       " << norm_layers << std::endl;
    std::cout << "  Embedding Layers:  " << embedding_layers << std::endl;
    std::cout << "  Output Layers:     " << output_layers << std::endl;
    std::cout << "  Other:             " << other_layers << std::endl;
    std::cout << std::endl;
}

void GGUFInspector::PrintVerification() {
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " VERIFICATION SUMMARY" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    
    std::string claimed_params = "N/A";
    auto it = metadata.find("general.parameter_count");
    if (it != metadata.end()) {
        claimed_params = it->second.str_value;
    }
    
    size_t total_params = 0;
    for (const auto& t : tensors) {
        size_t elements = 1;
        for (auto d : t.dims) elements *= d;
        total_params += elements;
    }
    
    std::cout << "  Claimed Parameters:  " << claimed_params << std::endl;
    std::cout << "  Actual Parameters:   " << FormatNumber(total_params) << std::endl;
    std::cout << "  File Size:           " << FormatBytes(file_size) << std::endl;
    
    bool has_moe_metadata = metadata.find("llama.expert_count") != metadata.end();
    bool has_expert_tensors = false;
    for (const auto& t : tensors) {
        if (t.name.find("expert") != std::string::npos ||
            t.name.find("ffn_gate_exps") != std::string::npos) {
            has_expert_tensors = true;
            break;
        }
    }
    
    std::cout << std::endl;
    std::cout << "  MoE Claims vs Reality:" << std::endl;
    if (has_moe_metadata && has_expert_tensors) {
        std::cout << "    ✅ VERIFIED: MoE architecture with expert tensors" << std::endl;
    } else if (has_moe_metadata && !has_expert_tensors) {
        std::cout << "    ⚠️  WARNING: MoE metadata but NO expert tensors found" << std::endl;
        std::cout << "       Likely: Dense model with MoE system prompt only" << std::endl;
    } else if (!has_moe_metadata && has_expert_tensors) {
        std::cout << "    ⚠️  WARNING: Expert tensors found but no MoE metadata" << std::endl;
    } else {
        std::cout << "    ❌ Dense model (no MoE)" << std::endl;
    }
    
    std::cout << std::endl;
}

void GGUFInspector::PrintTensorList(int limit) {
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " FIRST " << limit << " TENSORS" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    
    int count = 0;
    for (const auto& t : tensors) {
        if (count >= limit) break;
        
        std::cout << "  " << std::left << std::setw(50) << t.name;
        std::cout << " [" << ggml_type_name((ggml_type)t.type) << "] ";
        std::cout << "[";
        for (size_t i = 0; i < t.dims.size(); i++) {
            if (i > 0) std::cout << ", ";
            std::cout << t.dims[i];
        }
        std::cout << "] ";
        std::cout << FormatBytes(t.size) << std::endl;
        count++;
    }
    
    if (tensors.size() > limit) {
        std::cout << "  ... and " << (tensors.size() - limit) << " more tensors" << std::endl;
    }
    std::cout << std::endl;
}

void GGUFInspector::PrintAllMetadata() {
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << " ALL METADATA (" << metadata.size() << " entries)" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════════════════" << std::endl;
    
    for (const auto& [key, kv] : metadata) {
        std::cout << "  " << std::left << std::setw(50) << key << ": ";
        if (kv.str_value.length() > 60) {
            std::cout << kv.str_value.substr(0, 57) << "...";
        } else {
            std::cout << kv.str_value;
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

void GGUFInspector::ExportJSON(const std::string& output_path) {
    std::ofstream out(output_path);
    if (!out) {
        std::cerr << "Failed to open output: " << output_path << std::endl;
        return;
    }
    
    out << "{" << std::endl;
    out << "  \"file\": \"" << filepath << "\"," << std::endl;
    out << "  \"file_size\": " << file_size << "," << std::endl;
    out << "  \"gguf_version\": " << header.version << "," << std::endl;
    out << "  \"tensor_count\": " << header.tensor_count << "," << std::endl;
    out << "  \"metadata\": {" << std::endl;
    
    bool first = true;
    for (const auto& [key, kv] : metadata) {
        if (!first) out << "," << std::endl;
        first = false;
        out << "    \"" << EscapeJSON(key) << "\": \"" << EscapeJSON(kv.str_value) << "\"";
    }
    out << std::endl << "  }," << std::endl;
    
    out << "  \"tensors\": [" << std::endl;
    first = true;
    for (const auto& t : tensors) {
        if (!first) out << "," << std::endl;
        first = false;
        out << "    {\"name\": \"" << EscapeJSON(t.name) << "\", ";
        out << "\"type\": \"" << ggml_type_name((ggml_type)t.type) << "\", ";
        out << "\"size\": " << t.size << "}";
    }
    out << std::endl << "  ]" << std::endl;
    out << "}" << std::endl;
    
    std::cout << "Exported to: " << output_path << std::endl;
}

bool GGUFInspector::ReadString(FILE* f, std::string& out) {
    uint64_t len;
    if (fread(&len, 8, 1, f) != 1) return false;
    out.resize(len);
    if (len > 0) {
        if (fread(&out[0], 1, len, f) != len) return false;
    }
    return true;
}

bool GGUFInspector::ReadValue(FILE* f, uint32_t type, std::vector<uint8_t>& value, std::string& str_value) {
    switch (type) {
        case GGUF_TYPE_UINT8: {
            uint8_t v;
            if (fread(&v, 1, 1, f) != 1) return false;
            value.resize(1);
            value[0] = v;
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_INT8: {
            int8_t v;
            if (fread(&v, 1, 1, f) != 1) return false;
            value.resize(1);
            value[0] = v;
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_UINT16: {
            uint16_t v;
            if (fread(&v, 2, 1, f) != 1) return false;
            value.resize(2);
            memcpy(value.data(), &v, 2);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_INT16: {
            int16_t v;
            if (fread(&v, 2, 1, f) != 1) return false;
            value.resize(2);
            memcpy(value.data(), &v, 2);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_UINT32: {
            uint32_t v;
            if (fread(&v, 4, 1, f) != 1) return false;
            value.resize(4);
            memcpy(value.data(), &v, 4);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_INT32: {
            int32_t v;
            if (fread(&v, 4, 1, f) != 1) return false;
            value.resize(4);
            memcpy(value.data(), &v, 4);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_UINT64: {
            uint64_t v;
            if (fread(&v, 8, 1, f) != 1) return false;
            value.resize(8);
            memcpy(value.data(), &v, 8);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_INT64: {
            int64_t v;
            if (fread(&v, 8, 1, f) != 1) return false;
            value.resize(8);
            memcpy(value.data(), &v, 8);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_FLOAT32: {
            float v;
            if (fread(&v, 4, 1, f) != 1) return false;
            value.resize(4);
            memcpy(value.data(), &v, 4);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_FLOAT64: {
            double v;
            if (fread(&v, 8, 1, f) != 1) return false;
            value.resize(8);
            memcpy(value.data(), &v, 8);
            str_value = std::to_string(v);
            break;
        }
        case GGUF_TYPE_BOOL: {
            uint8_t v;
            if (fread(&v, 1, 1, f) != 1) return false;
            value.resize(1);
            value[0] = v;
            str_value = v ? "true" : "false";
            break;
        }
        case GGUF_TYPE_STRING: {
            std::string v;
            if (!ReadString(f, v)) return false;
            value.resize(v.size());
            memcpy(value.data(), v.data(), v.size());
            str_value = v;
            break;
        }
        case GGUF_TYPE_ARRAY: {
            uint32_t arr_type;
            uint64_t arr_len;
            if (fread(&arr_type, 4, 1, f) != 1) return false;
            if (fread(&arr_len, 8, 1, f) != 1) return false;
            str_value = "[array of " + std::to_string(arr_len) + " elements]";
            for (uint64_t i = 0; i < arr_len; i++) {
                std::vector<uint8_t> dummy;
                std::string dummy_str;
                if (!ReadValue(f, arr_type, dummy, dummy_str)) return false;
            }
            break;
        }
        default:
            return false;
    }
    return true;
}

size_t GGUFInspector::CalculateTensorSize(const TensorInfo& info) {
    size_t elements = 1;
    for (auto d : info.dims) elements *= d;
    
    ggml_type type = (ggml_type)info.type;
    size_t type_size = ggml_type_size(type);
    
    switch (type) {
        case GGML_TYPE_Q4_0:
        case GGML_TYPE_Q4_1:
            return (elements / 32) * type_size;
        case GGML_TYPE_Q5_0:
        case GGML_TYPE_Q5_1:
            return (elements / 32) * type_size;
        case GGML_TYPE_Q8_0:
        case GGML_TYPE_Q8_1:
            return (elements / 32) * type_size;
        case GGML_TYPE_Q2_K:
        case GGML_TYPE_Q3_K:
        case GGML_TYPE_Q4_K:
        case GGML_TYPE_Q5_K:
        case GGML_TYPE_Q6_K:
        case GGML_TYPE_Q8_K:
            return (elements / 256) * type_size;
        default:
            return elements * type_size;
    }
}

std::string GGUFInspector::FormatBytes(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = (double)bytes;
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
    return std::string(buf);
}

std::string GGUFInspector::FormatNumber(size_t n) {
    char buf[64];
    if (n >= 1000000000) {
        snprintf(buf, sizeof(buf), "%.2fB", n / 1000000000.0);
    } else if (n >= 1000000) {
        snprintf(buf, sizeof(buf), "%.2fM", n / 1000000.0);
    } else if (n >= 1000) {
        snprintf(buf, sizeof(buf), "%.2fK", n / 1000.0);
    } else {
        snprintf(buf, sizeof(buf), "%zu", n);
    }
    return std::string(buf);
}

std::string GGUFInspector::EscapeJSON(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c >= 0x20 && c < 0x7F) {
                    out += c;
                } else {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                }
        }
    }
    return out;
}

void PrintUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <gguf_file> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --json <file>     Export analysis to JSON" << std::endl;
    std::cout << "  --full            Print full tensor list" << std::endl;
    std::cout << "  --metadata        Print all metadata" << std::endl;
    std::cout << "  --help            Show this help" << std::endl;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string filepath = argv[1];
    std::string json_output;
    bool full_tensors = false;
    bool all_metadata = false;
    
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--json" && i + 1 < argc) {
            json_output = argv[++i];
        } else if (arg == "--full") {
            full_tensors = true;
        } else if (arg == "--metadata") {
            all_metadata = true;
        } else if (arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    GGUFInspector inspector;
    
    std::cout << "Loading GGUF file..." << std::endl;
    if (!inspector.Load(filepath)) {
        std::cerr << "Failed to load GGUF file" << std::endl;
        return 1;
    }
    
    inspector.PrintHeader();
    inspector.PrintArchitecture();
    inspector.PrintTensorSummary();
    inspector.PrintLayerAnalysis();
    inspector.PrintVerification();
    
    if (all_metadata) {
        inspector.PrintAllMetadata();
    } else {
        inspector.PrintTensorList(full_tensors ? 1000 : 20);
    }
    
    if (!json_output.empty()) {
        inspector.ExportJSON(json_output);
    }
    
    return 0;
}
