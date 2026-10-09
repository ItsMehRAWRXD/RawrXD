#ifndef MODELGENIE_EXECUTOR_HPP
#define MODELGENIE_EXECUTOR_HPP

//=============================================================================
// ModelGenieExecutor - reusable Deep2 IR execution engine
// RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
//
// Extracted from the standalone rawrxd_modelgenie_ir_executor tool. This
// header owns the model/context interface; the .cpp owns the verified kernels
// and the 300-operation IR dispatch table. Test-only code (CLI parsing,
// teacher-forced harness, differential capture driver) lives in
// tools/rawrxd_modelgenie_ir_executor.cpp so the runtime is importable by
// both the standalone executable and RawrXDCore.dll.
//=============================================================================

#include "RawrXD_IR_Trace.hpp" // RAWRXD_PARITY_TRACE_INJECTED
#include "ModelGenome.hpp"
#include "ModelGenomeReader.hpp"
#include "ModelGenieCompat.hpp"
#include "ModelExport.generated.hpp"
#include "ExecutionIR.generated.hpp"
#include "CapabilityManifest.generated.hpp"
#include "TensorROM.generated.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

namespace ModelGenie = ::RawrXD::Deep2::ModelGenie;
namespace Generated = ::RawrXD::Deep2::Generated;
// NOTE: deliberately not aliasing RawrXD::Deep2 to a bare `Deep2` - callers of
// this header (RawrXDCore.h / Deep2::GGUFLoader) already use that name.

namespace MG = ModelGenie;
namespace GEN = Generated;


struct TensorView
{
    Generated::TensorId id;
    const uint8_t* data;
    uint64_t bytes;
    uint64_t elementCount;
    uint32_t rank;
    const uint32_t* dims;
    const char* name;
    ModelGenie::GGMLType type;
};

class GGUFROM
{
public:
    const uint8_t* base = nullptr;
    uint64_t size = 0;
    uint64_t ggufDataOffset = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = INVALID_HANDLE_VALUE;

    struct LiveTensorInfo {
        std::string name;
        ModelGenie::GGMLType type;
        uint64_t dataOffset;
        uint64_t encodedBytes;
        std::vector<uint64_t> dims;
    };
    std::vector<LiveTensorInfo> liveTensors;

    bool Open(const std::string& path);

    ~GGUFROM() { Close(); }

    void Close()
    {
        if (base) { UnmapViewOfFile(base); base = nullptr; }
        if (hMap) { CloseHandle(hMap); hMap = nullptr; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
    }

private:
    bool ParseGGUFHeader();
};

float FP16ToFloat(uint16_t h);
void DequantizeTensor(const TensorView& tv, std::vector<float>& out);

class MlaKVCache
{
public:
    struct LayerCache {
        std::vector<float> kv_latent;    // [max_seq_len, kKvLoraRank]
        std::vector<float> k_rope_raw;   // [max_seq_len, kRopeDimensionCount]
        size_t max_seq_len = 0;
        size_t current_len = 0;

        void Init(size_t max_seq_len_)
        {
            max_seq_len = max_seq_len_;
            kv_latent.assign(max_seq_len_ * GEN::ModelConfig::kKvLoraRank, 0.0f);
            k_rope_raw.assign(max_seq_len_ * GEN::ModelConfig::kRopeDimensionCount, 0.0f);
            current_len = 0;
        }
        bool WriteLatentKv(const float* kv_latent_in, const float* k_rope_raw_in)
        {
            if (current_len >= max_seq_len) return false;
            float* latent_dst = kv_latent.data() + current_len * GEN::ModelConfig::kKvLoraRank;
            float* rope_dst = k_rope_raw.data() + current_len * GEN::ModelConfig::kRopeDimensionCount;
            std::memcpy(latent_dst, kv_latent_in, GEN::ModelConfig::kKvLoraRank * sizeof(float));
            std::memcpy(rope_dst, k_rope_raw_in, GEN::ModelConfig::kRopeDimensionCount * sizeof(float));
            current_len++;
            return true;
        }
        const float* ReadKvLatent(size_t pos) const
        {
            if (pos >= current_len) return nullptr;
            return kv_latent.data() + pos * GEN::ModelConfig::kKvLoraRank;
        }
        const float* ReadKRopeRaw(size_t pos) const
        {
            if (pos >= current_len) return nullptr;
            return k_rope_raw.data() + pos * GEN::ModelConfig::kRopeDimensionCount;
        }
        const float* ReadAllKvLatent() const { return kv_latent.data(); }
        const float* ReadAllKRopeRaw() const { return k_rope_raw.data(); }
        size_t Size() const { return current_len; }
        void Reset() { current_len = 0; }
    };

    std::array<LayerCache, GEN::ModelConfig::kBlockCount> layers;
    size_t max_seq_len = 0;

    void Init(size_t max_seq_len_)
    {
        max_seq_len = max_seq_len_;
        for (auto& layer : layers) layer.Init(max_seq_len_);
    }
    void Reset()
    {
        for (auto& layer : layers) layer.Reset();
    }
    size_t CurrentLen() const { return layers[0].Size(); }
};

class ActivationArena
{
public:
    std::unordered_map<uint32_t, std::vector<float>> activations;

    float* GetOrCreate(uint32_t activationId, size_t elementCount)
    {
        auto it = activations.find(activationId);
        if (it == activations.end()) {
            auto result = activations.emplace(activationId, std::vector<float>(elementCount));
            return result.first->second.data();
        }
        if (it->second.size() != elementCount) {
            it->second.resize(elementCount);
        }
        return it->second.data();
    }
    float* Allocate(uint32_t id, size_t count)
    {
        auto it = activations.find(id);
        if (it == activations.end()) return nullptr;
        return it->second.data();
    }
    size_t Size(uint32_t activationId) const
    {
        auto it = activations.find(activationId);
        return it == activations.end() ? 0u : it->second.size();
    }
    const float* Get(uint32_t activationId) const
    {
        auto it = activations.find(activationId);
        if (it == activations.end()) return nullptr;
        return it->second.data();
    }
    void Clear() { activations.clear(); }
};

class ROMResolver
{
public:
    explicit ROMResolver(const std::string& ggufPath)
    {
        if (!romFile_.Open(ggufPath))
        {
            std::fprintf(stderr, "[IR] Failed to open GGUF: %s\n", ggufPath.c_str());
        }
    }

    const TensorView* Resolve(uint32_t id) const
    {
        if (!romFile_.base || id >= GEN::ModelConfig::kTensorCount) return nullptr;
        const auto& rom = GEN::kTensorROMTable[id];
        if (rom.tensorId >= romFile_.liveTensors.size()) return nullptr;
        const auto& live = romFile_.liveTensors[rom.tensorId];
        if (live.name != rom.name || live.type != rom.type ||
            live.dataOffset != rom.dataOffset || live.encodedBytes != rom.encodedBytes ||
            live.dims.size() != rom.rank) return nullptr;
        for (size_t d = 0; d < live.dims.size(); ++d)
            if (live.dims[d] != rom.dims[d]) return nullptr;
        if (live.dataOffset > romFile_.size - romFile_.ggufDataOffset) return nullptr;
        const uint64_t start = romFile_.ggufDataOffset + live.dataOffset;
        if (start > romFile_.size || live.encodedBytes > romFile_.size - start) return nullptr;
        auto& view = views_[id];
        view.id = static_cast<GEN::TensorId>(rom.tensorId);
        view.data = romFile_.base + start;
        view.bytes = live.encodedBytes;
        view.type = live.type;
        view.dims = rom.dims.data(); // lifetime is the immutable generated table
        view.rank = rom.rank;
        view.elementCount = rom.elementCount;
        view.name = rom.name;
        return &view;
    }

    bool GetExpertSlice(uint32_t id, uint32_t expert, std::vector<float>& out) const
    {
        const TensorView* v = Resolve(id);
        if (!v || v->rank != 3 || expert >= v->dims[2] ||
            !v->dims[2] || v->bytes % v->dims[2] ||
            v->elementCount % v->dims[2]) return false;
        const uint64_t bytesPerExpert = v->bytes / v->dims[2];
        const uint64_t elementsPerExpert = v->elementCount / v->dims[2];
        const uint32_t shape[2] = {v->dims[0], v->dims[1]};
        if (elementsPerExpert != uint64_t(shape[0]) * shape[1]) return false;
        TensorView slice = *v;
        slice.data += bytesPerExpert * expert;
        slice.bytes = bytesPerExpert;
        slice.elementCount = elementsPerExpert;
        slice.dims = shape;
        slice.rank = 2;
        DequantizeTensor(slice, out);
        return out.size() == elementsPerExpert;
    }

    const float* GetDequantizedWeight(uint32_t romTensorId) const
    {
        auto it = dequantCache_.find(romTensorId);
        if (it != dequantCache_.end()) {
            return it->second.data();
        }
        const TensorView* view = Resolve(romTensorId);
        if (!view || !view->data) return nullptr;
        if (view->type == ModelGenie::GGMLType::F32) {
            return reinterpret_cast<const float*>(view->data);
        }
        std::vector<float> dequantized;
        DequantizeTensor(*view, dequantized);
        auto result = dequantCache_.emplace(romTensorId, std::move(dequantized));
        return result.first->second.data();
    }

    bool IsValid() const { return romFile_.base != nullptr; }

private:
    GGUFROM romFile_;
    mutable std::array<TensorView, GEN::ModelConfig::kTensorCount> views_{};
    mutable std::unordered_map<uint32_t, std::vector<float>> dequantCache_;
};

//=============================================================================
// Differential Execution Verifier - Activation Capture
//=============================================================================
struct ActivationRecord {
    std::string op_name;
    uint32_t op_id;
    uint32_t layer_idx;
    size_t position;
    std::vector<int64_t> shape;
    std::vector<float> data;
    std::string tensor_type; // "input", "output", "weight", "intermediate"
};

class DifferentialRecorder {
public:
    std::vector<ActivationRecord> records;
    bool enabled = false;
    std::string output_dir;
    size_t capture_position = (std::numeric_limits<size_t>::max)();
    bool ShouldRecord(size_t pos) const {
        return enabled && (capture_position == (std::numeric_limits<size_t>::max)() || capture_position == pos);
    }
    
    void Enable(const std::string& dir) {
        enabled = true;
        output_dir = dir;
        records.clear();
    }
    
    void Disable() {
        enabled = false;
    }
    
    void Record(const std::string& op_name, uint32_t op_id, uint32_t layer_idx, 
                size_t position, const std::string& tensor_type,
                const float* data, const std::vector<int64_t>& shape) {
        if (!ShouldRecord(position) || !data || shape.empty()) return;
        
        ActivationRecord rec;
        rec.op_name = op_name;
        rec.op_id = op_id;
        rec.layer_idx = layer_idx;
        rec.position = position;
        rec.shape = shape;
        rec.tensor_type = tensor_type;
        
        // Calculate total elements from shape
        size_t total = 1;
        for (int64_t d : shape) {
            if (d <= 0 || static_cast<uint64_t>(d) > 200000u / total) {
                std::fprintf(stderr, "[DIFF] Invalid or oversized tensor: %s\n", op_name.c_str());
                return;
            }
            total *= static_cast<size_t>(d);
        }
        
        // Safety check: limit tensor size to prevent memory issues
        if (total > 200000) {
            std::fprintf(stderr, "[DIFF] SKIP large tensor: %s (size=%zu)\n", op_name.c_str(), total);
            return;
        }
        
        if (data) {
            rec.data.assign(data, data + total);
        }
        records.push_back(std::move(rec));
    }
    
    void SaveAll() {
        if (!enabled) return;
        
        // Create output directory
        DWORD result = CreateDirectoryA(output_dir.c_str(), NULL);
        if (result == 0 && GetLastError() != ERROR_ALREADY_EXISTS) {
            std::fprintf(stderr, "[DIFF] Failed to create directory: %s (error %lu)\n", 
                         output_dir.c_str(), GetLastError());
        }
        
        // Save as binary files
        for (size_t record_index = 0; record_index < records.size(); ++record_index) {
            const auto& rec = records[record_index];
            char fname[1024];
            const int nchars = std::snprintf(fname, sizeof(fname),
                "%s\\rec_%06zu_op%u_%s_l%u_p%zu_%s.bin",
                output_dir.c_str(), record_index, rec.op_id, rec.op_name.c_str(),
                rec.layer_idx, rec.position, rec.tensor_type.c_str());
            if (nchars < 0 || static_cast<size_t>(nchars) >= sizeof(fname)) {
                std::fprintf(stderr, "[DIFF] Record output path too long\n");
                continue;
            }
            
            // Save header + data
            std::ofstream f(fname, std::ios::binary);
            if (!f) {
                std::fprintf(stderr, "[DIFF] Failed to open file: %s\n", fname);
                continue;
            }
            
            // Write metadata
            const uint32_t op_id = rec.op_id;
            uint32_t ndim = static_cast<uint32_t>(rec.shape.size());
            
            f.write(reinterpret_cast<const char*>(&op_id), sizeof(op_id));
            f.write(reinterpret_cast<const char*>(&rec.layer_idx), sizeof(rec.layer_idx));
            f.write(reinterpret_cast<const char*>(&rec.position), sizeof(rec.position));
            f.write(reinterpret_cast<const char*>(&ndim), sizeof(ndim));
            for (int64_t d : rec.shape) {
                f.write(reinterpret_cast<const char*>(&d), sizeof(d));
            }
            uint64_t data_size = rec.data.size();
            f.write(reinterpret_cast<const char*>(&data_size), sizeof(data_size));
            f.write(reinterpret_cast<const char*>(rec.data.data()), rec.data.size() * sizeof(float));
            f.close();
        }
        
        // Also save a manifest
        std::ofstream manifest(output_dir + "\\manifest.json");
        manifest << "[\n";
        for (size_t i = 0; i < records.size(); ++i) {
            const auto& r = records[i];
            manifest << "  {\n";
            manifest << "    \"index\": " << i << ",\n";
            manifest << "    \"op_name\": \"" << r.op_name << "\",\n";
            manifest << "    \"op_id\": " << r.op_id << ",\n";
            manifest << "    \"layer_idx\": " << r.layer_idx << ",\n";
            manifest << "    \"position\": " << r.position << ",\n";
            manifest << "    \"tensor_type\": \"" << r.tensor_type << "\",\n";
            manifest << "    \"shape\": [";
            for (size_t j = 0; j < r.shape.size(); ++j) {
                manifest << r.shape[j] << (j + 1 < r.shape.size() ? ", " : "");
            }
            manifest << "],\n";
            manifest << "    \"num_elements\": " << r.data.size() << "\n";
            manifest << "  }" << (i + 1 < records.size() ? "," : "") << "\n";
        }
        manifest << "]\n";
        manifest.close();
        
        std::fprintf(stderr, "[DIFF] Saved %zu records to %s\n", records.size(), output_dir.c_str());
    }
    
    void Clear() {
        records.clear();
    }
};

// Process-wide differential recorder. Disabled by default; enabled only by the
// standalone verification harness (tools/rawrxd_modelgenie_ir_executor.cpp).
extern DifferentialRecorder g_differential_recorder;

#define DIFF_RECORD(op_name, op_id, layer_idx, position, tensor_type, data, shape) \
    do { if (g_differential_recorder.enabled) \
        g_differential_recorder.Record(op_name, op_id, layer_idx, position, tensor_type, data, shape); \
    } while(0)

#define DIFF_ENABLE(dir) do { g_differential_recorder.Enable(dir); } while(0)
#define DIFF_DISABLE() do { g_differential_recorder.Disable(); } while(0)
#define DIFF_SAVE() do { g_differential_recorder.SaveAll(); } while(0)
#define DIFF_CLEAR() do { g_differential_recorder.Clear(); } while(0)

//=============================================================================
// IRExecutor - walks GEN::kExecutionIRTable as the authoritative graph.
// One instance owns one model load, one KV cache, and one decoder position.
//=============================================================================
class IRExecutor
{
public:
    MlaKVCache kvCache_;
    size_t position_ = 0;

    IRExecutor(const std::string& ggufPath, uint32_t tokenId);

    bool Execute();
    uint32_t SampleToken() const;

    const std::vector<float>* GetLogits() const { return logits_.empty() ? nullptr : &logits_; }
    uint32_t Visited() const { return visited_; }
    uint32_t Dispatched() const { return dispatched_; }
    uint32_t Skipped() const { return skipped_; }

    void AdvancePosition() { position_++; }
    void ResetPosition() { position_ = 0; kvCache_.Reset(); arena_.Clear(); }
    size_t Position() const { return position_; }
    MlaKVCache* GetKVCache() { return &kvCache_; }
    void SetTokenId(uint32_t tokenId) { tokenId_ = tokenId; tokenStorage_ = static_cast<float>(tokenId); }
    void ClearArena() { arena_.Clear(); }

    // Prefill a token sequence at positions 0..n-1, keeping KV state persistent.
    bool Prefill(const std::vector<uint32_t>& tokens);

    // Autoregressive decode. When prompt is non-empty it is prefillled first.
    // Sampling is greedy over the IR-declared LM-head output activation.
    std::vector<uint32_t> Generate(const std::vector<uint32_t>& prompt, uint32_t maxTokens);

    // Returns the number of logits held by the last Execute(), for validation.
    size_t LogitCount() const { return logits_.size(); }

private:
    ROMResolver romResolver_;
    ActivationArena arena_;
    uint32_t tokenId_;
    float tokenStorage_ = 0.0f;
    std::vector<float> logits_;
    uint32_t visited_ = 0, dispatched_ = 0, skipped_ = 0;
};


#endif // MODELGENIE_EXECUTOR_HPP
