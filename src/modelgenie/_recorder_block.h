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

// Global differential recorder
static DifferentialRecorder g_differential_recorder;

#define DIFF_RECORD(op_name, op_id, layer_idx, position, tensor_type, data, shape) \
    do { if (g_differential_recorder.enabled) \
        g_differential_recorder.Record(op_name, op_id, layer_idx, position, tensor_type, data, shape); \
    } while(0)

#define DIFF_ENABLE(dir) do { g_differential_recorder.Enable(dir); } while(0)
#define DIFF_DISABLE() do { g_differential_recorder.Disable(); } while(0)