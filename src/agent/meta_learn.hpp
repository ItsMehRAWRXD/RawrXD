#pragma once
#include <string>
#include <vector>
<<<<<<< HEAD
#include <unordered_map>
#include <cstdint>
=======
#include <map>
#include <functional>
#include <cstdint>
#include <nlohmann/json.hpp>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

struct PerfRecord {
    std::string quant;
    std::string kernel;
    std::string gpu;
    std::string hardware;
<<<<<<< HEAD
    double tps = 0.0;
    double ppl = 0.0;
    int64_t timestamp = 0;
};

/// Callback typedefs (function pointers, not std::function)
typedef void (*OnRecordAddedCb)(const PerfRecord& rec);
typedef void (*OnSuggestionCb)(const char* suggestion);

class MetaLearn {
public:
    MetaLearn();
    bool record(const std::string& quant, const std::string& kernel, const std::string& gpu, double tps, double ppl);
    bool autoTuneQuant();
    bool autoTuneKernel();
    std::string suggestQuant() const;
    std::string suggestKernel() const;
    std::vector<PerfRecord> getHistory(const std::string& quant = "") const;
=======
    double tps;      // tokens per second
    double ppl;      // perplexity
    int64_t timestamp;
};

class MetaLearn {
public:
    explicit MetaLearn();
    
    virtual ~MetaLearn() = default;

    // Record performance metrics to database
    bool record(const std::string& quant,
                const std::string& kernel,
                const std::string& gpu,
                double tps,
                double ppl);
    
    // Auto-apply the best quantization/kernel for this machine
    bool autoTuneQuant();
    bool autoTuneKernel();
    
    // Suggestions without side effects
    std::string suggestQuant() const;
    std::string suggestKernel() const;
    
    // Get performance history
    std::vector<PerfRecord> getHistory(const std::string& quant = "") const;
    
    // Load database from disk
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    bool loadDatabase();
    bool saveDatabase() const;
    std::string gpuHash() const;

<<<<<<< HEAD
    /// Load perf_db.json and return parsed records (no nlohmann dependency)
    static std::vector<PerfRecord> loadDB(bool* ok = nullptr);

    // Callbacks (function pointers per project convention)
    OnRecordAddedCb onRecordAdded = nullptr;
    OnSuggestionCb onSuggestionReady = nullptr;
    OnSuggestionCb onKernelSuggestionReady = nullptr;

private:
    std::string resolveGpuLabel(const std::string& explicitGpu) const;
    bool computeQuantSuggestion(std::string* bestQuant, double* avgTps, double* avgPpl) const;
    bool computeKernelSuggestion(std::string* bestKernel, double* avgTps) const;
=======
    // Hardware fingerprint helper
    std::string gpuHash() const;

    // Lightweight static helper for callers needing raw records
    static nlohmann::json loadDB(bool* ok = nullptr);
    
    // Callbacks (replacing signals)
    std::function<void(const PerfRecord&)> onRecordAdded;
    std::function<void(const std::string&)> onSuggestionReady;
    std::function<void(const std::string&)> onKernelSuggestionReady;
    
private:
    std::string resolveGpuLabel(const std::string& explicitGpu) const;
    bool computeQuantSuggestion(std::string* bestQuant,
                                double* avgTps,
                                double* avgPpl) const;
    bool computeKernelSuggestion(std::string* bestKernel,
                                 double* avgTps) const;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string hardwareKey() const;
    std::vector<PerfRecord> m_records;
    std::string m_dbPath;
    std::string m_lastQuantSuggestion;
    std::string m_lastKernelSuggestion;
};
