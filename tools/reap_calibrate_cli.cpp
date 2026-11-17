// ============================================================================
// reap_calibrate_cli.cpp -- Expert importance calibration via inference observation.
// Runs the model on calibration prompts and records per-layer expert routing
// statistics via the existing ReapRouteTracker/ReapActivationAccumulator.
// Output: one expert ID per line (ranked by importance) per layer file.
// Format consumed by RawrXD::Reap::TryLoadCalibrationRanks.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <filesystem>
#include <iomanip>
#include <cmath>
#include <sstream>
#include <array>

// Deep2 inference engine headers
#include "deep2/GGUFLoader.hpp"
#include "deep2/MoERouter.hpp"
#include "deep2/ReapRouteTracker.hpp"
#include "Deep2Engine.h"
#include "ChatTemplate.hpp"

using namespace std;
using namespace Deep2;

namespace fs = std::filesystem;

// ---- Self-contained SHA-256 implementation ----
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t ROTR(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t SIGMA0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

static inline uint32_t SIGMA1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

static inline uint32_t sigma0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

static inline uint32_t sigma1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

static string computeFileSha256(const string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return "";

    uint64_t expectedBytes = 0;
    std::error_code sizeEc;
    const auto fileSize = fs::file_size(path, sizeEc);
    if (!sizeEc) expectedBytes = static_cast<uint64_t>(fileSize);
    uint64_t nextProgress = 1ull << 30;
    auto reportProgress = [&](uint64_t done) {
        if (expectedBytes == 0 || done < nextProgress) return;
        cerr << "[SOURCE_SHA256_PROGRESS] bytes=" << done
             << " total_bytes=" << expectedBytes
             << " percent=" << fixed << setprecision(2)
             << (100.0 * static_cast<double>(done) /
                 static_cast<double>(expectedBytes)) << endl;
        while (nextProgress <= done && nextProgress <= UINT64_MAX - (1ull << 30))
            nextProgress += 1ull << 30;
    };
    
    // Initial hash values
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint64_t totalBytes = 0;
    array<unsigned char, 64> block;
    size_t bytes;
    
    while ((bytes = fread(block.data(), 1, block.size(), f)) > 0) {
        totalBytes += bytes;
        reportProgress(totalBytes);
        
        if (bytes == 64) {
            // Full block - process directly
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (uint32_t(block[i*4]) << 24) | (uint32_t(block[i*4+1]) << 16) | 
                       (uint32_t(block[i*4+2]) << 8) | uint32_t(block[i*4+3]);
            }
            for (int i = 16; i < 64; ++i) {
                w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
            }
            
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];
            
            for (int i = 0; i < 64; ++i) {
                uint32_t t1 = h_val + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
                uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
                h_val = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }
            
            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
        } else {
            // Partial block - need padding
            array<unsigned char, 64> padded = block;
            padded[bytes] = 0x80;
            for (size_t i = bytes + 1; i < 64; ++i) padded[i] = 0;
            
            // If not enough space for length (8 bytes), process this block and add another
            if (bytes >= 56) {
                uint32_t w[64];
                for (int i = 0; i < 16; ++i) {
                    w[i] = (uint32_t(padded[i*4]) << 24) | (uint32_t(padded[i*4+1]) << 16) | 
                           (uint32_t(padded[i*4+2]) << 8) | uint32_t(padded[i*4+3]);
                }
                for (int i = 16; i < 64; ++i) {
                    w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
                }
                
                uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
                uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];
                
                for (int i = 0; i < 64; ++i) {
                    uint32_t t1 = h_val + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
                    uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
                    h_val = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }
                
                h[0] += a; h[1] += b; h[2] += c; h[3] += d;
                h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
                
                // Second block for length
                padded.fill(0);
            }
            
            // Add length in bits at the end
            uint64_t bitLen = totalBytes * 8;
            for (int i = 0; i < 8; ++i) {
                padded[56 + i] = (bitLen >> (56 - i * 8)) & 0xFF;
            }
            
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (uint32_t(padded[i*4]) << 24) | (uint32_t(padded[i*4+1]) << 16) | 
                       (uint32_t(padded[i*4+2]) << 8) | uint32_t(padded[i*4+3]);
            }
            for (int i = 16; i < 64; ++i) {
                w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
            }
            
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];
            
            for (int i = 0; i < 64; ++i) {
                uint32_t t1 = h_val + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
                uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
                h_val = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }
            
            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
        }
    }
    
    fclose(f);
    
    stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << hex << setw(8) << setfill('0') << h[i];
    }
    return ss.str();
}

struct CalibrationConfig {
    string modelPath;
    vector<string> prompts;
    string promptFile;
    int numLayers = 0;
    string outputDir;
    int numSamples = 10;
    bool verbose = false;
    string tokenizerPath;
    float temperature = 0.0f;
    int topK = 1;
    float topP = 1.0f;
    int maxNewTokens = 128;
    bool resume = false;
};

struct ExpertScore {
    int layer;
    int expertId;
    double activationSum = 0.0;
    double weightSum = 0.0;
    uint64_t routeCount = 0;
    uint64_t totalTokens = 0;
    
    // Composite importance score: frequency * avg_weight
    double importanceScore() const {
        if (routeCount == 0) return 0.0;
        double avgWeight = weightSum / routeCount;
        double frequency = static_cast<double>(routeCount) / static_cast<double>(totalTokens > 0 ? totalTokens : 1);
        return frequency * avgWeight;
    }
    
    bool operator<(const ExpertScore& other) const {
        return importanceScore() > other.importanceScore(); // Descending
    }
};

struct CheckpointManifest {
    string schema = "RAWRXD_REAP_CALIBRATION_CHECKPOINT_001";
    string modelPath;
    string modelSha256;
    string configHash;
    uint32_t numLayers = 0;
    uint32_t numExperts = 0;
    uint32_t topK = 0;
    vector<string> prompts;
    vector<string> promptHashes;
    vector<uint64_t> completedTokensPerPrompt;
    uint64_t totalTokens = 0;
    chrono::system_clock::time_point timestamp;
    
    bool write(const fs::path& path) const {
        fs::path tmpPath = path;
        tmpPath += ".tmp";
        ofstream out(tmpPath);
        if (!out) return false;
        
        out << "{\n";
        out << "  \"schema\": \"" << schema << "\",\n";
        out << "  \"model_path\": \"" << escapeJson(modelPath) << "\",\n";
        out << "  \"model_sha256\": \"" << escapeJson(modelSha256) << "\",\n";
        out << "  \"config_hash\": \"" << escapeJson(configHash) << "\",\n";
        out << "  \"num_layers\": " << numLayers << ",\n";
        out << "  \"num_experts\": " << numExperts << ",\n";
        out << "  \"top_k\": " << topK << ",\n";
        out << "  \"prompts\": [\n";
        for (size_t i = 0; i < prompts.size(); ++i) {
            if (i > 0) out << ",\n";
            out << "    {\n";
            out << "      \"prompt\": \"" << escapeJson(prompts[i]) << "\",\n";
            out << "      \"hash\": \"" << promptHashes[i] << "\",\n";
            out << "      \"completed_tokens\": " << (i < completedTokensPerPrompt.size() ? completedTokensPerPrompt[i] : 0) << "\n";
            out << "    }";
        }
        out << "\n  ],\n";
        out << "  \"total_tokens\": " << totalTokens << ",\n";
        auto t = chrono::system_clock::to_time_t(timestamp);
        out << "  \"timestamp\": " << t << "\n";
        out << "}\n";
        
out.close();
         error_code ec;
         fs::rename(tmpPath, path, ec);
         return !ec;
     }
    
    static bool read(const fs::path& path, CheckpointManifest& out) {
        ifstream in(path);
        if (!in) return false;
        // Simple JSON parsing for our fixed schema
        string line;
        string content;
        while (getline(in, line)) content += line;
        
        // Parse key fields (simplified - in production use nlohmann/json)
        // For now, just validate schema and model path
        if (content.find("\"schema\":\"RAWRXD_REAP_CALIBRATION_CHECKPOINT_001\"") == string::npos &&
            content.find("\"schema\": \"RAWRXD_REAP_CALIBRATION_CHECKPOINT_001\"") == string::npos) {
            return false;
        }
        return true;
    }
    
    static string escapeJson(const string& s) {
        string out;
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c; break;
            }
        }
        return out;
    }
    
    static string hashString(const string& s) {
        // Simple FNV-1a hash
        uint64_t hash = 14695981039346656037ULL;
        for (unsigned char c : s) {
            hash ^= c;
            hash *= 1099511628211ULL;
        }
        stringstream ss;
        ss << hex << hash;
        return ss.str();
    }
};

class CalibrationEngine {
public:
    CalibrationEngine(const CalibrationConfig& config) : config_(config) {}

    void phase(const char* name, const char* event) {
        const auto now = chrono::steady_clock::now();
        const auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - phaseStart_).count();
        cerr << "[CALIBRATION_PHASE] phase=" << name
             << " event=" << event
             << " elapsed_ms=" << elapsed << endl;
        phaseStart_ = now;
    }
    
    bool initialize() {
        phase("OUTPUT_DIRECTORY", "BEGIN");
        // Checkpoints and rank files are part of the calibration contract. Create
        // the destination before the first atomic temp-file write so a missing
        // parent cannot turn successful inference into a calibration failure.
        error_code outputEc;
        fs::create_directories(config_.outputDir, outputEc);
        if (outputEc) {
            cerr << "Failed to create calibration output directory: "
                 << config_.outputDir << ": " << outputEc.message() << endl;
            return false;
        }
        phase("OUTPUT_DIRECTORY", "END");

        // Create and initialize Deep2Engine
        phase("ENGINE_INITIALIZE", "BEGIN");
        engine_ = make_unique<Deep2Engine>();
        
        EngineConfig engineConfig;
        // Set defaults - will be overridden by model metadata during load
        engineConfig.hiddenDim = 4096;
        engineConfig.numLayers = 32;
        engineConfig.numHeads = 32;
        engineConfig.numKVHeads = 32;
        engineConfig.headDim = 128;
        engineConfig.vocabSize = 32000;
        engineConfig.intermediateDim = 11008;
        engineConfig.maxSeqLen = 8192;
        engineConfig.numThreads = 0; // auto
        engineConfig.weightQuant = EngineConfig::FP32;
        engineConfig.kvCacheQuant = EngineConfig::FP32;
        engineConfig.useKVCache = true;
        engineConfig.useThreadPool = true;
        engineConfig.pinThreads = true;
        engineConfig.useRoPE = true;
        engineConfig.ropeTheta = 10000.0f;
        engineConfig.ropeScaling = 1.0f;
        engineConfig.normEps = 1e-6f;
        
        if (!engine_->initialize(engineConfig)) {
            cerr << "Failed to initialize Deep2Engine" << endl;
            return false;
        }
        phase("ENGINE_INITIALIZE", "END");
        
        // Enable REAP calibration observation via environment
        // Deep2Engine checks this when creating MoE routers
        _putenv_s("RAWR_REAP_CALIBRATION", "1");
        
        // Load model - this creates MoE routers with real weights
        if (config_.verbose) {
            cout << "Loading model from: " << config_.modelPath << endl;
        }
        
        phase("MODEL_LOAD_TOKENIZER_INIT", "BEGIN");
        if (!engine_->loadModel(config_.modelPath)) {
            cerr << "Failed to load model" << endl;
            return false;
        }
        phase("MODEL_LOAD_TOKENIZER_INIT", "END");
        
        // Get model info
        const auto& modelWeights = engine_->getModelWeights();
        modelInfo_.numLayers = static_cast<uint32_t>(modelWeights.numLayers);
        modelInfo_.hiddenDim = static_cast<uint32_t>(modelWeights.hiddenDim);
        modelInfo_.numExperts = static_cast<uint32_t>(modelWeights.numExperts);
        modelInfo_.numActiveExperts = static_cast<uint32_t>(modelWeights.numExpertsPerToken);
        modelInfo_.expertDim = static_cast<uint32_t>(modelWeights.moeIntermediateDim);
        
        if (config_.verbose) {
            cout << "Model loaded successfully:" << endl;
            cout << "  Layers: " << modelInfo_.numLayers << endl;
            cout << "  Hidden dim: " << modelInfo_.hiddenDim << endl;
            cout << "  Experts per layer: " << modelInfo_.numExperts << endl;
            cout << "  Active experts (top-k): " << modelInfo_.numActiveExperts << endl;
            cout << "  Expert dim: " << modelInfo_.expertDim << endl;
            cout << "  Is MoE: " << (modelWeights.isMoE ? "yes" : "no") << endl;
        }
        
        if (!modelWeights.isMoE || modelInfo_.numExperts == 0) {
            cerr << "Model is not an MoE model or has no experts" << endl;
            return false;
        }
        
        // Install REAP observer to capture routing statistics
        phase("CALIBRATION_TRACKER_INIT", "BEGIN");
        phase("REAP_OBSERVER_INSTALL", "BEGIN");
        installReapObserver();
        phase("REAP_OBSERVER_INSTALL", "END");
        
        // Compute model SHA-256 for checkpoint validation
        phase("SOURCE_SHA256", "BEGIN");
        modelSha256_ = computeFileSha256(config_.modelPath);
        phase("SOURCE_SHA256", "END");
        if (config_.verbose) {
            cout << "  Model SHA-256: " << modelSha256_ << endl;
        }
        
        // Prepare checkpoint manifest
        checkpointPath_ = fs::path(config_.outputDir) / "calibration_checkpoint.json";
        phase("CALIBRATION_TRACKER_INIT", "END");
        
        return true;
    }
    
    bool runCalibration() {
        // Prepare calibration prompts
        phase("PROMPT_PREPARATION", "BEGIN");
        vector<string> calibrationPrompts = preparePrompts();
        if (calibrationPrompts.empty()) {
            cerr << "No calibration prompts available" << endl;
            return false;
        }
        phase("PROMPT_PREPARATION", "END");
        
        // Compute config hash for checkpoint validation
        configHash_ = computeConfigHash(calibrationPrompts);
        
        // Compute prompt hashes
        vector<string> promptHashes;
        for (const auto& p : calibrationPrompts) {
            promptHashes.push_back(CheckpointManifest::hashString(p));
        }
        
        // Handle resume: load checkpoint and validate
        size_t startPrompt = 0;
        if (config_.resume) {
            startPrompt = loadCheckpoint(promptHashes);
            if (startPrompt >= calibrationPrompts.size()) {
                cout << "Calibration already complete (all prompts processed)" << endl;
                return writeFinalOutput();
            }
        }
        
        if (config_.verbose) {
            cout << "Running calibration on " << calibrationPrompts.size() << " prompts" << endl;
            cout << "Model has " << modelInfo_.numLayers << " MoE layers" << endl;
            if (startPrompt > 0) {
                cout << "Resuming from prompt " << (startPrompt + 1) << endl;
            }
        }
        
        // Configure generation options
        GenerationOptions genOptions;
        genOptions.maxTokens = config_.maxNewTokens;
        genOptions.temperature = config_.temperature;
        genOptions.topP = config_.topP;
        genOptions.topK = config_.topK;
        genOptions.repeatPenalty = 1.0f;
        genOptions.minP = 0.0f;
        genOptions.seed = 0xDEADBEEF;
        
        // Run inference on each prompt and collect routing statistics
        vector<uint64_t> completedTokensPerPrompt(calibrationPrompts.size(), 0);
        
        for (size_t i = startPrompt; i < calibrationPrompts.size(); ++i) {
            const string& prompt = calibrationPrompts[i];
            if (config_.verbose) {
                cout << "  Prompt " << (i + 1) << "/" << calibrationPrompts.size() 
                     << ": " << prompt.substr(0, min<size_t>(80, prompt.size())) << "..." << endl;
            }
            
            uint64_t tokensBefore = accumulator_.tokenCount();
            phase("INFERENCE_CONTEXT_READY", "BEGIN");
            if (!runInferenceOnPrompt(prompt, genOptions)) {
                cerr << "Failed to run inference on prompt " << i << endl;
                return false;
            }
            phase("GENERATION_PROMPT", "END");
            
            uint64_t tokensAfter = accumulator_.tokenCount();
            completedTokensPerPrompt[i] = tokensAfter - tokensBefore;
            
            // Write checkpoint after each prompt
            if (!writeCheckpoint(calibrationPrompts, promptHashes, completedTokensPerPrompt, i)) {
                cerr << "Failed to write checkpoint after prompt " << i << endl;
                return false;
            }
            
            if (config_.verbose) {
                cout << "    Generated " << completedTokensPerPrompt[i] << " tokens (total: " << tokensAfter << ")" << endl;
            }
        }
        
        // Final output
        return writeFinalOutput();
    }
    
private:
    CalibrationConfig config_;
    unique_ptr<Deep2Engine> engine_;
    chrono::steady_clock::time_point phaseStart_ = chrono::steady_clock::now();
    
    // Model metadata
    struct ModelInfo {
        uint32_t numLayers = 0;
        uint32_t numExperts = 0;
        uint32_t numActiveExperts = 8; // top-k
        uint32_t hiddenDim = 0;
        uint32_t expertDim = 0;
    } modelInfo_;
    
    // Reap activation accumulator
    ReapActivationAccumulator accumulator_;
    
    // Checkpoint state
    string modelSha256_;
    string configHash_;
    fs::path checkpointPath_;
    fs::path outputDir_;
    
    void installReapObserver() {
        ReapRouteTracker::Instance().Install(
            [this](size_t layer, const vector<float>& probabilities,
                   const vector<int>& expertIds, const vector<float>& weights) {
                accumulator_.Observe(layer, probabilities, expertIds, weights);
            }
        );
    }
    
    vector<string> preparePrompts() {
        vector<string> prompts;
        
        // Add explicit prompts
        for (const auto& p : config_.prompts) {
            if (!p.empty()) prompts.push_back(p);
        }
        
        // Load prompts from file
        if (!config_.promptFile.empty()) {
            ifstream in(config_.promptFile);
            if (in) {
                string line;
                while (getline(in, line)) {
                    if (!line.empty() && line[0] != '#') {
                        prompts.push_back(line);
                    }
                }
            }
        }
        
        // Default calibration prompts if none provided
        if (prompts.empty()) {
            prompts = {
                "Write a Python function to calculate the Fibonacci sequence.",
                "Explain the concept of recursion in programming.",
                "What is the difference between a list and a tuple in Python?",
                "Implement a binary search algorithm.",
                "Describe how a hash table works.",
                "Write a C++ class for a simple stack data structure.",
                "Explain the difference between stack and heap memory.",
                "What is polymorphism in object-oriented programming?",
                "Implement a quicksort algorithm in Python.",
                "Describe the Model-View-Controller (MVC) pattern."
            };
        }
        
        // Limit to numSamples
        if (static_cast<int>(prompts.size()) > config_.numSamples) {
            prompts.resize(config_.numSamples);
        }
        
        return prompts;
    }
    
    string computeConfigHash(const vector<string>& prompts) {
        stringstream ss;
        ss << config_.temperature << "|" << config_.topK << "|" << config_.topP 
           << "|" << config_.maxNewTokens << "|" << prompts.size();
        return CheckpointManifest::hashString(ss.str());
    }
    
    size_t loadCheckpoint(const vector<string>& promptHashes) {
        if (!fs::exists(checkpointPath_)) {
            if (config_.verbose) cout << "No checkpoint found, starting fresh" << endl;
            return 0;
        }
        
        ifstream in(checkpointPath_);
        if (!in) {
            if (config_.verbose) cout << "Failed to read checkpoint, starting fresh" << endl;
            return 0;
        }
        
        // Read entire file
        string content((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        
        // Validate model SHA-256
        if (content.find(modelSha256_) == string::npos) {
            cerr << "Checkpoint model SHA mismatch, starting fresh" << endl;
            return 0;
        }
        
        // Validate config hash
        if (content.find(configHash_) == string::npos) {
            cerr << "Checkpoint config hash mismatch, starting fresh" << endl;
            return 0;
        }
        
        // Validate prompt hashes match
        bool allMatch = true;
        for (const auto& ph : promptHashes) {
            if (content.find(ph) == string::npos) {
                allMatch = false;
                break;
            }
        }
        if (!allMatch) {
            cerr << "Checkpoint prompt hashes mismatch, starting fresh" << endl;
            return 0;
        }
        
        // Parse completed tokens per prompt (simplified)
        // In production, use proper JSON parsing
        size_t completed = 0;
        // Count prompts that have completed_tokens > 0 in the JSON
        // Simplified: find "completed_tokens" occurrences with non-zero values
        size_t pos = 0;
        while ((pos = content.find("completed_tokens", pos)) != string::npos) {
            pos += 16;
            while (pos < content.size() && isspace(content[pos])) pos++;
            if (pos < content.size() && content[pos] > '0') {
                completed++;
            }
        }
        
        if (config_.verbose) {
            cout << "Checkpoint valid: resuming from prompt " << (completed + 1) << endl;
        }
        
        return completed;
    }
    
    bool writeCheckpoint(const vector<string>& prompts,
                         const vector<string>& promptHashes,
                         const vector<uint64_t>& completedTokensPerPrompt,
                         size_t lastCompleted) {
        CheckpointManifest manifest;
        manifest.modelPath = config_.modelPath;
        manifest.modelSha256 = modelSha256_;
        manifest.configHash = configHash_;
        manifest.numLayers = modelInfo_.numLayers;
        manifest.numExperts = modelInfo_.numExperts;
        manifest.topK = modelInfo_.numActiveExperts;
        manifest.prompts = prompts;
        manifest.promptHashes = promptHashes;
        manifest.completedTokensPerPrompt = completedTokensPerPrompt;
        manifest.totalTokens = accumulator_.tokenCount();
        manifest.timestamp = chrono::system_clock::now();
        
        if (!manifest.write(checkpointPath_)) {
            return false;
        }
        
        // Also write incremental layer files
        return writeLayerFiles();
    }
    
    bool writeLayerFiles() {
        // Get accumulated metrics
        auto metrics = accumulator_.Snapshot();
        uint64_t totalTokens = accumulator_.tokenCount();
        
        // Organize by layer
        map<int, vector<ExpertScore>> layerScores;
        
        for (const auto& [key, metric] : metrics) {
            size_t layer = key.first;
            size_t expert = key.second;
            
            ExpertScore score;
            score.layer = static_cast<int>(layer);
            score.expertId = static_cast<int>(expert);
            score.activationSum = metric.activationSum;
            score.weightSum = metric.weightSum;
            score.routeCount = metric.routeCount;
            score.totalTokens = totalTokens;
            
            layerScores[layer].push_back(score);
        }
        
        // Also include experts that were never routed (score = 0)
        for (uint32_t layer = 0; layer < modelInfo_.numLayers; ++layer) {
            auto& scores = layerScores[layer];
            unordered_set<int> seenExperts;
            for (const auto& s : scores) {
                seenExperts.insert(s.expertId);
            }
            
            // Add missing experts with zero score
            for (int e = 0; e < static_cast<int>(modelInfo_.numExperts); ++e) {
                if (seenExperts.find(e) == seenExperts.end()) {
                    ExpertScore zeroScore;
                    zeroScore.layer = static_cast<int>(layer);
                    zeroScore.expertId = e;
                    zeroScore.totalTokens = totalTokens;
                    scores.push_back(zeroScore);
                }
            }
            
            // Sort by importance (descending)
            sort(scores.begin(), scores.end());
        }
        
        // Write one file per layer (atomic: .tmp then rename)
        bool allSuccess = true;
        for (const auto& [layer, scores] : layerScores) {
            fs::path outFile = fs::path(config_.outputDir) / ("layer_" + to_string(layer) + "_calib.txt");
            fs::path tmpFile = outFile;
            tmpFile += ".tmp";
            
            ofstream out(tmpFile);
            if (!out) {
                cerr << "Failed to open output file: " << tmpFile << endl;
                allSuccess = false;
                continue;
            }
            
            // Write header comment
            out << "# REAP Calibration Ranks for Layer " << layer << "\n";
            out << "# Generated by reap_calibrate_cli\n";
            out << "# Model: " << fs::path(config_.modelPath).filename().string() << "\n";
            out << "# Total tokens: " << totalTokens << "\n";
            out << "# Experts: " << modelInfo_.numExperts << " (top-" << modelInfo_.numActiveExperts << ")\n";
            out << "# Format: expert_id (one per line, ranked by importance)\n";
            out << "#\n";
            
            // Write ranked expert IDs
            for (const auto& score : scores) {
                out << score.expertId << "\n";
            }
            
            out.close();
            
            error_code ec;
            fs::rename(tmpFile, outFile, ec);
            if (ec) {
                cerr << "Failed to rename " << tmpFile << " to " << outFile << ": " << ec.message() << endl;
                allSuccess = false;
            }
            
            if (config_.verbose) {
                cout << "  Wrote " << scores.size() << " experts to " << outFile << endl;
            }
        }
        
        return allSuccess;
    }
    
    bool runInferenceOnPrompt(const string& prompt, const GenerationOptions& genOptions) {
        phase("INFERENCE_CONTEXT_READY", "END");
        phase("GENERATION_LOOP", "BEGIN");
        if (config_.verbose) {
            cout << "    Running generateStream..." << endl;
        }
        
        // Use generateStream to run inference and capture routing
        // We don't need the tokens, just the side-effect of routing observation
        GenerationResult result = engine_->generateStream(prompt, genOptions, 
            [](int32_t tokenId, const string& token) -> bool {
                // Just consume tokens, we don't need them for calibration
                return true; // continue generation
            });
        
        if (config_.verbose) {
            cout << "    Generated " << result.generatedTokens << " tokens" << endl;
        }
        
        // A failed native K2/MLA generation can return cancelled=false while
        // producing zero tokens (for example after a non-finite softmax).
        // Treating that as a successful calibration prompt poisons the rank
        // files and advances the checkpoint past an unobserved forward pass.
        if (result.cancelled || result.generatedTokens == 0) {
            cerr << "Calibration inference produced no valid tokens" << endl;
            return false;
        }
        return true;
    }
    
    bool writeFinalOutput() {
        if (config_.verbose) {
            cout << "Writing final calibration output..." << endl;
        }
        
        // Write layer files
        if (!writeLayerFiles()) {
            return false;
        }
        
        // Write final manifest
        fs::path manifestFile = fs::path(config_.outputDir) / "calibration_manifest.json";
        fs::path tmpManifest = manifestFile;
        tmpManifest += ".tmp";
        
        ofstream manifest(tmpManifest);
        if (!manifest) {
            cerr << "Failed to open manifest file: " << tmpManifest << endl;
            return false;
        }
        
        // Get accumulated metrics
        auto metrics = accumulator_.Snapshot();
        uint64_t totalTokens = accumulator_.tokenCount();
        
        // Organize by layer
        map<int, vector<ExpertScore>> layerScores;
        
        for (const auto& [key, metric] : metrics) {
            size_t layer = key.first;
            size_t expert = key.second;
            
            ExpertScore score;
            score.layer = static_cast<int>(layer);
            score.expertId = static_cast<int>(expert);
            score.activationSum = metric.activationSum;
            score.weightSum = metric.weightSum;
            score.routeCount = metric.routeCount;
            score.totalTokens = totalTokens;
            
            layerScores[layer].push_back(score);
        }
        
        // Also include experts that were never routed (score = 0)
        for (uint32_t layer = 0; layer < modelInfo_.numLayers; ++layer) {
            auto& scores = layerScores[layer];
            unordered_set<int> seenExperts;
            for (const auto& s : scores) {
                seenExperts.insert(s.expertId);
            }
            
            for (int e = 0; e < static_cast<int>(modelInfo_.numExperts); ++e) {
                if (seenExperts.find(e) == seenExperts.end()) {
                    ExpertScore zeroScore;
                    zeroScore.layer = static_cast<int>(layer);
                    zeroScore.expertId = e;
                    zeroScore.totalTokens = totalTokens;
                    scores.push_back(zeroScore);
                }
            }
            
            sort(scores.begin(), scores.end());
        }
        
        // JSON manifest with detailed scores
        manifest << "{\n";
        manifest << "  \"schema\": \"RAWRXD_REAP_CALIBRATION_001\",\n";
        manifest << "  \"model\": \"" << fs::path(config_.modelPath).filename().string() << "\",\n";
        manifest << "  \"model_sha256\": \"" << modelSha256_ << "\",\n";
        manifest << "  \"total_tokens\": " << totalTokens << ",\n";
        manifest << "  \"num_layers\": " << modelInfo_.numLayers << ",\n";
        manifest << "  \"num_experts\": " << modelInfo_.numExperts << ",\n";
        manifest << "  \"top_k\": " << modelInfo_.numActiveExperts << ",\n";
        manifest << "  \"layers\": [\n";
        
        bool firstLayer = true;
        for (const auto& [layer, scores] : layerScores) {
            if (!firstLayer) manifest << ",\n";
            firstLayer = false;
            
            manifest << "    {\n";
            manifest << "      \"layer\": " << layer << ",\n";
            manifest << "      \"experts\": [\n";
            
            bool firstExpert = true;
            for (const auto& score : scores) {
                if (!firstExpert) manifest << ",\n";
                firstExpert = false;
                
                manifest << "        {\n";
                manifest << "          \"expert_id\": " << score.expertId << ",\n";
                manifest << "          \"route_count\": " << score.routeCount << ",\n";
                manifest << "          \"activation_sum\": " << score.activationSum << ",\n";
                manifest << "          \"weight_sum\": " << score.weightSum << ",\n";
                manifest << "          \"importance_score\": " << score.importanceScore() << "\n";
                manifest << "        }";
            }
            
            manifest << "\n      ]\n";
            manifest << "    }";
        }
        
        manifest << "\n  ]\n";
        manifest << "}\n";
        
        manifest.close();
        
        error_code ec;
        fs::rename(tmpManifest, manifestFile, ec);
        if (ec) {
            cerr << "Failed to rename manifest: " << ec.message() << endl;
            return false;
        }
        
        if (config_.verbose) {
            cout << "Wrote manifest to " << manifestFile << endl;
        }
        
        return true;
    }
};

static void printUsage(const char* progName) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Required:\n"
        "  --model <path>           Path to GGUF model (first shard)\n"
        "  --output <dir>           Output directory for calibration files\n"
        "\n"
        "Optional:\n"
        "  --prompt <text>          Calibration prompt (can be repeated)\n"
        "  --prompt-file <path>     File with calibration prompts (one per line)\n"
        "  --layers <N>             Number of layers to calibrate (0 = all)\n"
        "  --samples <N>            Number of calibration samples (default: 10)\n"
        "  --tokenizer <path>       Path to tokenizer.json/model (default: auto-detect)\n"
        "  --temperature <f>        Sampling temperature (default: 0.0)\n"
        "  --top-k <N>              Top-k sampling (default: 1)\n"
        "  --top-p <f>              Top-p sampling (default: 1.0)\n"
        "  --max-tokens <N>         Max new tokens per prompt (default: 128)\n"
        "  --verbose                Verbose output\n"
        "  --resume                 Resume from checkpoint\n"
        "  --help                   Show this help\n"
        "\n"
        "Output:\n"
        "  Creates layer_N_calib.txt files in output directory, one per MoE layer.\n"
        "  Each file contains expert IDs ranked by importance (one per line).\n"
        "  Format consumed by RawrXD::Reap::TryLoadCalibrationRanks.\n"
        "  Checkpoint file: calibration_checkpoint.json enables --resume.\n"
        "\n"
        "Example:\n"
        "  %s --model qwen3-next-80b-00001-of-00004.gguf --output calib_out \\\n"
        "       --prompt \"Write a Python function...\" --prompt \"Explain recursion...\" \\\n"
        "       --samples 20 --verbose\n",
        progName, progName);
}

int main(int argc, char** argv) {
    CalibrationConfig config;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "--model" && i + 1 < argc) {
            config.modelPath = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            config.outputDir = argv[++i];
        } else if (arg == "--prompt" && i + 1 < argc) {
            config.prompts.push_back(argv[++i]);
        } else if (arg == "--prompt-file" && i + 1 < argc) {
            config.promptFile = argv[++i];
        } else if (arg == "--layers" && i + 1 < argc) {
            config.numLayers = stoi(argv[++i]);
        } else if (arg == "--samples" && i + 1 < argc) {
            config.numSamples = stoi(argv[++i]);
        } else if (arg == "--tokenizer" && i + 1 < argc) {
            config.tokenizerPath = argv[++i];
        } else if (arg == "--temperature" && i + 1 < argc) {
            config.temperature = stof(argv[++i]);
        } else if (arg == "--top-k" && i + 1 < argc) {
            config.topK = stoi(argv[++i]);
        } else if (arg == "--top-p" && i + 1 < argc) {
            config.topP = stof(argv[++i]);
        } else if (arg == "--max-tokens" && i + 1 < argc) {
            config.maxNewTokens = stoi(argv[++i]);
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--resume") {
            config.resume = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Validate required arguments
    if (config.modelPath.empty()) {
        fprintf(stderr, "Error: --model is required\n");
        printUsage(argv[0]);
        return 1;
    }
    
    if (config.outputDir.empty()) {
        fprintf(stderr, "Error: --output is required\n");
        printUsage(argv[0]);
        return 1;
    }
    
    if (!fs::exists(config.modelPath)) {
        fprintf(stderr, "Error: Model file not found: %s\n", config.modelPath.c_str());
        return 1;
    }
    
    // Run calibration
    CalibrationEngine engine(config);
    
    if (!engine.initialize()) {
        fprintf(stderr, "Failed to initialize calibration engine\n");
        return 1;
    }
    
    if (!engine.runCalibration()) {
        fprintf(stderr, "Calibration failed\n");
        return 1;
    }
    
    printf("Calibration completed successfully!\n");
    printf("Output directory: %s\n", config.outputDir.c_str());
    
    return 0;
}
