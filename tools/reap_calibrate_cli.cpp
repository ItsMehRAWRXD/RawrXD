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
#include <io.h>
#include <sstream>
#include <array>
#include <tuple>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

// Deep2 inference engine headers
#include "deep2/GGUFLoader.hpp"
#include "deep2/MoERouter.hpp"
#include "deep2/ReapRouteTracker.hpp"
#include "deep2/ReapCapturePolicy.hpp"
#include "deep2/ReapCalibrationState.hpp"
#include "deep2/ReapShardIdentity.hpp"
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
#ifdef _WIN32
    ifstream in(path, ios::binary);
    if (!in) return "";
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hashLen = 0, result = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return "";
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen),
                          &result, 0) != 0 || hashLen == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return "";
    }
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return "";
    }
    vector<unsigned char> buffer(1u << 20);
    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()),
                static_cast<streamsize>(buffer.size()));
        const streamsize n = in.gcount();
        if (n <= 0) break;
        if (BCryptHashData(hash, buffer.data(), static_cast<ULONG>(n), 0) != 0) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return "";
        }
    }
    vector<unsigned char> digest(hashLen);
    const bool ok = in.eof() && !in.bad() && BCryptFinishHash(hash, digest.data(), hashLen, 0) == 0;
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) return "";
    stringstream native;
    native << hex << setfill('0');
    for (unsigned char byte : digest) native << setw(2) << static_cast<unsigned>(byte);
    return native.str();
#else
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return "";
    // The SHA-256 compression function still consumes 64-byte blocks, but
    // reading each block with a separate stdio call makes multi-gigabyte GGUF
    // provenance scans syscall-bound. Keep the hash algorithm unchanged while
    // letting stdio fill a large read buffer underneath it.
    static constexpr size_t kHashReadBufferBytes = 1u << 20;
    if (setvbuf(f, nullptr, _IOFBF, kHashReadBufferBytes) != 0) {
        fclose(f);
        return "";
    }

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
#endif
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
    bool saliencyCapture = false;
    // Reference-observability outputs (optional; P1 CPU reference).
    // Empty paths disable the corresponding capture and leave calibration
    // behaviour byte-identical to the uninstrumented run.
    string dumpTokensPath;
    string dumpLogitsPath;
    // P1-G: weighted accumulated MoE output for one layer (first step).
    string dumpMoePath;
    int dumpMoeLayer = -1;
    // P2-C: routing decision (ids + applied weights) and expert input for one layer.
    string dumpRoutingPath;
    int dumpRoutingLayer = -1;
    // P2-C parity: engine-produced expert outputs (shared + routed) for one layer.
    string dumpExpertOutPath;
    int dumpExpertOutLayer = -1;
};

// ---------------------------------------------------------------------------
// Reference logits observer (P1). Copies each pre-sampling logits buffer
// verbatim as [u64 step][u32 vocab][float x vocab]. Never recomputes logits and
// never mutates the buffer the sampler receives. Empty path => no capture.
// ---------------------------------------------------------------------------
struct RefLogitsSink {
    FILE* fp = nullptr;
    uint64_t steps = 0;
    uint32_t vocab = 0;
    string path;
};

static RefLogitsSink g_refLogits;

static bool RefLogitsObserver(const Deep2Engine::ReferenceObservation& obs, void* user) {
    auto* sink = static_cast<RefLogitsSink*>(user);
    if (!sink || sink->path.empty()) return true;
    if (!sink->fp) {
        sink->fp = std::fopen(sink->path.c_str(), "wb");
        if (!sink->fp) return false;
        sink->vocab = obs.vocabulary_size;
    }
    if (obs.logits_count != obs.vocabulary_size) return false;
    if (fwrite(&obs.generation_step, sizeof(obs.generation_step), 1, sink->fp) != 1) return false;
    if (fwrite(&obs.vocabulary_size, sizeof(obs.vocabulary_size), 1, sink->fp) != 1) return false;
    if (fwrite(obs.logits, sizeof(float), obs.vocabulary_size, sink->fp) != obs.vocabulary_size)
        return false;
    ++sink->steps;
    return true;
}

// ---------------------------------------------------------------------------
// P1-G observer: weighted accumulated MoE output for one layer/step.
// Payload: [u32 layer][u64 step][u32 count][f32 x count].
// ---------------------------------------------------------------------------
struct RefMoeSink {
    FILE* fp = nullptr;
    string path;
    uint32_t layer = 0;
    uint64_t step = 0;
    uint32_t count = 0;
    uint64_t captures = 0;
};

static RefMoeSink g_refMoe;

static bool RefMoeObserver(const Deep2Engine::MoEReferenceObservation& obs, void* user) {
    auto* sink = static_cast<RefMoeSink*>(user);
    if (!sink || sink->path.empty()) return true;
    if (!sink->fp) {
        sink->fp = std::fopen(sink->path.c_str(), "wb");
        if (!sink->fp) return false;
        sink->layer = obs.layer_index;
        sink->step = obs.generation_step;
        sink->count = obs.element_count;
    }
    if (fwrite(&obs.layer_index, sizeof(uint32_t), 1, sink->fp) != 1) return false;
    if (fwrite(&obs.generation_step, sizeof(uint64_t), 1, sink->fp) != 1) return false;
    if (fwrite(&obs.element_count, sizeof(uint32_t), 1, sink->fp) != 1) return false;
    if (fwrite(obs.weighted_moe_output, sizeof(float), obs.element_count, sink->fp)
        != obs.element_count) return false;
    ++sink->captures;
    return true;
}

// ---------------------------------------------------------------------------
// P2-C observer: routing decision actually applied + the expert input.
// Payload: [u32 layer][u64 step][u32 hidden][u32 count]
//          [u32 ids x count][f32 weights x count][f32 input x hidden]
// ---------------------------------------------------------------------------
struct RefRoutingSink {
    FILE* fp = nullptr;
    string path;
    uint32_t layer = 0;
    uint64_t step = 0;
    uint32_t hidden = 0;
    uint32_t count = 0;
    uint64_t captures = 0;
    bool failed = false;
};

static RefRoutingSink g_refRouting;
// Preallocated per-prompt counters for the full paired capture only.
static std::vector<ReapCapture::LayerCounts> g_saliencyLayerCounts;

static bool RefRoutingObserver(const Deep2Engine::MoERoutingObservation& obs, void* user) {
    auto* sink = static_cast<RefRoutingSink*>(user);
    if (!sink || sink->path.empty()) return true;
    if (sink->failed) return false;
    const auto fail = [&]() { sink->failed = true; return false; };
    if (!sink->fp) {
        sink->fp = std::fopen(sink->path.c_str(), "wb");
        if (!sink->fp) return fail();
        sink->layer = obs.layer;
        sink->step = obs.generation_step;
        sink->hidden = obs.hidden_size;
        sink->count = obs.selected_count;
    }
    if (fwrite(&obs.layer, sizeof(uint32_t), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.generation_step, sizeof(uint64_t), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.hidden_size, sizeof(uint32_t), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.selected_count, sizeof(uint32_t), 1, sink->fp) != 1) return fail();
    if (obs.selected_count) {
        if (fwrite(obs.expert_ids, sizeof(uint32_t), obs.selected_count, sink->fp)
            != obs.selected_count) return fail();
        if (fwrite(obs.applied_weights, sizeof(float), obs.selected_count, sink->fp)
            != obs.selected_count) return fail();
    }
    if (fwrite(obs.expert_input, sizeof(float), obs.hidden_size, sink->fp)
        != obs.hidden_size) return fail();
    if (!g_saliencyLayerCounts.empty()) {
        if (obs.layer >= g_saliencyLayerCounts.size()) return fail();
        ++g_saliencyLayerCounts[obs.layer].routes;
    }
    ++sink->captures;
    return true;
}

// ---------------------------------------------------------------------------
// P2-C parity observer: engine-produced expert outputs (shared then routed).
// Records: [u32 layer][u64 step][u32 kind][u32 expert][f32 weight][u32 count]
//          [f32 x count]   kind 0 = shared contribution in the layer output,
//                          kind 1 = routed expert output before weighting.
// ---------------------------------------------------------------------------
struct RefExpertOutSink {
    FILE* fp = nullptr;
    string path;
    uint32_t layer = 0;
    uint64_t step = 0;
    uint64_t records = 0;
    uint64_t shared = 0;
    uint64_t routed = 0;
    bool failed = false;
};

static RefExpertOutSink g_refExpertOut;

static bool RefExpertOutObserver(const Deep2Engine::MoEExpertOutputObservation& obs, void* user) {
    auto* sink = static_cast<RefExpertOutSink*>(user);
    if (!sink || sink->path.empty()) return true;
    if (sink->failed) return false;
    const auto fail = [&]() { sink->failed = true; return false; };
    if (!sink->fp) {
        sink->fp = std::fopen(sink->path.c_str(), "wb");
        if (!sink->fp) return fail();
        sink->layer = obs.layer;
        sink->step = obs.generation_step;
    }
    if (fwrite(&obs.layer, sizeof(uint32_t), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.generation_step, sizeof(uint64_t), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.kind, sizeof(uint32_t), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.expert_id, sizeof(uint32_t), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.applied_weight, sizeof(float), 1, sink->fp) != 1) return fail();
    if (fwrite(&obs.element_count, sizeof(uint32_t), 1, sink->fp) != 1) return fail();
    if (fwrite(obs.output, sizeof(float), obs.element_count, sink->fp)
        != obs.element_count) return fail();
    if (!g_saliencyLayerCounts.empty()) {
        if (obs.layer >= g_saliencyLayerCounts.size() || obs.kind > 1) return fail();
        auto& c = g_saliencyLayerCounts[obs.layer];
        ++c.records;
        if (obs.kind == 0) ++c.shared; else ++c.routed;
    }
    ++sink->records;
    if (obs.kind == 0) ++sink->shared; else ++sink->routed;
    return true;
}

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
        
        if (config_.saliencyCapture) {
            // Same routed-layer predicate as the production transformer path.
            expectedSaliencyLayers_.resize(modelWeights.layers.size(), false);
            for (size_t layer = 0; layer < modelWeights.layers.size(); ++layer) {
                const auto& router = modelWeights.layers[layer].moeRouter;
                expectedSaliencyLayers_[layer] = router.data && router.sizeBytes > 0 &&
                    (config_.dumpRoutingLayer < 0 ||
                     layer == static_cast<size_t>(config_.dumpRoutingLayer));
            }
            if (std::find(expectedSaliencyLayers_.begin(), expectedSaliencyLayers_.end(), true)
                    == expectedSaliencyLayers_.end() ||
                !modelInfo_.numActiveExperts ||
                modelInfo_.numActiveExperts > modelInfo_.numExperts) {
                cerr << "No valid routed source layers or top-k for saliency capture" << endl;
                return false;
            }
            g_saliencyLayerCounts.resize(expectedSaliencyLayers_.size());
        }

        // Install REAP observer to capture routing statistics
        phase("CALIBRATION_TRACKER_INIT", "BEGIN");
        phase("REAP_OBSERVER_INSTALL", "BEGIN");
        installReapObserver();
        phase("REAP_OBSERVER_INSTALL", "END");
        
        // Compute model SHA-256 for checkpoint validation
        phase("SOURCE_SHA256", "BEGIN");
        modelSha256_ = computeFileSha256(config_.modelPath);
        if (modelSha256_.size() != 64) {
            cerr << "Source checkpoint hash failed" << endl;
            return false;
        }
        if (!config_.saliencyCapture && !buildCheckpointIdentity()) {
            cerr << "Cannot establish complete checkpoint identity" << endl;
            return false;
        }
        phase("SOURCE_SHA256", "END");
        if (config_.verbose) {
            cout << "  Model SHA-256: " << modelSha256_ << endl;
        }
        
        // Prepare checkpoint manifest
        checkpointPath_ = fs::path(config_.outputDir) / "calibration_checkpoint.state";
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
        vector<uint64_t> completedTokensPerPrompt(calibrationPrompts.size(), 0);
        const ReapState::Identity stateIdentity{checkpointIdentity_, configHash_,
            modelInfo_.numLayers, modelInfo_.numExperts, modelInfo_.numActiveExperts,
            calibrationPrompts};
        if (config_.resume) {
            if (!loadCheckpoint(stateIdentity, completedTokensPerPrompt, startPrompt)) {
                cerr << "Invalid or missing native checkpoint; use a new output directory to restart" << endl;
                return false;
            }
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
        
        // Run inference on each prompt and collect routing statistics.
        // The progress vector above retains the restored prefix.
        
        if (!config_.dumpLogitsPath.empty()) {
            g_refLogits.path = config_.dumpLogitsPath;
            engine_->SetReferenceObserver(&RefLogitsObserver, &g_refLogits);
        }
        if (!config_.dumpMoePath.empty() && config_.dumpMoeLayer >= 0) {
            g_refMoe.path = config_.dumpMoePath;
            engine_->SetMoEReferenceObserver(&RefMoeObserver, &g_refMoe,
                                             static_cast<uint32_t>(config_.dumpMoeLayer),
                                             0xFFFFFFFFFFFFFFFFull);
        }
        if (!config_.dumpRoutingPath.empty() &&
            (config_.dumpRoutingLayer >= 0 || config_.saliencyCapture)) {
            g_refRouting.path = config_.dumpRoutingPath;
            engine_->SetMoERoutingObserver(&RefRoutingObserver, &g_refRouting,
                                           static_cast<uint32_t>(config_.dumpRoutingLayer),
                                           ReapCapture::AllSteps, config_.saliencyCapture);
        }
        if (!config_.dumpExpertOutPath.empty() &&
            (config_.dumpExpertOutLayer >= 0 || config_.saliencyCapture)) {
            g_refExpertOut.path = config_.dumpExpertOutPath;
            engine_->SetMoEExpertOutputObserver(&RefExpertOutObserver, &g_refExpertOut,
                                                static_cast<uint32_t>(config_.dumpExpertOutLayer),
                                                config_.saliencyCapture ? ReapCapture::AllSteps : 0ull,
                                                config_.saliencyCapture);
        }

        for (size_t i = startPrompt; i < calibrationPrompts.size(); ++i) {
            const string& prompt = calibrationPrompts[i];
            if (config_.verbose) {
                cout << "  Prompt " << (i + 1) << "/" << calibrationPrompts.size() 
                     << ": " << prompt.substr(0, min<size_t>(80, prompt.size())) << "..." << endl;
            }
            
            if (config_.saliencyCapture)
                std::fill(g_saliencyLayerCounts.begin(), g_saliencyLayerCounts.end(),
                          ReapCapture::LayerCounts{});
            uint64_t tokensBefore = accumulator_.tokenCount();
            phase("INFERENCE_CONTEXT_READY", "BEGIN");
            if (!runInferenceOnPrompt(prompt, genOptions)) {
                cerr << "Failed to run inference on prompt " << i << endl;
                return false;
            }
            phase("GENERATION_PROMPT", "END");
            
            uint64_t tokensAfter = accumulator_.tokenCount();
            completedTokensPerPrompt[i] = tokensAfter - tokensBefore;
            
            if (config_.saliencyCapture &&
                (g_refRouting.failed || g_refExpertOut.failed ||
                 (g_refRouting.fp && std::fflush(g_refRouting.fp) != 0) ||
                 (g_refExpertOut.fp && std::fflush(g_refExpertOut.fp) != 0))) {
                cerr << "Saliency capture I/O failed" << endl;
                return false;
            }
            if (config_.saliencyCapture &&
                !ReapCapture::CompleteCoverage(expectedSaliencyLayers_, g_saliencyLayerCounts,
                                                modelInfo_.numActiveExperts)) {
                cerr << "Incomplete per-layer saliency coverage on prompt " << i << endl;
                return false;
            }
            // Paired captures are evidence, not routing-only ranking files.
            if (!config_.saliencyCapture &&
                !writeCheckpoint(stateIdentity, calibrationPrompts, promptHashes,
                                 completedTokensPerPrompt, i)) {
                cerr << "Failed to write checkpoint after prompt " << i << endl;
                return false;
            }
            
            if (config_.verbose) {
                cout << "    Generated " << completedTokensPerPrompt[i] << " tokens (total: " << tokensAfter << ")" << endl;
            }
        }
        
        if (g_refLogits.fp) {
            std::fclose(g_refLogits.fp);
            g_refLogits.fp = nullptr;
            std::string metaPath = config_.dumpLogitsPath + ".meta.json";
            FILE* mf = std::fopen(metaPath.c_str(), "wb");
            if (mf) {
                std::fprintf(mf,
                    "{\"dtype\":\"f32\",\"layout\":\"contiguous\",\"step_prefix\":\"u64\","
                    "\"vocab\":%u,\"steps\":%llu,\"model_sha256\":\"%s\","
                    "\"boundary\":\"pre_sampling_logits\"}\n",
                    g_refLogits.vocab, (unsigned long long)g_refLogits.steps,
                    modelSha256_.c_str());
                std::fclose(mf);
            }
            engine_->SetReferenceObserver(nullptr, nullptr);
            if (config_.verbose) {
                cout << "  Logits dump: " << g_refLogits.steps << " steps, vocab "
                     << g_refLogits.vocab << endl;
            }
        }

        if (g_refMoe.fp) {
            std::fclose(g_refMoe.fp);
            g_refMoe.fp = nullptr;
            std::string mpath = config_.dumpMoePath + ".meta.json";
            FILE* mp = std::fopen(mpath.c_str(), "wb");
            if (mp) {
                std::fprintf(mp,
                    "{\"dtype\":\"f32\",\"layout\":\"contiguous\","
                    "\"prefix\":\"u32_layer,u64_step,u32_count\","
                    "\"boundary\":\"weighted_moe_output_pre_residual\","
                    "\"includes_shared_expert\":true,"
                    "\"layer\":%u,\"generation_step\":%llu,\"element_count\":%u,"
                    "\"captures\":%llu,\"model_sha256\":\"%s\"}\n",
                    g_refMoe.layer, (unsigned long long)g_refMoe.step,
                    g_refMoe.count, (unsigned long long)g_refMoe.captures,
                    modelSha256_.c_str());
                std::fclose(mp);
            }
            engine_->SetMoEReferenceObserver(nullptr, nullptr, 0xFFFFFFFFu,
                                             0xFFFFFFFFFFFFFFFFull);
            if (config_.verbose) {
                cout << "  MoE boundary dump: layer " << g_refMoe.layer
                     << ", step " << g_refMoe.step << ", " << g_refMoe.count
                     << " floats" << endl;
            }
        }

        if (g_refRouting.fp) {
            if (std::fclose(g_refRouting.fp) != 0) g_refRouting.failed = true;
            g_refRouting.fp = nullptr;
            std::string rpath = config_.dumpRoutingPath + ".meta.json";
            FILE* rp = std::fopen(rpath.c_str(), "wb");
            if (rp) {
                std::fprintf(rp,
                    "{\"dtype\":\"mixed\",\"prefix\":\"u32_layer,u64_step,u32_hidden,u32_count,"
                    "u32_ids[],f32_weights[],f32_input[]\","
                    "\"boundary\":\"applied_routing_and_expert_input\","
                    "\"layer\":%u,\"generation_step\":%llu,\"hidden\":%u,"
                    "\"selected_count\":%u,\"captures\":%llu,\"model_sha256\":\"%s\"}\n",
                    g_refRouting.layer, (unsigned long long)g_refRouting.step,
                    g_refRouting.hidden, g_refRouting.count,
                    (unsigned long long)g_refRouting.captures, modelSha256_.c_str());
                std::fclose(rp);
            }
            engine_->SetMoERoutingObserver(nullptr, nullptr, 0xFFFFFFFFu,
                                           0xFFFFFFFFFFFFFFFFull);
            if (config_.verbose) {
                cout << "  Routing dump: layer " << g_refRouting.layer << ", step "
                     << g_refRouting.step << ", " << g_refRouting.count
                     << " experts, hidden " << g_refRouting.hidden << endl;
            }
        }

        if (g_refExpertOut.fp) {
            if (std::fclose(g_refExpertOut.fp) != 0) g_refExpertOut.failed = true;
            g_refExpertOut.fp = nullptr;

            // Keep only the first forward's records so this aligns with the
            // one-shot routing and boundary captures. Records are emitted in
            // order: one shared contribution followed by the routed experts.
            // Preserve all records in the separate saliency capture mode.
            if (!config_.saliencyCapture) {
                FILE* rf = std::fopen(config_.dumpExpertOutPath.c_str(), "rb+");
                if (rf) {
                    uint32_t keptShared = 0, keptRouted = 0;
                    for (;;) {
                        uint32_t layer = 0, kind = 0, expert = 0, count = 0;
                        uint64_t step = 0;
                        float w = 0.0f;
                        if (std::fread(&layer, 4, 1, rf) != 1) break;
                        if (std::fread(&step, 8, 1, rf) != 1) break;
                        if (std::fread(&kind, 4, 1, rf) != 1) break;
                        if (std::fread(&expert, 4, 1, rf) != 1) break;
                        if (std::fread(&w, 4, 1, rf) != 1) break;
                        if (std::fread(&count, 4, 1, rf) != 1) break;
                        if (_fseeki64(rf, static_cast<__int64>(count) * 4, SEEK_CUR) != 0) break;
                        if (kind == 0) ++keptShared; else ++keptRouted;
                        if (keptShared == 1 && keptRouted == modelInfo_.numActiveExperts) {
                            _chsize_s(_fileno(rf), _ftelli64(rf));
                            break;
                        }
                    }
                    std::fclose(rf);
                    g_refExpertOut.shared = keptShared;
                    g_refExpertOut.routed = keptRouted;
                    g_refExpertOut.records = keptShared + keptRouted;
                }
            }

            std::string epath = config_.dumpExpertOutPath + ".meta.json";
            FILE* ep = std::fopen(epath.c_str(), "wb");
            if (ep) {
                std::fprintf(ep,
                    "{\"dtype\":\"f32\",\"prefix\":\"u32_layer,u64_step,u32_kind,u32_expert,"
                    "f32_weight,u32_count,f32_output[]\","
                    "\"kinds\":{\"0\":\"shared_contribution\",\"1\":\"routed_pre_weight\"},"
                    "\"layer\":%u,\"generation_step\":%llu,\"records\":%llu,"
                    "\"shared_records\":%llu,\"routed_records\":%llu,"
                    "\"model_sha256\":\"%s\"}\n",
                    g_refExpertOut.layer, (unsigned long long)g_refExpertOut.step,
                    (unsigned long long)g_refExpertOut.records,
                    (unsigned long long)g_refExpertOut.shared,
                    (unsigned long long)g_refExpertOut.routed,
                    modelSha256_.c_str());
                std::fclose(ep);
            }
            engine_->SetMoEExpertOutputObserver(nullptr, nullptr, 0xFFFFFFFFu,
                                                0xFFFFFFFFFFFFFFFFull);
            if (config_.verbose) {
                cout << "  Expert-output dump: layer " << g_refExpertOut.layer
                     << ", shared=" << g_refExpertOut.shared
                     << ", routed=" << g_refExpertOut.routed << endl;
            }
        }

        if (config_.saliencyCapture) {
            if (g_refRouting.failed || g_refExpertOut.failed || modelSha256_.empty() ||
                !ReapCapture::CompleteCounts(g_refRouting.captures, g_refExpertOut.shared,
                    g_refExpertOut.routed, g_refExpertOut.records, modelInfo_.numActiveExperts)) {
                cerr << "Incomplete paired saliency capture; no completion receipt emitted" << endl;
                return false;
            }
            // First-shard hash is explicitly scoped; full checkpoint provenance
            // and independent scoring must be established before any rewrite.
            const auto receiptPath = fs::path(config_.outputDir) / "saliency_capture_receipt.tsv";
            auto tmpPath = receiptPath;
            tmpPath += ".tmp";
            ofstream receipt(tmpPath, ios::binary | ios::trunc);
            receipt << "route_records\t" << g_refRouting.captures
                    << "\nshared_records\t" << g_refExpertOut.shared
                    << "\nrouted_records\t" << g_refExpertOut.routed
                    << "\nexpert_count\t" << modelInfo_.numExperts
                    << "\ntop_k\t" << modelInfo_.numActiveExperts
                    << "\nfirst_shard_sha256\t" << modelSha256_
                    << "\nlayer_filter\t" << config_.dumpRoutingLayer
                    << "\nrewrite_authorized\t0\n";
            for (size_t layer = 0; layer < expectedSaliencyLayers_.size(); ++layer)
                if (expectedSaliencyLayers_[layer]) receipt << "expected_layer\t" << layer << "\n";
            receipt.close();
            if (!receipt) return false;
            error_code ec;
            fs::rename(tmpPath, receiptPath, ec);
            if (ec) return false;
            cout << "PAIRED_CAPTURE_COUNTS=PASS ROUTE_RECORDS=" << g_refRouting.captures
                 << " REWRITE_AUTHORIZED=0" << endl;
            return true;
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
    std::vector<bool> expectedSaliencyLayers_;
    
    // Checkpoint state
    string modelSha256_;
    string checkpointIdentity_;
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
    
    // Bind the routing-state checkpoint to every canonical GGUF shard.
    // The CLI requires the first shard, matching the existing source hash convention.
    bool buildCheckpointIdentity() {
        vector<fs::path> paths;
        if (!ReapState::ShardPaths(config_.modelPath, paths)) return false;
        checkpointIdentity_ = modelSha256_;
        for (size_t i = 1; i < paths.size(); ++i) {
            const string digest = computeFileSha256(paths[i].string());
            if (digest.size() != 64) return false;
            checkpointIdentity_ += ":" + digest;
        }
        return true;
    }

    string computeConfigHash(const vector<string>& prompts) {
        // Exact configuration identity, not a lossy substring/FNV check.
        stringstream ss;
        ss.imbue(std::locale::classic());
        ss << setprecision(std::numeric_limits<float>::max_digits10)
           << config_.temperature << "|" << config_.topK << "|" << config_.topP
           << "|" << config_.maxNewTokens << "|" << prompts.size()
           << "|seed=3735928559|repeatPenalty=1|minP=0|tokenizer="
           << config_.tokenizerPath;
        return ss.str();
    }

    bool loadCheckpoint(const ReapState::Identity& identity,
                        vector<uint64_t>& completed, size_t& start) {
        ReapState::State state;
        if (!ReapState::Load(checkpointPath_, identity, state)) return false;
        decltype(accumulator_.Snapshot()) metrics;
        for (const auto& m : state.metrics)
            metrics.emplace(std::make_pair(size_t(m.layer),size_t(m.expert)),
                            ReapExpertMetric{m.count,m.activation,m.weight});
        accumulator_.Restore(std::move(metrics), state.observations);
        completed = std::move(state.completed);
        start = 0;
        while (start < completed.size() && completed[start]) ++start;
        return true;
    }

    bool writeCheckpoint(const ReapState::Identity& identity,
                         const vector<string>& prompts,
                         const vector<string>& promptHashes,
                         const vector<uint64_t>& completedTokensPerPrompt,
                         size_t lastCompleted) {
        ReapState::State state;
        state.completed = completedTokensPerPrompt;
        if (lastCompleted >= state.completed.size() || !state.completed[lastCompleted]) return false;
        state.observations = accumulator_.tokenCount();
        for (const auto& entry : accumulator_.Snapshot()) {
            if (entry.first.first >= identity.layers || entry.first.second >= identity.experts)
                return false;
            state.metrics.push_back({static_cast<uint32_t>(entry.first.first),
                static_cast<uint32_t>(entry.first.second),entry.second.routeCount,
                entry.second.activationSum,entry.second.weightSum});
        }
        std::sort(state.metrics.begin(),state.metrics.end(),[](const auto& a,const auto& b) {
            return std::tie(a.layer,a.expert) < std::tie(b.layer,b.expert);
        });
        if (!ReapState::Save(checkpointPath_,identity,state)) return false;

        // Legacy JSON is informational only. Resume uses the complete native state.
        CheckpointManifest manifest;
        manifest.modelPath = config_.modelPath;
        manifest.modelSha256 = modelSha256_;
        manifest.configHash = CheckpointManifest::hashString(configHash_);
        manifest.numLayers = modelInfo_.numLayers;
        manifest.numExperts = modelInfo_.numExperts;
        manifest.topK = modelInfo_.numActiveExperts;
        manifest.prompts = prompts;
        manifest.promptHashes = promptHashes;
        manifest.completedTokensPerPrompt = completedTokensPerPrompt;
        manifest.totalTokens = state.observations;
        manifest.timestamp = chrono::system_clock::now();
        if (!manifest.write(fs::path(config_.outputDir) / "calibration_checkpoint.json"))
            return false;
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
        std::vector<int32_t> emittedTokens;
        GenerationResult result = engine_->generateStream(prompt, genOptions, 
            [&emittedTokens](int32_t tokenId, const string& token) -> bool {
                // Keep ids for the P1 reference. Activation observation is
                // unchanged: ReapRouteTracker still sees the real routing.
                emittedTokens.push_back(tokenId);
                return true; // continue generation
            });
        if (!config_.dumpTokensPath.empty()) {
            FILE* tf = std::fopen(config_.dumpTokensPath.c_str(), "ab");
            if (tf) {
                std::string line;
                line.reserve(emittedTokens.size() * 8 + 16);
                for (size_t k = 0; k < emittedTokens.size(); ++k) {
                    if (k) line.push_back(' ');
                    line += std::to_string(emittedTokens[k]);
                }
                line.push_back('\n');
                std::fwrite(line.data(), 1, line.size(), tf);
                std::fclose(tf);
            }
        }
        
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
        "  --saliency-capture       Record paired routes and expert outputs in a new output directory\n"
        "  --resume                 Resume from checkpoint\n"
        "  --help                   Show this help\n"
        "\n"
        "Output:\n"
        "  Creates layer_N_calib.txt files in output directory, one per MoE layer.\n"
        "  Each file contains expert IDs ranked by importance (one per line).\n"
        "  Format consumed by RawrXD::Reap::TryLoadCalibrationRanks.\n"
        "  Checkpoint file: calibration_checkpoint.state contains full metrics for --resume.\n"
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
        } else if (arg == "--dump-tokens" && i + 1 < argc) {
            config.dumpTokensPath = argv[++i];
        } else if (arg == "--dump-logits" && i + 1 < argc) {
            config.dumpLogitsPath = argv[++i];
        } else if (arg == "--dump-moe" && i + 1 < argc) {
            config.dumpMoePath = argv[++i];
        } else if (arg == "--dump-moe-layer" && i + 1 < argc) {
            config.dumpMoeLayer = stoi(argv[++i]);
        } else if (arg == "--dump-routing" && i + 1 < argc) {
            config.dumpRoutingPath = argv[++i];
        } else if (arg == "--dump-routing-layer" && i + 1 < argc) {
            config.dumpRoutingLayer = stoi(argv[++i]);
        } else if (arg == "--dump-expert-outs" && i + 1 < argc) {
            config.dumpExpertOutPath = argv[++i];
        } else if (arg == "--dump-expert-layer" && i + 1 < argc) {
            config.dumpExpertOutLayer = stoi(argv[++i]);
        } else if (arg == "--saliency-capture") {
            config.saliencyCapture = true;
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
    
    if (config.resume && (!config.dumpTokensPath.empty() || !config.dumpLogitsPath.empty() ||
        !config.dumpMoePath.empty() || !config.dumpRoutingPath.empty() || !config.dumpExpertOutPath.empty())) {
        fprintf(stderr, "Resume cannot append or overwrite diagnostic capture streams\n");
        return 1;
    }
    if (config.saliencyCapture) {
        error_code ec;
        const bool exists = fs::exists(config.outputDir, ec);
        if (config.resume || !config.dumpRoutingPath.empty() ||
            !config.dumpExpertOutPath.empty() || exists || ec ||
            config.dumpRoutingLayer != config.dumpExpertOutLayer ||
            config.dumpRoutingLayer < -1) {
            fprintf(stderr, "Saliency capture requires a fresh output directory, no resume or explicit capture paths, and matching optional layer filters\n");
            return 1;
        }
        config.dumpRoutingPath = (fs::path(config.outputDir) / "routes.bin").string();
        config.dumpExpertOutPath = (fs::path(config.outputDir) / "expert_outputs.bin").string();
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
