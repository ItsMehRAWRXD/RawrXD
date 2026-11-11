// =============================================================================
// RawrXD Hash Chain Verifier
// Cryptographic proof of correct execution at every layer
// =============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <unordered_map>

#include <windows.h>

namespace RawrXD {

// =============================================================================
// Hash Types
// =============================================================================

enum class HashType {
    GGUF_RAW = 0,           // Raw file bytes
    TENSOR_METADATA = 1,    // Tensor header + shape
    DEQUANTIZED = 2,        // F32 tensor data
    KERNEL_OUTPUT = 3,      // Post-kernel execution
    LAYER_CHECKPOINT = 4,   // Full layer output
    LOGITS = 5,             // Final logits
    TOKEN_OUTPUT = 6,       // Sampled token
    REPLAY = 7              // Full sequence hash
};

const char* HashTypeToString(HashType type) {
    switch (type) {
        case HashType::GGUF_RAW: return "GGUF_RAW";
        case HashType::TENSOR_METADATA: return "TENSOR_METADATA";
        case HashType::DEQUANTIZED: return "DEQUANTIZED";
        case HashType::KERNEL_OUTPUT: return "KERNEL_OUTPUT";
        case HashType::LAYER_CHECKPOINT: return "LAYER_CHECKPOINT";
        case HashType::LOGITS: return "LOGITS";
        case HashType::TOKEN_OUTPUT: return "TOKEN_OUTPUT";
        case HashType::REPLAY: return "REPLAY";
        default: return "UNKNOWN";
    }
}

// =============================================================================
// Hash Chain Entry
// =============================================================================

struct HashChainEntry {
    uint64_t timestamp;
    HashType type;
    char layerName[64];
    char tensorName[128];
    uint8_t inputHash[32];   // SHA256
    uint8_t outputHash[32];  // SHA256
    uint64_t version;
    uint32_t tier;
    double executionTimeMs;
    uint64_t bytesProcessed;
};

// =============================================================================
// Simple SHA256 Implementation (for verification)
// =============================================================================

class SHA256 {
public:
    SHA256();
    void update(const uint8_t* data, size_t length);
    void finalize(uint8_t hash[32]);
    
    static std::string toHex(const uint8_t hash[32]);
    
private:
    uint32_t state[8];
    uint64_t bitCount;
    uint8_t buffer[64];
    size_t bufferLen;
    
    void transform(const uint8_t* data);
    static uint32_t rotr(uint32_t x, uint32_t n);
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t sigma0(uint32_t x);
    static uint32_t sigma1(uint32_t x);
    static uint32_t gamma0(uint32_t x);
    static uint32_t gamma1(uint32_t x);
};

// SHA256 constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256::SHA256() : bitCount(0), bufferLen(0) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

uint32_t SHA256::rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
uint32_t SHA256::ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
uint32_t SHA256::maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
uint32_t SHA256::sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
uint32_t SHA256::sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
uint32_t SHA256::gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
uint32_t SHA256::gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

void SHA256::transform(const uint8_t* data) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        W[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
               (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
    }
    
    // Initialize working variables
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // Main loop
    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    
    // Update state
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void SHA256::update(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buffer[bufferLen++] = data[i];
        if (bufferLen == 64) {
            transform(buffer);
            bitCount += 512;
            bufferLen = 0;
        }
    }
}

void SHA256::finalize(uint8_t hash[32]) {
    // Padding
    uint64_t totalBits = bitCount + (bufferLen * 8);
    buffer[bufferLen++] = 0x80;
    
    if (bufferLen > 56) {
        while (bufferLen < 64) buffer[bufferLen++] = 0;
        transform(buffer);
        bufferLen = 0;
    }
    
    while (bufferLen < 56) buffer[bufferLen++] = 0;
    
    // Append length
    for (int i = 7; i >= 0; i--) {
        buffer[bufferLen++] = (totalBits >> (i * 8)) & 0xFF;
    }
    
    transform(buffer);
    
    // Output hash
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = state[i] & 0xFF;
    }
}

std::string SHA256::toHex(const uint8_t hash[32]) {
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// =============================================================================
// Hash Chain Verifier
// =============================================================================

class HashChainVerifier {
public:
    static HashChainVerifier& Instance();
    
    bool Initialize(const std::string& modelPath);
    void Shutdown();
    
    // Hash computation
    uint8_t* ComputeFileHash(const std::string& path);
    uint8_t* ComputeTensorHash(const std::string& name, const void* data, size_t size);
    uint8_t* ComputeKernelHash(const std::string& kernel, const void* input, size_t inSize,
                               const void* output, size_t outSize);
    
    // Chain recording
    void RecordHash(HashType type, const char* layer, const char* tensor,
                    const uint8_t* inputHash, const uint8_t* outputHash,
                    uint64_t version, uint32_t tier, double execTime, uint64_t bytes);
    
    // Verification
    bool VerifyChainIntegrity();
    bool VerifyDeterminism(const std::string& previousChain);
    bool VerifyMigrationPreservesData(uint64_t tensorId, uint32_t srcTier, uint32_t dstTier);
    
    // Export
    void ExportChain(const std::string& filename);
    void PrintChainSummary();
    
    // Stats
    uint64_t GetEntryCount() const { return entries_.size(); }
    
private:
    HashChainVerifier() = default;
    ~HashChainVerifier() = default;
    
    std::vector<HashChainEntry> entries_;
    std::unordered_map<std::string, std::vector<uint8_t>> tensorHashes_;
    
    std::string modelPath_;
    uint8_t modelHash_[32];
    bool initialized_ = false;
};

HashChainVerifier& HashChainVerifier::Instance() {
    static HashChainVerifier instance;
    return instance;
}

bool HashChainVerifier::Initialize(const std::string& modelPath) {
    std::cout << "\n========================================\n";
    std::cout << "Hash Chain Verifier Initialized\n";
    std::cout << "Model: " << modelPath << "\n";
    std::cout << "========================================\n\n";
    
    modelPath_ = modelPath;
    
    // Compute model file hash
    uint8_t* hash = ComputeFileHash(modelPath);
    if (hash) {
        memcpy(modelHash_, hash, 32);
        std::cout << "Model SHA256: " << SHA256::toHex(modelHash_) << "\n\n";
        delete[] hash;
    }
    
    initialized_ = true;
    return true;
}

void HashChainVerifier::Shutdown() {
    initialized_ = false;
}

uint8_t* HashChainVerifier::ComputeFileHash(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[!] Failed to open: " << path << "\n";
        return nullptr;
    }
    
    SHA256 sha;
    char buffer[8192];
    
    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        sha.update(reinterpret_cast<uint8_t*>(buffer), file.gcount());
    }
    
    uint8_t* hash = new uint8_t[32];
    sha.finalize(hash);
    
    return hash;
}

uint8_t* HashChainVerifier::ComputeTensorHash(const std::string& name, 
                                               const void* data, size_t size) {
    SHA256 sha;
    sha.update(reinterpret_cast<const uint8_t*>(name.c_str()), name.length());
    sha.update(reinterpret_cast<const uint8_t*>(data), size);
    
    uint8_t* hash = new uint8_t[32];
    sha.finalize(hash);
    
    // Store for later verification
    std::vector<uint8_t> stored(hash, hash + 32);
    tensorHashes_[name] = stored;
    
    return hash;
}

uint8_t* HashChainVerifier::ComputeKernelHash(const std::string& kernel,
                                               const void* input, size_t inSize,
                                               const void* output, size_t outSize) {
    SHA256 sha;
    sha.update(reinterpret_cast<const uint8_t*>(kernel.c_str()), kernel.length());
    sha.update(reinterpret_cast<const uint8_t*>(input), inSize);
    sha.update(reinterpret_cast<const uint8_t*>(output), outSize);
    
    uint8_t* hash = new uint8_t[32];
    sha.finalize(hash);
    
    return hash;
}

void HashChainVerifier::RecordHash(HashType type, const char* layer, const char* tensor,
                                    const uint8_t* inputHash, const uint8_t* outputHash,
                                    uint64_t version, uint32_t tier, double execTime, 
                                    uint64_t bytes) {
    HashChainEntry entry{};
    entry.timestamp = GetTickCount64();
    entry.type = type;
    strncpy(entry.layerName, layer, sizeof(entry.layerName) - 1);
    strncpy(entry.tensorName, tensor, sizeof(entry.tensorName) - 1);
    memcpy(entry.inputHash, inputHash, 32);
    memcpy(entry.outputHash, outputHash, 32);
    entry.version = version;
    entry.tier = tier;
    entry.executionTimeMs = execTime;
    entry.bytesProcessed = bytes;
    
    entries_.push_back(entry);
}

bool HashChainVerifier::VerifyChainIntegrity() {
    std::cout << "\n[+] Verifying hash chain integrity...\n";
    
    bool valid = true;
    uint64_t errors = 0;
    
    for (size_t i = 1; i < entries_.size(); i++) {
        // Verify output of previous = input of current
        if (memcmp(entries_[i - 1].outputHash, entries_[i].inputHash, 32) != 0) {
            std::cerr << "[!] Chain break at entry " << i << "\n";
            std::cerr << "    Previous output: " << SHA256::toHex(entries_[i - 1].outputHash) << "\n";
            std::cerr << "    Current input:   " << SHA256::toHex(entries_[i].inputHash) << "\n";
            valid = false;
            errors++;
        }
    }
    
    if (valid) {
        std::cout << "    Chain integrity: VERIFIED (" << entries_.size() << " entries)\n";
    } else {
        std::cout << "    Chain integrity: FAILED (" << errors << " breaks)\n";
    }
    
    return valid;
}

bool HashChainVerifier::VerifyMigrationPreservesData(uint64_t tensorId, 
                                                       uint32_t srcTier, uint32_t dstTier) {
    // Find all entries for this tensor
    std::vector<const HashChainEntry*> tensorEntries;
    for (const auto& entry : entries_) {
        if (strstr(entry.tensorName, std::to_string(tensorId).c_str())) {
            tensorEntries.push_back(&entry);
        }
    }
    
    if (tensorEntries.size() < 2) {
        return true;  // No migration recorded
    }
    
    // Verify data hash unchanged across migrations
    bool preserved = true;
    for (size_t i = 1; i < tensorEntries.size(); i++) {
        if (memcmp(tensorEntries[i - 1]->outputHash, tensorEntries[i]->inputHash, 32) != 0) {
            std::cerr << "[!] Data corruption detected for tensor " << tensorId << "\n";
            preserved = false;
        }
    }
    
    return preserved;
}

void HashChainVerifier::ExportChain(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[!] Failed to open: " << filename << "\n";
        return;
    }
    
    // Write header
    uint64_t count = entries_.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    // Write model hash
    file.write(reinterpret_cast<const char*>(modelHash_), 32);
    
    // Write entries
    for (const auto& entry : entries_) {
        file.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
    }
    
    file.close();
    std::cout << "[+] Exported hash chain to: " << filename << "\n";
    std::cout << "    Entries: " << count << "\n";
}

void HashChainVerifier::PrintChainSummary() {
    std::cout << "\n========== Hash Chain Summary ==========\n";
    std::cout << "Total Entries: " << entries_.size() << "\n\n";
    
    // Count by type
    std::unordered_map<HashType, uint64_t> typeCounts;
    for (const auto& entry : entries_) {
        typeCounts[entry.type]++;
    }
    
    std::cout << "By Type:\n";
    for (const auto& [type, count] : typeCounts) {
        std::cout << "  " << HashTypeToString(type) << ": " << count << "\n";
    }
    
    // Show sample entries
    std::cout << "\nSample Entries:\n";
    for (size_t i = 0; i < std::min(size_t(5), entries_.size()); i++) {
        const auto& e = entries_[i];
        std::cout << "  [" << i << "] " << HashTypeToString(e.type)
                  << " | " << e.layerName
                  << " | in: " << SHA256::toHex(e.inputHash).substr(0, 16) << "..."
                  << " | out: " << SHA256::toHex(e.outputHash).substr(0, 16) << "..."
                  << " | v" << e.version << "\n";
    }
    
    std::cout << "========================================\n";
}

// =============================================================================
// C API
// =============================================================================

extern "C" {

bool RawrXD_Verifier_Initialize(const char* modelPath) {
    return HashChainVerifier::Instance().Initialize(modelPath);
}

void RawrXD_Verifier_Shutdown() {
    HashChainVerifier::Instance().Shutdown();
}

void RawrXD_Verifier_RecordHash(int type, const char* layer, const char* tensor,
                                 const uint8_t* inputHash, const uint8_t* outputHash,
                                 uint64_t version, uint32_t tier, double execTime, 
                                 uint64_t bytes) {
    HashChainVerifier::Instance().RecordHash(
        static_cast<HashType>(type), layer, tensor,
        inputHash, outputHash, version, tier, execTime, bytes);
}

bool RawrXD_Verifier_VerifyChain() {
    return HashChainVerifier::Instance().VerifyChainIntegrity();
}

void RawrXD_Verifier_Export(const char* filename) {
    HashChainVerifier::Instance().ExportChain(filename);
}

void RawrXD_Verifier_PrintSummary() {
    HashChainVerifier::Instance().PrintChainSummary();
}

} // extern "C"

} // namespace RawrXD

// =============================================================================
// Main Test
// =============================================================================

int main(int argc, char* argv[]) {
    using namespace RawrXD;
    
    std::cout << "========================================\n";
    std::cout << "RawrXD Hash Chain Verifier\n";
    std::cout << "Cryptographic Proof of Correct Execution\n";
    std::cout << "========================================\n\n";
    
    const char* modelPath = (argc > 1) ? argv[1] : "llama-2-7b.gguf";
    
    // Initialize
    if (!RawrXD_Verifier_Initialize(modelPath)) {
        return 1;
    }
    
    auto& verifier = HashChainVerifier::Instance();
    
    // Simulate hash chain recording
    std::cout << "[+] Simulating inference with hash recording...\n\n";
    
    // Simulate layer execution with hash recording
    for (int layer = 0; layer < 5; layer++) {
        char layerName[64];
        snprintf(layerName, sizeof(layerName), "blk.%02d", layer);
        
        // Input hash (from previous layer)
        uint8_t inputHash[32];
        for (int i = 0; i < 32; i++) inputHash[i] = (layer * 32 + i) % 256;
        
        // Simulate kernel execution
        uint8_t outputHash[32];
        for (int i = 0; i < 32; i++) outputHash[i] = ((layer + 1) * 32 + i) % 256;
        
        // Record hash
        verifier.RecordHash(
            HashType::LAYER_CHECKPOINT,
            layerName,
            "output",
            inputHash,
            outputHash,
            layer + 1,
            0,  // VRAM
            10.0 + layer * 2.0,  // Simulated execution time
            4096 * 4096 * sizeof(float)
        );
        
        std::cout << "  Recorded: " << layerName << " | hash: " 
                  << SHA256::toHex(outputHash).substr(0, 16) << "...\n";
    }
    
    // Print summary
    verifier.PrintChainSummary();
    
    // Verify chain
    bool integrity = verifier.VerifyChainIntegrity();
    
    // Export
    verifier.ExportChain("proof_chain.rawrproof");
    
    // Cleanup
    RawrXD_Verifier_Shutdown();
    
    std::cout << "\n========================================\n";
    std::cout << "Verification: " << (integrity ? "PASSED" : "FAILED") << "\n";
    std::cout << "========================================\n";
    
    return integrity ? 0 : 1;
}
