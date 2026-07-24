// Intent Replay Engine - Implementation
// Deterministic replay of autonomous actions

#include "IntentReplayEngine.hpp"
#include "AgentKernel.hpp"

#include <sstream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <iomanip>

// SHA256 hashing — self-contained implementation (no OpenSSL dependency)
// Using a minimal SHA-256 based on FIPS 180-4

namespace {

struct SHA256Ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t buflen;
};

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(SHA256Ctx& ctx, const uint8_t* block) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)block[i*4] << 24 | (uint32_t)block[i*4+1] << 16 |
               (uint32_t)block[i*4+2] << 8 | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=ctx.state[0],b=ctx.state[1],c=ctx.state[2],d=ctx.state[3];
    uint32_t e=ctx.state[4],f=ctx.state[5],g=ctx.state[6],h=ctx.state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx.state[0]+=a; ctx.state[1]+=b; ctx.state[2]+=c; ctx.state[3]+=d;
    ctx.state[4]+=e; ctx.state[5]+=f; ctx.state[6]+=g; ctx.state[7]+=h;
}

static void sha256_init(SHA256Ctx& ctx) {
    ctx.state[0]=0x6a09e667; ctx.state[1]=0xbb67ae85;
    ctx.state[2]=0x3c6ef372; ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f; ctx.state[5]=0x9b05688c;
    ctx.state[6]=0x1f83d9ab; ctx.state[7]=0x5be0cd19;
    ctx.bitlen = 0; ctx.buflen = 0;
}

static void sha256_update(SHA256Ctx& ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx.buffer[ctx.buflen++] = data[i];
        if (ctx.buflen == 64) {
            sha256_transform(ctx, ctx.buffer);
            ctx.bitlen += 512;
            ctx.buflen = 0;
        }
    }
}

static void sha256_final(SHA256Ctx& ctx, uint8_t out[32]) {
    uint64_t bitlen = ctx.bitlen + ctx.buflen * 8;
    ctx.buffer[ctx.buflen++] = 0x80;
    if (ctx.buflen > 56) {
        while (ctx.buflen < 64) ctx.buffer[ctx.buflen++] = 0;
        sha256_transform(ctx, ctx.buffer);
        ctx.buflen = 0;
    }
    while (ctx.buflen < 56) ctx.buffer[ctx.buflen++] = 0;
    for (int i = 7; i >= 0; i--) ctx.buffer[ctx.buflen++] = (uint8_t)(bitlen >> (i*8));
    sha256_transform(ctx, ctx.buffer);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx.state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx.state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx.state[i] >> 8);
        out[i*4+3] = (uint8_t)(ctx.state[i]);
    }
}

} // anonymous namespace

namespace RawrXD {
namespace Kernel {

// ============================================================================
// Utility Functions
// ============================================================================

static std::string ComputeSHA256(const std::string& data) {
    SHA256Ctx ctx;
    sha256_init(ctx);
    sha256_update(ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    uint8_t hash[32];
    sha256_final(ctx, hash);
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

static std::string ComputeSHA256(const std::vector<uint8_t>& data) {
    return ComputeSHA256(std::string(data.begin(), data.end()));
}

static uint64_t GetTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

// ============================================================================
// FileSystemSnapshot Implementation
// ============================================================================

std::string FileSystemSnapshot::ComputeAggregateHash() const {
    std::stringstream ss;
    for (const auto& [path, hash] : fileHashes) {
        ss << path << ":" << hash << ";";
    }
    return ComputeSHA256(ss.str());
}

bool FileSystemSnapshot::HasFileChanged(const std::string& path, 
                                        const std::string& hash) const {
    auto it = fileHashes.find(path);
    if (it == fileHashes.end()) return true; // File didn't exist before
    return it->second != hash;
}

// ============================================================================
// MemorySnapshot Implementation
// ============================================================================

std::string MemorySnapshot::ComputeAggregateHash() const {
    std::stringstream ss;
    for (const auto& [symbol, addr] : symbolAddresses) {
        ss << symbol << "@" << std::hex << addr << ";";
    }
    return ComputeSHA256(ss.str());
}

// ============================================================================
// BuildSnapshot Implementation
// ============================================================================

bool BuildSnapshot::IsValid() const {
    return !executableHash.empty() && !objectFiles.empty();
}

std::string BuildSnapshot::ComputeAggregateHash() const {
    std::stringstream ss;
    ss << buildConfig << ":" << cmakeCacheHash << ":" << executableHash;
    for (const auto& obj : objectFiles) {
        ss << ":" << obj;
    }
    return ComputeSHA256(ss.str());
}

// ============================================================================
// ContextSnapshot Implementation
// ============================================================================

std::string ContextSnapshot::ComputeContextHash() const {
    std::stringstream ss;
    ss << fs.ComputeAggregateHash() << ":"
       << memory.ComputeAggregateHash() << ":"
       << build.ComputeAggregateHash() << ":"
       << agentId;
    return ComputeSHA256(ss.str());
}

// ============================================================================
// ReplayRecord Implementation
// ============================================================================

std::string ReplayRecord::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"recordId\":" << recordId << ",";
    ss << "\"timestamp\":" << timestamp << ",";
    ss << "\"intentType\":\"" << intent.intentType << "\",";
    ss << "\"agentId\":" << intent.sourceAgent << ",";
    ss << "\"succeeded\":" << (succeeded ? "true" : "false") << ",";
    ss << "\"executionTimeMs\":" << executionTimeMs << ",";
    ss << "\"contextHash\":\"" << preSnapshot.ComputeContextHash() << "\",";
    ss << "\"patchHash\":\"" << patchHash << "\",";
    ss << "\"errorMessage\":\"" << errorMessage << "\"";
    ss << "}";
    return ss.str();
}

std::optional<ReplayRecord> ReplayRecord::FromJson(const std::string& json) {
    // Simplified parsing - in production use nlohmann/json
    ReplayRecord record;
    // TODO: Implement full JSON parsing
    return record;
}

std::string ReplayRecord::ComputeReplayHash() const {
    std::stringstream ss;
    ss << intent.intentType << ":"
       << preSnapshot.ComputeContextHash() << ":"
       << patchHash;
    return ComputeSHA256(ss.str());
}

// ============================================================================
// ReplayJournal Implementation
// ============================================================================

ReplayJournal& ReplayJournal::Instance() {
    static ReplayJournal instance;
    return instance;
}

void ReplayJournal::Initialize(const std::string& journalPath) {
    journalPath_ = journalPath;
    
    // Create directory if needed
    std::filesystem::create_directories(journalPath_);
    
    // Load existing records
    LoadExistingRecords();
    
    initialized_.store(true);
}

void ReplayJournal::Shutdown() {
    initialized_.store(false);
}

void ReplayJournal::LoadExistingRecords() {
    if (!std::filesystem::exists(journalPath_)) return;
    
    for (const auto& entry : std::filesystem::directory_iterator(journalPath_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            // Load record
            std::ifstream file(entry.path());
            if (file) {
                std::string json((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
                auto recordOpt = ReplayRecord::FromJson(json);
                if (recordOpt) {
                    auto& record = *recordOpt;
                    records_[record.recordId] = record;
                    
                    // Update indexes
                    intentTypeIndex_[record.intent.intentType].push_back(record.recordId);
                    agentIndex_[record.intent.sourceAgent].push_back(record.recordId);
                    if (!record.succeeded) {
                        failedRecords_.push_back(record.recordId);
                    }
                    recentRecords_.push_back(record.recordId);
                }
            }
        }
    }
}

uint64_t ReplayJournal::StartRecording(const IntentRequest& intent) {
    uint64_t recordId = nextRecordId_.fetch_add(1);
    
    ReplayRecord record;
    record.recordId = recordId;
    record.timestamp = GetTimestamp();
    record.intent = intent;
    
    {
        std::lock_guard<std::mutex> lock(recordsMutex_);
        records_.emplace(recordId, std::move(record));
    }
    
    return recordId;
}

void ReplayJournal::RecordSnapshot(uint64_t recordId, const ContextSnapshot& snapshot, 
                                  bool isPre) {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto it = records_.find(recordId);
    if (it == records_.end()) return;
    
    if (isPre) {
        it->second.preSnapshot = snapshot;
    } else {
        it->second.postSnapshot = snapshot;
    }
}

void ReplayJournal::RecordEvent(uint64_t recordId, const BeaconEvent& event) {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto it = records_.find(recordId);
    if (it == records_.end()) return;
    
    it->second.events.push_back(event);
}

void ReplayJournal::RecordLease(uint64_t recordId, std::shared_ptr<ResourceLease> lease) {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto it = records_.find(recordId);
    if (it == records_.end()) return;
    
    it->second.leases.push_back(lease);
}

void ReplayJournal::RecordTransaction(uint64_t recordId, Hotpatch::PatchTransaction&& tx) {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto it = records_.find(recordId);
    if (it == records_.end()) return;
    
    it->second.transaction = std::make_unique<Hotpatch::PatchTransaction>(std::move(tx));
}

void ReplayJournal::RecordResult(uint64_t recordId, bool success, 
                                  const std::string& error, uint64_t timeMs) {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto it = records_.find(recordId);
    if (it == records_.end()) return;
    
    it->second.succeeded = success;
    it->second.errorMessage = error;
    it->second.executionTimeMs = timeMs;
}

void ReplayJournal::FinalizeRecord(uint64_t recordId) {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto it = records_.find(recordId);
    if (it == records_.end()) return;
    
    auto& record = it->second;
    
    // Update indexes
    intentTypeIndex_[record.intent.intentType].push_back(recordId);
    agentIndex_[record.intent.sourceAgent].push_back(recordId);
    if (!record.succeeded) {
        failedRecords_.push_back(recordId);
    }
    recentRecords_.push_back(recordId);
    
    // Persist to disk
    PersistRecord(record);
}

void ReplayJournal::PersistRecord(const ReplayRecord& record) {
    std::string filename = journalPath_ + "/record_" + std::to_string(record.recordId) + ".json";
    std::ofstream file(filename);
    if (file) {
        file << record.ToJson();
    }
}

std::optional<ReplayRecord> ReplayJournal::GetRecord(uint64_t recordId) const {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto it = records_.find(recordId);
    if (it != records_.end()) return std::move(it->second);
    return std::nullopt;
}

std::vector<ReplayRecord> ReplayJournal::GetRecordsForIntent(const std::string& intentType,
                                                               size_t max) const {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    std::vector<ReplayRecord> result;
    auto it = intentTypeIndex_.find(intentType);
    if (it == intentTypeIndex_.end()) return result;
    
    size_t count = std::min(max, it->second.size());
    for (size_t i = it->second.size() - count; i < it->second.size(); ++i) {
        auto recordIt = records_.find(it->second[i]);
        if (recordIt != records_.end()) {
            result.emplace_back(std::move(recordIt->second));
        }
    }
    
    return result;
}

std::vector<ReplayRecord> ReplayJournal::GetRecordsForAgent(AgentId agent, size_t max) const {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    std::vector<ReplayRecord> result;
    auto it = agentIndex_.find(agent);
    if (it == agentIndex_.end()) return result;
    
    size_t count = std::min(max, it->second.size());
    for (size_t i = it->second.size() - count; i < it->second.size(); ++i) {
        auto recordIt = records_.find(it->second[i]);
        if (recordIt != records_.end()) {
            result.emplace_back(std::move(recordIt->second));
        }
    }
    
    return result;
}

std::vector<ReplayRecord> ReplayJournal::GetFailedRecords(size_t max) const {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    std::vector<ReplayRecord> result;
    size_t count = std::min(max, failedRecords_.size());
    for (size_t i = failedRecords_.size() - count; i < failedRecords_.size(); ++i) {
        auto it = records_.find(failedRecords_[i]);
        if (it != records_.end()) {
            result.push_back(it->second);
        }
    }
    return result;
}

std::vector<ReplayRecord> ReplayJournal::GetRecentRecords(size_t max) const {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    std::vector<ReplayRecord> result;
    size_t count = std::min(max, recentRecords_.size());
    for (size_t i = recentRecords_.size() - count; i < recentRecords_.size(); ++i) {
        auto it = records_.find(recentRecords_[i]);
        if (it != records_.end()) {
            result.push_back(it->second);
        }
    }
    return result;
}

std::optional<ReplayRecord> ReplayJournal::FindSimilarRecord(
    const IntentRequest& intent, const ContextSnapshot& context) const {
    
    // Find records with same intent type
    auto candidates = GetRecordsForIntent(intent.intentType, 100);
    
    std::optional<ReplayRecord> bestMatch;
    size_t bestScore = 0;
    size_t bestIdx = SIZE_MAX;
    
    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& record = candidates[i];
        // Compute similarity score
        size_t score = 0;
        
        // Same agent type
        if (record.preSnapshot.agentType == context.agentType) score += 10;
        
        // Similar file targets
        for (const auto& target : intent.targetFiles) {
            if (std::find(record.intent.targetFiles.begin(), 
                         record.intent.targetFiles.end(), target) 
                         != record.intent.targetFiles.end()) {
                score += 5;
            }
        }
        
        // Similar context hash (first 8 chars)
        std::string ctxHash = context.ComputeContextHash();
        std::string recHash = record.preSnapshot.ComputeContextHash();
        if (ctxHash.substr(0, 8) == recHash.substr(0, 8)) score += 20;
        
        if (score > bestScore) {
            bestScore = score;
            bestIdx = i;
        }
    }
    
    if (bestIdx != SIZE_MAX) {
        bestMatch = std::move(candidates[bestIdx]);
    }
    
    return bestMatch;
}

void ReplayJournal::PruneOldRecords(std::chrono::days maxAge) {
    auto cutoff = std::chrono::system_clock::now() - maxAge;
    uint64_t cutoffMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        cutoff.time_since_epoch()).count();
    
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    std::vector<uint64_t> toRemove;
    for (const auto& [id, record] : records_) {
        if (record.timestamp < cutoffMs) {
            toRemove.push_back(id);
        }
    }
    
    for (uint64_t id : toRemove) {
        records_.erase(id);
        
        // Remove from file system
        std::string filename = journalPath_ + "/record_" + std::to_string(id) + ".json";
        std::filesystem::remove(filename);
    }
}

ReplayJournal::JournalStats ReplayJournal::GetStats() const {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    JournalStats stats{};
    stats.totalRecords = records_.size();
    
    for (const auto& [id, record] : records_) {
        if (record.succeeded) {
            stats.successfulRecords++;
        } else {
            stats.failedRecords++;
        }
    }
    
    // TODO: Compute total size, oldest/newest
    
    return stats;
}

// ============================================================================
// SnapshotManager Implementation
// ============================================================================

SnapshotManager& SnapshotManager::Instance() {
    static SnapshotManager instance;
    return instance;
}

ContextSnapshot SnapshotManager::CaptureFullSnapshot() {
    ContextSnapshot snapshot;
    snapshot.snapshotId = GetTimestamp();
    snapshot.timestamp = snapshot.snapshotId;
    
    // Capture filesystem
    snapshot.fs = CaptureFileSystem(".");
    
    // Capture memory
    snapshot.memory = CaptureMemory();
    
    // Capture build
    snapshot.build = CaptureBuild();
    
    // Capture agent state
    auto& kernel = AgentKernel::Instance();
    snapshot.agentId = 0; // TODO: Current agent
    snapshot.agentType = "unknown";
    
    return snapshot;
}

FileSystemSnapshot SnapshotManager::CaptureFileSystem(const std::string& rootPath) {
    FileSystemSnapshot snapshot;
    snapshot.rootPath = rootPath;
    
    // Walk directory and hash files
    if (std::filesystem::exists(rootPath)) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath)) {
            if (entry.is_regular_file()) {
                std::string path = entry.path().string();
                
                // Read file and compute hash
                std::ifstream file(entry.path(), std::ios::binary);
                if (file) {
                    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                                  std::istreambuf_iterator<char>());
                    snapshot.fileHashes[path] = ComputeSHA256(data);
                    snapshot.fileTimestamps[path] = std::chrono::duration_cast<std::chrono::seconds>(
                        entry.last_write_time().time_since_epoch()).count();
                }
            }
        }
    }
    
    return snapshot;
}

MemorySnapshot SnapshotManager::CaptureMemory() {
    MemorySnapshot snapshot;
    
    // TODO: Capture actual memory state
    // This would involve reading symbol tables, heap state, etc.
    
    return snapshot;
}

BuildSnapshot SnapshotManager::CaptureBuild() {
    BuildSnapshot snapshot;
    
    // Read CMake cache
    if (std::filesystem::exists("CMakeCache.txt")) {
        std::ifstream file("CMakeCache.txt");
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        snapshot.cmakeCacheHash = ComputeSHA256(content);
    }
    
    // Find object files
    if (std::filesystem::exists("build")) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator("build")) {
            if (entry.is_regular_file() && entry.path().extension() == ".obj") {
                snapshot.objectFiles.push_back(entry.path().string());
            }
        }
    }
    
    return snapshot;
}

SnapshotManager::DiffResult SnapshotManager::CompareSnapshots(
    const ContextSnapshot& a, const ContextSnapshot& b) const {
    
    DiffResult result;
    result.identical = true;
    
    // Compare filesystems
    auto fsDiff = CompareFileSystems(a.fs, b.fs);
    if (!fsDiff.identical) {
        result.identical = false;
        result.differences.insert(result.differences.end(), 
                                 fsDiff.differences.begin(), 
                                 fsDiff.differences.end());
    }
    
    // TODO: Compare memory and build
    
    return result;
}

SnapshotManager::DiffResult SnapshotManager::CompareFileSystems(
    const FileSystemSnapshot& a, const FileSystemSnapshot& b) const {
    
    DiffResult result;
    result.identical = true;
    
    // Find files that changed
    for (const auto& [path, hashA] : a.fileHashes) {
        auto it = b.fileHashes.find(path);
        if (it == b.fileHashes.end()) {
            result.identical = false;
            result.differences.push_back("File deleted: " + path);
        } else if (it->second != hashA) {
            result.identical = false;
            result.differences.push_back("File modified: " + path);
        }
    }
    
    // Find new files
    for (const auto& [path, hashB] : b.fileHashes) {
        if (a.fileHashes.find(path) == a.fileHashes.end()) {
            result.identical = false;
            result.differences.push_back("File added: " + path);
        }
    }
    
    return result;
}

// ============================================================================
// IntentReplayEngine Implementation
// ============================================================================

IntentReplayEngine& IntentReplayEngine::Instance() {
    static IntentReplayEngine instance;
    return instance;
}

bool IntentReplayEngine::Initialize(const std::string& journalPath) {
    REPLAY_JOURNAL.Initialize(journalPath);
    initialized_.store(true);
    return true;
}

void IntentReplayEngine::Shutdown() {
    REPLAY_JOURNAL.Shutdown();
    initialized_.store(false);
}

void IntentReplayEngine::StartRecordingIntent(const IntentRequest& intent) {
    if (!initialized_.load()) return;
    
    uint64_t recordId = REPLAY_JOURNAL.StartRecording(intent);
    currentRecordId_.store(recordId);
    isRecording_.store(true);
    
    // Capture pre-snapshot
    auto snapshot = SNAPSHOT_MANAGER.CaptureFullSnapshot();
    snapshot.agentId = intent.sourceAgent;
    REPLAY_JOURNAL.RecordSnapshot(recordId, snapshot, true);
}

void IntentReplayEngine::StopRecordingIntent(bool success, const std::string& error) {
    if (!isRecording_.load()) return;
    
    uint64_t recordId = currentRecordId_.load();
    
    // Capture post-snapshot
    auto snapshot = SNAPSHOT_MANAGER.CaptureFullSnapshot();
    REPLAY_JOURNAL.RecordSnapshot(recordId, snapshot, false);
    
    // Record result
    REPLAY_JOURNAL.RecordResult(recordId, success, error, 0);
    REPLAY_JOURNAL.FinalizeRecord(recordId);
    
    isRecording_.store(false);
}

ReplayResult IntentReplayEngine::ReplayIntent(uint64_t recordId, 
                                                const ReplayOptions& options) {
    ReplaySession session(recordId, options);
    return session.Execute();
}

ReplayResult IntentReplayEngine::ReplayLastIntent(const ReplayOptions& options) {
    auto recent = REPLAY_JOURNAL.GetRecentRecords(1);
    if (recent.empty()) {
        ReplayResult result;
        result.success = false;
        result.errorMessage = "No recent records to replay";
        return result;
    }
    
    return ReplayIntent(recent[0].recordId, options);
}

std::vector<ReplayResult> IntentReplayEngine::ReplayIntentType(
    const std::string& intentType, const ReplayOptions& options) {
    
    std::vector<ReplayResult> results;
    auto records = REPLAY_JOURNAL.GetRecordsForIntent(intentType, 10);
    
    for (const auto& record : records) {
        results.push_back(ReplayIntent(record.recordId, options));
    }
    
    return results;
}

std::vector<ReplayResult> IntentReplayEngine::ReplayFailedIntents(
    const ReplayOptions& options) {
    
    std::vector<ReplayResult> results;
    auto records = REPLAY_JOURNAL.GetFailedRecords(10);
    
    for (const auto& record : records) {
        results.push_back(ReplayIntent(record.recordId, options));
    }
    
    return results;
}

std::string IntentReplayEngine::GenerateReplayReport(uint64_t recordId) const {
    auto recordOpt = REPLAY_JOURNAL.GetRecord(recordId);
    if (!recordOpt) return "Record not found";
    
    auto& record = *recordOpt;
    
    std::stringstream ss;
    ss << "=== Replay Report for Record " << recordId << " ===\n\n";
    ss << "Intent Type: " << record.intent.intentType << "\n";
    ss << "Agent: " << record.intent.sourceAgent << "\n";
    ss << "Timestamp: " << record.timestamp << "\n";
    ss << "Result: " << (record.succeeded ? "SUCCESS" : "FAILED") << "\n";
    ss << "Execution Time: " << record.executionTimeMs << " ms\n";
    ss << "Context Hash: " << record.preSnapshot.ComputeContextHash() << "\n";
    ss << "Patch Hash: " << record.patchHash << "\n\n";
    
    if (!record.succeeded) {
        ss << "Error: " << record.errorMessage << "\n\n";
    }
    
    ss << "Events (" << record.events.size() << "):\n";
    for (const auto& event : record.events) {
        ss << "  - " << static_cast<int>(event.type) << "\n";
    }
    
    return ss.str();
}

void IntentReplayEngine::ConnectToPipeline() {
    // Subscribe to pipeline events
    pipelineSubscriptionId_ = BEACON_BUS.SubscribeAll(
        [this](const BeaconEvent& event) { OnPipelineEvent(event); }
    );
}

void IntentReplayEngine::DisconnectFromPipeline() {
    if (pipelineSubscriptionId_ != 0) {
        BEACON_BUS.Unsubscribe(pipelineSubscriptionId_);
        pipelineSubscriptionId_ = 0;
    }
}

void IntentReplayEngine::OnPipelineEvent(const BeaconEvent& event) {
    if (!isRecording_.load()) return;
    
    uint64_t recordId = currentRecordId_.load();
    REPLAY_JOURNAL.RecordEvent(recordId, event);
}

// ============================================================================
// ScopedReplayRecording Implementation
// ============================================================================

ScopedReplayRecording::ScopedReplayRecording(const IntentRequest& intent) {
    REPLAY_ENGINE.StartRecordingIntent(intent);
    recordId_ = REPLAY_ENGINE.IsRecording() ? 1 : 0; // TODO: Get actual record ID
}

ScopedReplayRecording::~ScopedReplayRecording() {
    if (!finalized_) {
        MarkFailed("Recording scope exited without explicit result");
    }
}

void ScopedReplayRecording::MarkSuccess() {
    if (finalized_) return;
    REPLAY_ENGINE.StopRecordingIntent(true, "");
    finalized_ = true;
}

void ScopedReplayRecording::MarkFailed(const std::string& error) {
    if (finalized_) return;
    REPLAY_ENGINE.StopRecordingIntent(false, error);
    finalized_ = true;
}

// ============================================================================
// ReplaySession Implementation (Stub)
// ============================================================================

ReplaySession::ReplaySession(uint64_t recordId, const ReplayOptions& options)
    : recordId_(recordId), options_(options) {}

bool ReplaySession::Prepare() {
    originalRecord_ = REPLAY_JOURNAL.GetRecord(recordId_);
    return originalRecord_.has_value();
}

ReplayResult ReplaySession::Execute() {
    ReplayResult result;
    
    if (!Prepare()) {
        result.success = false;
        result.errorMessage = "Failed to load original record";
        return result;
    }
    
    // Check context match
    auto currentSnapshot = SNAPSHOT_MANAGER.CaptureFullSnapshot();
    auto diff = SNAPSHOT_MANAGER.CompareSnapshots(originalRecord_->preSnapshot, currentSnapshot);
    
    result.contextMatched = diff.identical;
    if (!diff.identical) {
        std::stringstream diffSs;
        for (const auto& d : diff.differences) {
            diffSs << d << "\n";
        }
        result.contextDiff = diffSs.str();
        
        if (options_.stopOnMismatch) {
            result.success = false;
            result.errorMessage = "Context mismatch detected";
            return result;
        }
    }
    
    // TODO: Actually replay the intent
    result.success = true;
    result.resultMatched = true;
    
    return result;
}

} // namespace Kernel
} // namespace RawrXD
