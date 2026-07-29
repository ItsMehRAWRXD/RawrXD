/**
 * @file meta_learn.cpp
 * @brief Performance database for quantization/kernel auto-tuning (Qt-free, nlohmann-free)
 *
 * Stores perf records in a JSON file. Uses Win32 / POSIX for system info
 * and CryptoAPI / openssl for SHA-256 hardware hashing.
 * Uses json_types.hpp for serialization, minimal parser for loading.
 */
#include "meta_learn.hpp"
<<<<<<< HEAD
#include "../json_types.hpp"
=======
#include <fstream>
#include <sstream>
#include <filesystem>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
<<<<<<< HEAD
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <numeric>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
=======
#include <chrono>
#include <windows.h>
#include <bcrypt.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <wincrypt.h>
#  pragma comment(lib, "advapi32.lib")
#else
#  include <unistd.h>
#endif

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
namespace {

<<<<<<< HEAD
std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string toUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    return s;
}

int64_t currentMsEpoch() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

std::string ensureDatabasePath() {
    std::string base;
#ifdef _WIN32
    const char* ad = std::getenv("LOCALAPPDATA");
    if (ad) base = std::string(ad) + "\\RawrXD";
#else
    const char* home = std::getenv("HOME");
    if (home) base = std::string(home) + "/.local/share/RawrXD";
#endif
    if (base.empty()) base = ".rawrxd";

    fs::create_directories(base);
    return (fs::path(base) / "perf_db.json").string();
}

std::string defaultGpuLabel() {
#ifdef _WIN32
    char buf[256]{};
    DWORD sz = sizeof(buf);
    if (GetComputerNameA(buf, &sz)) return buf;
#else
    char buf[256]{};
    if (gethostname(buf, sizeof(buf)) == 0) return buf;
#endif
    return "unknown-gpu";
}

std::string sha256Hex(const std::string& input) {
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return {};
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return {};
    }
    CryptHashData(hHash, reinterpret_cast<const BYTE*>(input.data()),
                  static_cast<DWORD>(input.size()), 0);
    DWORD hashLen = 32;
    uint8_t hash[32]{};
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (DWORD i = 0; i < hashLen; ++i) {
        result += hex[hash[i] >> 4];
        result += hex[hash[i] & 0xF];
    }
    return result.substr(0, 32); // first 16 bytes hex
#else
    // Fallback: trivial FNV-style hash (replace with openssl if available)
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : input) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    char buf[17]{};
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return buf;
#endif
}

std::string computeHardwareHash() {
    std::string payload;
#ifdef _WIN32
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    payload += "arch=" + std::to_string(si.wProcessorArchitecture) + "|";
    char buf[256]{};
    DWORD sz = sizeof(buf);
    if (GetComputerNameA(buf, &sz)) payload += std::string("host=") + buf + "|";
#else
    char buf[256]{};
    if (gethostname(buf, sizeof(buf)) == 0) payload += std::string("host=") + buf + "|";
#endif
    payload += "threads=" + std::to_string(std::thread::hardware_concurrency());
    return sha256Hex(payload);
=======
std::string ensureDatabasePath() {
    char* appData = nullptr;
    size_t len = 0;
    _dupenv_s(&appData, &len, "APPDATA");
    
    std::string base;
    if (appData && len > 0) {
        base = std::string(appData) + "\\RawrXD";
        free(appData);
    } else {
        char* home = nullptr;
        _dupenv_s(&home, &len, "USERPROFILE");
        if (home && len > 0) {
            base = std::string(home) + "\\.rawrxd";
            free(home);
        } else {
            base = ".rawrxd";
        }
    }
    
    fs::create_directories(base);
    return base + "\\perf_db.json";
}

std::string defaultGpuLabel() {
    return "unknown-gpu";
}

std::string computeHardwareHash() {
    char hostname[256] = {0};
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    std::string payload = std::string(hostname) + "|" + 
                         std::to_string(sysInfo.dwNumberOfProcessors);
    
    // Use BCrypt for SHA-256
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHash = 0;
    DWORD cbData = 0;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
        return "unknown-hash";
    }
    
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    
    std::vector<BYTE> hash(cbHash);
    
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
        BCryptHashData(hHash, (PBYTE)payload.data(), (ULONG)payload.size(), 0);
        BCryptFinishHash(hHash, hash.data(), cbHash, 0);
        BCryptDestroyHash(hHash);
    }
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    // Convert to hex string (first 32 chars)
    std::stringstream ss;
    for (size_t i = 0; i < std::min(size_t(16), hash.size()); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

} // namespace

<<<<<<< HEAD
// ---------------------------------------------------------------------------
// MetaLearn implementation
// ---------------------------------------------------------------------------
MetaLearn::MetaLearn()
    : m_dbPath(ensureDatabasePath())
{
    loadDatabase();
}

std::string MetaLearn::gpuHash() const { return hardwareKey(); }

std::string MetaLearn::hardwareKey() const { return computeHardwareHash(); }

std::string MetaLearn::resolveGpuLabel(const std::string& explicitGpu) const {
    std::string t = trim(explicitGpu);
    return t.empty() ? defaultGpuLabel() : t;
}

// ---------------------------------------------------------------------------
// Minimal JSON field extraction helpers (no nlohmann dependency)
// ---------------------------------------------------------------------------

/// Extract a string value for "key": "value" from a JSON object fragment
static std::string extractJsonString(const std::string& obj, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = obj.find(pat);
    if (pos == std::string::npos) return {};
    pos = obj.find(':', pos + pat.size());
    if (pos == std::string::npos) return {};
    pos = obj.find('"', pos + 1);
    if (pos == std::string::npos) return {};
    ++pos;
    size_t end = pos;
    while (end < obj.size() && obj[end] != '"') {
        if (obj[end] == '\\') ++end; // skip escape
        ++end;
=======
std::vector<PerfRecord> MetaLearn::loadDB(bool* ok) {
    if (ok) {
        *ok = true;
    }
    
    std::string path = ensureDatabasePath();
    if (!fs::exists(path)) {
        return {};
    }
    
    std::ifstream f(path);
    if (!f) {
        if (ok) {
            *ok = false;
        }
        return {};
    }
    
    json j;
    try {
        f >> j;
    } catch (...) {
        if (ok) {
            *ok = false;
        }
        return {};
    }
    f.close();
    
    if (!j.is_array()) {
        if (ok) {
            *ok = false;
        }
        return {};
    }
    
    std::vector<PerfRecord> records;
    for (const auto& item : j) {
        PerfRecord rec;
        
        if (item.contains("quant") && item["quant"].is_string()) {
            std::string quant = item["quant"];
            std::transform(quant.begin(), quant.end(), quant.begin(), ::toupper);
            rec.quant = quant.empty() ? "UNKNOWN" : quant;
        } else {
            rec.quant = "UNKNOWN";
        }
        
        if (item.contains("kernel") && item["kernel"].is_string()) {
            std::string kernel = item["kernel"];
            std::transform(kernel.begin(), kernel.end(), kernel.begin(), ::toupper);
            rec.kernel = kernel.empty() ? "UNKNOWN" : kernel;
        } else {
            rec.kernel = "UNKNOWN";
        }
        
        rec.gpu = item.value("gpu", defaultGpuLabel());
        rec.hardware = item.value("sha256", item.value("hardware", computeHardwareHash()));
        rec.tps = item.value("tps", 0.0);
        rec.ppl = item.value("ppl", 0.0);
        rec.timestamp = item.value("when", std::chrono::system_clock::now().time_since_epoch().count());
        
        records.push_back(rec);
    }
    
    return records;
}

MetaLearn::MetaLearn()
    : m_dbPath(ensureDatabasePath()) {
    loadDatabase();
}

std::string MetaLearn::gpuHash() const {
    return hardwareKey();
}

std::string MetaLearn::hardwareKey() const {
    return computeHardwareHash();
}

std::string MetaLearn::resolveGpuLabel(const std::string& explicitGpu) const {
    // Trim whitespace
    std::string trimmed = explicitGpu;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r"));
    trimmed.erase(trimmed.find_last_not_of(" \t\n\r") + 1);
    
    if (!trimmed.empty()) {
        return trimmed;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    return obj.substr(pos, end - pos);
}

<<<<<<< HEAD
/// Extract a numeric value for "key": 123.45 from a JSON object fragment
static double extractJsonDouble(const std::string& obj, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = obj.find(pat);
    if (pos == std::string::npos) return 0.0;
    pos = obj.find(':', pos + pat.size());
    if (pos == std::string::npos) return 0.0;
    ++pos;
    while (pos < obj.size() && (obj[pos] == ' ' || obj[pos] == '\t')) ++pos;
    return std::strtod(obj.c_str() + pos, nullptr);
}

/// Extract an int64 value for "key": 12345 from a JSON object fragment
static int64_t extractJsonInt64(const std::string& obj, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = obj.find(pat);
    if (pos == std::string::npos) return 0;
    pos = obj.find(':', pos + pat.size());
    if (pos == std::string::npos) return 0;
    ++pos;
    while (pos < obj.size() && (obj[pos] == ' ' || obj[pos] == '\t')) ++pos;
    return std::strtoll(obj.c_str() + pos, nullptr, 10);
}

/// Parse a JSON array of objects and extract top-level { ... } blocks
static std::vector<std::string> splitJsonObjects(const std::string& raw) {
    std::vector<std::string> objects;
    int depth = 0;
    size_t objStart = std::string::npos;
    bool inArray = false;

    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '"') {
            // skip string contents
            ++i;
            while (i < raw.size() && raw[i] != '"') {
                if (raw[i] == '\\') ++i;
                ++i;
            }
            continue;
        }
        if (c == '[' && !inArray) { inArray = true; continue; }
        if (c == '{') {
            if (depth == 0) objStart = i;
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 0 && objStart != std::string::npos) {
                objects.push_back(raw.substr(objStart, i - objStart + 1));
                objStart = std::string::npos;
            }
        }
    }
    return objects;
}

std::vector<PerfRecord> MetaLearn::loadDB(bool* ok) {
    if (ok) *ok = true;

    std::string path = ensureDatabasePath();
    if (!fs::exists(path)) return {};

    std::ifstream f(path);
    if (!f.is_open()) {
        if (ok) *ok = false;
        fprintf(stderr, "[WARN] [MetaLearn] Failed to open %s\n", path.c_str());
        return {};
    }

    std::string raw((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    if (raw.empty()) return {};

    auto objects = splitJsonObjects(raw);
    std::vector<PerfRecord> records;
    records.reserve(objects.size());

    for (const auto& obj : objects) {
        PerfRecord rec;
        rec.quant    = extractJsonString(obj, "quant");
        rec.kernel   = extractJsonString(obj, "kernel");
        rec.gpu      = extractJsonString(obj, "gpu");
        rec.hardware = extractJsonString(obj, "sha256");
        if (rec.hardware.empty())
            rec.hardware = extractJsonString(obj, "hardware");
        rec.tps      = extractJsonDouble(obj, "tps");
        rec.ppl      = extractJsonDouble(obj, "ppl");
        rec.timestamp = extractJsonInt64(obj, "when");
        records.push_back(rec);
    }

    return records;
}

bool MetaLearn::record(const std::string& quant,
                       const std::string& kernel,
                       const std::string& gpu,
                       double tps, double ppl) {
    PerfRecord rec;
    rec.quant    = toUpper(trim(quant));
    rec.kernel   = toUpper(trim(kernel));
    rec.gpu      = resolveGpuLabel(gpu);
    rec.hardware = hardwareKey();
    rec.tps      = (std::isfinite(tps) && tps > 0.0) ? tps : 0.0;
    rec.ppl      = (std::isfinite(ppl) && ppl > 0.0) ? ppl : 0.0;
    rec.timestamp = currentMsEpoch();

    if (rec.quant.empty())  rec.quant  = "UNKNOWN";
    if (rec.kernel.empty()) rec.kernel = "UNKNOWN";

    m_records.push_back(rec);
    if (onRecordAdded) onRecordAdded(rec);

    if (!saveDatabase()) {
        m_records.pop_back();
        fprintf(stderr, "[WARN] [MetaLearn] Failed to persist record\n");
        return false;
    }
=======
bool MetaLearn::record(const std::string& quant,
                       const std::string& kernel,
                       const std::string& gpu,
                       double tps,
                       double ppl) {
    PerfRecord rec;
    
    // Convert to uppercase and trim
    std::string quantUpper = quant;
    std::transform(quantUpper.begin(), quantUpper.end(), quantUpper.begin(), ::toupper);
    quantUpper.erase(0, quantUpper.find_first_not_of(" \t\n\r"));
    quantUpper.erase(quantUpper.find_last_not_of(" \t\n\r") + 1);
    rec.quant = quantUpper.empty() ? "UNKNOWN" : quantUpper;
    
    std::string kernelUpper = kernel;
    std::transform(kernelUpper.begin(), kernelUpper.end(), kernelUpper.begin(), ::toupper);
    kernelUpper.erase(0, kernelUpper.find_first_not_of(" \t\n\r"));
    kernelUpper.erase(kernelUpper.find_last_not_of(" \t\n\r") + 1);
    rec.kernel = kernelUpper.empty() ? "UNKNOWN" : kernelUpper;
    
    rec.gpu = resolveGpuLabel(gpu);
    rec.hardware = hardwareKey();
    rec.tps = (std::isfinite(tps) && tps > 0.0) ? tps : 0.0;
    rec.ppl = (std::isfinite(ppl) && ppl > 0.0) ? ppl : 0.0;
    rec.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    m_records.push_back(rec);
    if (onRecordAdded) onRecordAdded(rec);
    
    if (!saveDatabase()) {
        m_records.pop_back();
        return false;
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

bool MetaLearn::autoTuneQuant() {
<<<<<<< HEAD
    std::string best;
    double avgTps = 0, avgPpl = 0;
    if (!computeQuantSuggestion(&best, &avgTps, &avgPpl)) return false;
    if (m_lastQuantSuggestion == best) return true;
    m_lastQuantSuggestion = best;
    if (onSuggestionReady) onSuggestionReady(best.c_str());
    fprintf(stderr, "[INFO] [MetaLearn] Auto-selected quant: %s (TPS: %.1f, PPL: %.2f)\n",
            best.c_str(), avgTps, avgPpl);
=======
    std::string bestQuant;
    double avgTps = 0.0;
    double avgPpl = 0.0;
    if (!computeQuantSuggestion(&bestQuant, &avgTps, &avgPpl)) {
        return false;
    }
    
    if (m_lastQuantSuggestion == bestQuant) {
        return true;
    }
    
    m_lastQuantSuggestion = bestQuant;
    if (onSuggestionReady) onSuggestionReady(bestQuant);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

bool MetaLearn::autoTuneKernel() {
<<<<<<< HEAD
    std::string best;
    double avgTps = 0;
    if (!computeKernelSuggestion(&best, &avgTps)) return false;
    if (m_lastKernelSuggestion == best) return true;
    m_lastKernelSuggestion = best;
    if (onKernelSuggestionReady) onKernelSuggestionReady(best.c_str());
    fprintf(stderr, "[INFO] [MetaLearn] Auto-selected kernel: %s (TPS: %.1f)\n",
            best.c_str(), avgTps);
=======
    std::string bestKernel;
    double avgTps = 0.0;
    if (!computeKernelSuggestion(&bestKernel, &avgTps)) {
        return false;
    }
    
    if (m_lastKernelSuggestion == bestKernel) {
        return true;
    }
    
    m_lastKernelSuggestion = bestKernel;
    if (onKernelSuggestionReady) onKernelSuggestionReady(bestKernel);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

std::string MetaLearn::suggestQuant() const {
<<<<<<< HEAD
    std::string best; double t, p;
    return computeQuantSuggestion(&best, &t, &p) ? best : "Q4_0";
}

std::string MetaLearn::suggestKernel() const {
    std::string best; double t;
    return computeKernelSuggestion(&best, &t) ? best : "AVX2";
}

std::vector<PerfRecord> MetaLearn::getHistory(const std::string& quant) const {
    if (quant.empty()) return m_records;
    std::string qUp = toUpper(trim(quant));
    std::vector<PerfRecord> out;
    for (const auto& r : m_records)
        if (r.quant == qUp) out.push_back(r);
    return out;
=======
    std::string bestQuant;
    double avgTps = 0.0;
    double avgPpl = 0.0;
    if (!computeQuantSuggestion(&bestQuant, &avgTps, &avgPpl)) {
        return "Q4_0";
    }
    return bestQuant;
}

std::string MetaLearn::suggestKernel() const {
    std::string bestKernel;
    double avgTps = 0.0;
    if (!computeKernelSuggestion(&bestKernel, &avgTps)) {
        return "AVX2";
    }
    return bestKernel;
}

std::vector<PerfRecord> MetaLearn::getHistory(const std::string& quant) const {
    if (quant.empty()) {
        return m_records;
    }
    
    std::vector<PerfRecord> filtered;
    std::string qUpper = quant;
    std::transform(qUpper.begin(), qUpper.end(), qUpper.begin(), ::toupper);
    qUpper.erase(0, qUpper.find_first_not_of(" \t\n\r"));
    qUpper.erase(qUpper.find_last_not_of(" \t\n\r") + 1);
    
    for (const PerfRecord& rec : m_records) {
        if (rec.quant == qUpper) {
            filtered.push_back(rec);
        }
    }
    return filtered;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool MetaLearn::loadDatabase() {
    m_records.clear();
<<<<<<< HEAD
    bool ok = false;
    std::vector<PerfRecord> arr = MetaLearn::loadDB(&ok);
    if (!ok) return false;
    if (arr.empty()) return true;

    m_records.reserve(arr.size());
    for (auto& rec : arr) {
        // Normalize fields
        rec.quant    = toUpper(trim(rec.quant));
        rec.kernel   = toUpper(trim(rec.kernel));
        if (rec.quant.empty())    rec.quant    = "UNKNOWN";
        if (rec.kernel.empty())   rec.kernel   = "UNKNOWN";
        if (rec.gpu.empty())      rec.gpu      = defaultGpuLabel();
        if (rec.hardware.empty()) rec.hardware = hardwareKey();
        if (rec.timestamp <= 0)   rec.timestamp = currentMsEpoch();
        m_records.push_back(rec);
    }

    fprintf(stderr, "[INFO] [MetaLearn] Loaded %zu records\n", m_records.size());
    return true;
}

bool MetaLearn::saveDatabase() const {
    JsonArray arr;
    for (const auto& rec : m_records) {
        JsonObject obj;
        obj["quant"]   = JsonValue(rec.quant);
        obj["kernel"]  = JsonValue(rec.kernel);
        obj["gpu"]     = JsonValue(rec.gpu);
        obj["sha256"]  = JsonValue(rec.hardware);
        obj["tps"]     = JsonValue(rec.tps);
        obj["ppl"]     = JsonValue(rec.ppl);
        obj["when"]    = JsonValue(rec.timestamp);
        arr.push_back(JsonValue(std::move(obj)));
    }

    std::string output = JsonDoc::toJson(arr);

    fs::create_directories(fs::path(m_dbPath).parent_path());
    std::ofstream f(m_dbPath, std::ios::trunc);
    if (!f.is_open()) {
        fprintf(stderr, "[WARN] [MetaLearn] Cannot write %s\n", m_dbPath.c_str());
        return false;
    }
    f << output;
    return f.good();
=======
    
    bool ok = false;
    m_records = MetaLearn::loadDB(&ok);
    return ok || m_records.empty();
}

bool MetaLearn::saveDatabase() const {
    json arr = json::array();
    
    for (const PerfRecord& rec : m_records) {
        json obj;
        obj["quant"] = rec.quant;
        obj["kernel"] = rec.kernel;
        obj["gpu"] = rec.gpu;
        obj["sha256"] = rec.hardware;
        obj["tps"] = rec.tps;
        obj["ppl"] = rec.ppl;
        obj["when"] = rec.timestamp;
        arr.push_back(obj);
    }
    
    fs::path dbPath(m_dbPath);
    fs::create_directories(dbPath.parent_path());
    
    std::ofstream f(m_dbPath);
    if (!f) {
        return false;
    }
    
    f << arr.dump(2);
    f.close();
    
    return true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool MetaLearn::computeQuantSuggestion(std::string* bestQuant,
                                       double* avgTps,
                                       double* avgPpl) const {
<<<<<<< HEAD
    struct S { double sumTps = 0, sumPpl = 0; int count = 0; };
    std::string key = hardwareKey();
    std::unordered_map<std::string, S> stats;

    for (const auto& r : m_records) {
        if (!r.hardware.empty() && r.hardware != key) continue;
        if (r.quant.empty()) continue;
        if (!std::isfinite(r.tps) || r.tps <= 0) continue;
        if (!std::isfinite(r.ppl) || r.ppl <= 0) continue;
        auto& e = stats[r.quant];
        e.sumTps += r.tps; e.sumPpl += r.ppl; e.count++;
    }

    if (stats.empty()) {
        if (bestQuant) bestQuant->clear();
        if (avgTps) *avgTps = 0; if (avgPpl) *avgPpl = 0;
        return false;
    }

    double bestPplVal = std::numeric_limits<double>::max();
    for (const auto& [_, v] : stats) {
        if (!v.count) continue;
        bestPplVal = std::min(bestPplVal, v.sumPpl / v.count);
    }

    double pplLimit = bestPplVal * 1.05;
    std::string chosen; double cTps = 0, cPpl = 0; bool found = false;
    for (const auto& [name, v] : stats) {
        if (!v.count) continue;
        double at = v.sumTps / v.count, ap = v.sumPpl / v.count;
        if (ap <= pplLimit && (!found || at > cTps)) {
            found = true; chosen = name; cTps = at; cPpl = ap;
=======
    struct QuantStats {
        double sumTps = 0.0;
        double sumPpl = 0.0;
        int count = 0;
    };
    
    const std::string key = hardwareKey();
    std::unordered_map<std::string, QuantStats> stats;
    
    for (const PerfRecord& rec : m_records) {
        if (!rec.hardware.empty() && rec.hardware != key) {
            continue;
        }
        if (rec.quant.empty()) {
            continue;
        }
        if (!std::isfinite(rec.tps) || rec.tps <= 0.0) {
            continue;
        }
        if (!std::isfinite(rec.ppl) || rec.ppl <= 0.0) {
            continue;
        }
        
        QuantStats& entry = stats[rec.quant];
        entry.sumTps += rec.tps;
        entry.sumPpl += rec.ppl;
        entry.count += 1;
    }
    
    if (stats.empty()) {
        if (bestQuant) {
            bestQuant->clear();
        }
        if (avgTps) {
            *avgTps = 0.0;
        }
        if (avgPpl) {
            *avgPpl = 0.0;
        }
        return false;
    }
    
    double bestPplValue = std::numeric_limits<double>::max();
    for (const auto& [k, v] : stats) {
        if (!v.count) {
            continue;
        }
        const double avg = v.sumPpl / v.count;
        bestPplValue = std::min(bestPplValue, avg);
    }
    
    const double pplLimit = bestPplValue * 1.05;
    std::string chosen;
    double chosenTps = 0.0;
    double chosenPpl = 0.0;
    bool found = false;
    
    for (const auto& [k, v] : stats) {
        if (!v.count) {
            continue;
        }
        const double avgT = v.sumTps / v.count;
        const double avgP = v.sumPpl / v.count;
        if (avgP <= pplLimit && (!found || avgT > chosenTps)) {
            found = true;
            chosen = k;
            chosenTps = avgT;
            chosenPpl = avgP;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }
    }
    
    if (!found) {
<<<<<<< HEAD
        for (const auto& [name, v] : stats) {
            if (!v.count) continue;
            double at = v.sumTps / v.count, ap = v.sumPpl / v.count;
            if (!found || ap < cPpl || (std::abs(ap - cPpl) < 1e-6 && at > cTps)) {
                found = true; chosen = name; cTps = at; cPpl = ap;
=======
        for (const auto& [k, v] : stats) {
            if (!v.count) {
                continue;
            }
            const double avgT = v.sumTps / v.count;
            const double avgP = v.sumPpl / v.count;
            if (!found || avgP < chosenPpl || (std::abs(avgP - chosenPpl) < 1e-6 && avgT > chosenTps)) {
                found = true;
                chosen = k;
                chosenTps = avgT;
                chosenPpl = avgP;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            }
        }
    }
    
    if (!found) {
        if (bestQuant) bestQuant->clear();
        if (avgTps) *avgTps = 0; if (avgPpl) *avgPpl = 0;
        return false;
    }
<<<<<<< HEAD

    if (bestQuant) *bestQuant = chosen;
    if (avgTps) *avgTps = cTps;
    if (avgPpl) *avgPpl = cPpl;
=======
    
    if (bestQuant) {
        *bestQuant = chosen;
    }
    if (avgTps) {
        *avgTps = chosenTps;
    }
    if (avgPpl) {
        *avgPpl = chosenPpl;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

bool MetaLearn::computeKernelSuggestion(std::string* bestKernel,
                                        double* avgTps) const {
<<<<<<< HEAD
    struct K { double sumTps = 0; int count = 0; };
    std::string key = hardwareKey();
    std::unordered_map<std::string, K> stats;

    for (const auto& r : m_records) {
        if (r.kernel.empty()) continue;
        if (!r.hardware.empty() && r.hardware != key) continue;
        if (!std::isfinite(r.tps) || r.tps <= 0) continue;
        auto& e = stats[r.kernel];
        e.sumTps += r.tps; e.count++;
    }

    if (stats.empty()) {
        if (bestKernel) bestKernel->clear();
        if (avgTps) *avgTps = 0;
        return false;
    }

    std::string chosen; double cTps = 0; bool found = false;
    for (const auto& [name, v] : stats) {
        if (!v.count) continue;
        double at = v.sumTps / v.count;
        if (!found || at > cTps) { found = true; chosen = name; cTps = at; }
=======
    struct KernelStats {
        double sumTps = 0.0;
        int count = 0;
    };
    
    const std::string key = hardwareKey();
    std::unordered_map<std::string, KernelStats> stats;
    
    for (const PerfRecord& rec : m_records) {
        if (rec.kernel.empty()) {
            continue;
        }
        if (!rec.hardware.empty() && rec.hardware != key) {
            continue;
        }
        if (!std::isfinite(rec.tps) || rec.tps <= 0.0) {
            continue;
        }
        
        KernelStats& entry = stats[rec.kernel];
        entry.sumTps += rec.tps;
        entry.count += 1;
    }
    
    if (stats.empty()) {
        if (bestKernel) {
            bestKernel->clear();
        }
        if (avgTps) {
            *avgTps = 0.0;
        }
        return false;
    }
    
    std::string chosen;
    double chosenTps = 0.0;
    bool found = false;
    
    for (const auto& [k, v] : stats) {
        if (!v.count) {
            continue;
        }
        const double avgT = v.sumTps / v.count;
        if (!found || avgT > chosenTps) {
            found = true;
            chosen = k;
            chosenTps = avgT;
        }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    
    if (!found) {
        if (bestKernel) bestKernel->clear();
        if (avgTps) *avgTps = 0;
        return false;
    }
<<<<<<< HEAD

    if (bestKernel) *bestKernel = chosen;
    if (avgTps) *avgTps = cTps;
=======
    
    if (bestKernel) {
        *bestKernel = chosen;
    }
    if (avgTps) {
        *avgTps = chosenTps;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}
