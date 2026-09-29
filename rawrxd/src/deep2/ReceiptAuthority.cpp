// ReceiptAuthority.cpp — RAWRXD_RECEIPT_AUTHORITY_001
// RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001
#include "ReceiptAuthority.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <mutex>
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <atomic>
#include <windows.h>
#include <bcrypt.h>

namespace rawrxd { namespace receipt {

static std::mutex g_receiptMutex;
static std::atomic<uint64_t> g_runCounter{0};

// === SHA256 computation using Windows BCrypt ===
std::string sha256File(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buf),
                       static_cast<ULONG>(f.gcount()), 0);
    }

    UCHAR hash[32];
    BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (int i = 0; i < 32; ++i) oss << std::setw(2) << (int)hash[i];
    return oss.str();
}

// === Immutable per-run receipt API ===

static std::string getUtcTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm);
    return std::string(buf);
}

std::string beginImmutableGate(const std::string& gateName) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);

    // Generate run path: receipts/<gateName>/runs/<UTC>_<PID>_<counter>.ini
    std::string utc = getUtcTimestamp();
    DWORD pid = GetCurrentProcessId();
    uint64_t runId = g_runCounter.fetch_add(1);

    std::filesystem::path baseDir = std::filesystem::current_path() / "receipts" / gateName;
    std::filesystem::path runsDir = baseDir / "runs";
    std::error_code ec;
    std::filesystem::create_directories(runsDir, ec);

    std::ostringstream nameStream;
    nameStream << utc << "_PID" << pid << "_RUN" << runId << ".ini";
    std::filesystem::path runPath = runsDir / nameStream.str();

    // CREATE_NEW semantics: fail if file already exists
    HANDLE hFile = CreateFileA(runPath.string().c_str(),
        GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return {};  // file already exists — immutable violation
    }
    CloseHandle(hFile);

    // Write GATE header
    FILE* f = nullptr;
    fopen_s(&f, runPath.string().c_str(), "w");
    if (!f) return {};
    std::fprintf(f, "GATE=%s\n", gateName.c_str());
    std::fprintf(f, "RECEIPT_SCHEMA_VERSION=1\n");
    std::fprintf(f, "RUN_ID=%llu\n", (unsigned long long)runId);
    std::fclose(f);

    // Update latest.txt (mutable pointer — allowed to overwrite)
    std::filesystem::path latestPath = baseDir / "latest.txt";
    std::ofstream latest(latestPath);
    if (latest.is_open()) {
        latest << runPath.string() << std::endl;
        latest.close();
    }

    // Append to index.jsonl (append-only)
    std::filesystem::path indexPath = baseDir / "index.jsonl";
    std::ofstream index(indexPath, std::ios::app);
    if (index.is_open()) {
        index << "{\"run_id\":" << runId
              << ",\"pid\":" << pid
              << ",\"utc\":\"" << utc << "\""
              << ",\"path\":\"" << runPath.string() << "\""
              << ",\"gate\":\"" << gateName << "\""
              << "}" << std::endl;
        index.close();
    }

    return runPath.string();
}

void writeImmutableKeyValue(const std::string& runPath, const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);
    FILE* f = nullptr;
    fopen_s(&f, runPath.c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s=%s\n", key.c_str(), value.c_str());
    std::fclose(f);
}

void writeImmutableKeyValueInt(const std::string& runPath, const std::string& key, int64_t value) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);
    FILE* f = nullptr;
    fopen_s(&f, runPath.c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s=%lld\n", key.c_str(), (long long)value);
    std::fclose(f);
}

void writeImmutableKeyValueFloat(const std::string& runPath, const std::string& key, double value) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);
    FILE* f = nullptr;
    fopen_s(&f, runPath.c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s=%.6f\n", key.c_str(), value);
    std::fclose(f);
}

std::string endImmutableGate(const std::string& runPath, const std::string& verdict) {
    // Write VERDICT line
    writeImmutableKeyValue(runPath, "VERDICT", verdict);

    // Compute SHA256 of the receipt
    std::string hash = sha256File(runPath);
    if (!hash.empty()) {
        writeImmutableKeyValue(runPath, "RECEIPT_SHA256", hash);
    }

    // Update latest.txt with final pointer
    std::filesystem::path runPathObj(runPath);
    std::filesystem::path baseDir = runPathObj.parent_path().parent_path();
    std::filesystem::path latestPath = baseDir / "latest.txt";
    std::ofstream latest(latestPath);
    if (latest.is_open()) {
        latest << runPath << std::endl;
        latest.close();
    }

    return hash;
}

// === Legacy fixed-path API (still available but not for new gates) ===

void writeKeyValue(const std::string& path, const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s=%s\n", key.c_str(), value.c_str());
    std::fclose(f);
}

void writeKeyValueInt(const std::string& path, const std::string& key, int64_t value) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s=%lld\n", key.c_str(), (long long)value);
    std::fclose(f);
}

void writeKeyValueFloat(const std::string& path, const std::string& key, double value) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s=%.6f\n", key.c_str(), value);
    std::fclose(f);
}

void beginGate(const std::string& path, const std::string& gateName) {
    std::lock_guard<std::mutex> lock(g_receiptMutex);
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "w");  // truncate at begin
    if (!f) return;
    std::fprintf(f, "GATE=%s\n", gateName.c_str());
    std::fclose(f);
}

void endGate(const std::string& path, const std::string& verdict) {
    writeKeyValue(path, "VERDICT", verdict);
}

}} // namespace rawrxd::receipt