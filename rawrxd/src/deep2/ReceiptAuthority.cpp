// ReceiptAuthority.cpp — RAWRXD_RECEIPT_AUTHORITY_001
#include "ReceiptAuthority.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <mutex>

namespace rawrxd { namespace receipt {

static std::mutex g_receiptMutex;

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