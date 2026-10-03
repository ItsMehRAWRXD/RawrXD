// KernelDictionaryAuthority.cpp — RAWRXD_KERNEL_DICTIONARY_AUTHORITY_001
#include "KernelDictionaryAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <vector>
#include <mutex>
namespace rawrxd { namespace kernels {
static std::mutex g_mutex;
static std::vector<KernelEntry> g_entries;
void registerKernel(const std::string& name, const std::string& isa, const std::string& backend) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_entries.push_back({name, isa, backend, true});
}
std::string resolveKernel(const std::string& quantType, const std::string& isa, const std::string& backend) {
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& e : g_entries) {
        if (e.name.find(quantType) != std::string::npos && e.isa == isa && e.backend == backend)
            return e.name;
    }
    return quantType + "_SCALAR"; // fallback
}
std::vector<KernelEntry> listAvailableKernels() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_entries;
}
void writeKernelDictionaryReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_KERNEL_DICTIONARY_AUTHORITY_001");
    auto entries = listAvailableKernels();
    int registered = 0;
    for (auto& e : entries) { if (e.registered) ++registered; }
    rawrxd::receipt::writeKeyValueInt(path, "KERNEL_COUNT", (int64_t)entries.size());
    rawrxd::receipt::writeKeyValueInt(path, "REGISTERED_COUNT", registered);
    for (auto& e : entries) {
        rawrxd::receipt::writeKeyValueInt(path, "KERNEL_" + e.name, e.registered ? 1 : 0);
    }
    rawrxd::receipt::endGate(path, registered > 0 ? "PASS" : "FAIL");
}
}} // namespace rawrxd::kernels