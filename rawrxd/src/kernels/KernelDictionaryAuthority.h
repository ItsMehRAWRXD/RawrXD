// KernelDictionaryAuthority.h — RAWRXD_KERNEL_DICTIONARY_AUTHORITY_001
#pragma once
#include <string>
#include <vector>
namespace rawrxd { namespace kernels {
struct KernelEntry { std::string name; std::string isa; std::string backend; bool registered; };
void registerKernel(const std::string& name, const std::string& isa, const std::string& backend);
std::string resolveKernel(const std::string& quantType, const std::string& isa, const std::string& backend);
std::vector<KernelEntry> listAvailableKernels();
void writeKernelDictionaryReceipt(const std::string& path);
}} // namespace rawrxd::kernels