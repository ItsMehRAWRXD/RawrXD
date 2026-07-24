//============================================================================
// nevm_kernel_provenance.cpp
// RawrXD N-EVM - Kernel Provenance Implementation
//============================================================================

#include "nevm_kernel_provenance.hpp"
#include <iostream>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Kernel Provenance
//============================================================================

Json::Value KernelProvenance::ToJSON() const {
    Json::Value prov;
    prov["compiler_name"] = compiler_name;
    prov["compiler_version"] = compiler_version;
    prov["compiler_flags"] = compiler_flags;
    prov["isa_path"] = isa_path;
    prov["registry_version"] = registry_version;
    prov["kernel_hash"] = kernel_hash;
    prov["build_timestamp"] = build_timestamp;
    prov["build_host"] = build_host;
    prov["git_commit"] = git_commit;
    prov["fma_enabled"] = fma_enabled;
    prov["avx512_enabled"] = avx512_enabled;
    prov["vnni_enabled"] = vnni_enabled;
    prov["bfloat16_enabled"] = bfloat16_enabled;
    return prov;
}

KernelProvenance KernelProvenance::FromJSON(const Json::Value& json) {
    KernelProvenance prov;
    prov.compiler_name = json.get("compiler_name", "").asString();
    prov.compiler_version = json.get("compiler_version", "").asString();
    prov.compiler_flags = json.get("compiler_flags", "").asString();
    prov.isa_path = json.get("isa_path", "").asString();
    prov.registry_version = json.get("registry_version", "").asString();
    prov.kernel_hash = json.get("kernel_hash", "").asString();
    prov.build_timestamp = json.get("build_timestamp", "").asString();
    prov.build_host = json.get("build_host", "").asString();
    prov.git_commit = json.get("git_commit", "").asString();
    prov.fma_enabled = json.get("fma_enabled", false).asBool();
    prov.avx512_enabled = json.get("avx512_enabled", false).asBool();
    prov.vnni_enabled = json.get("vnni_enabled", false).asBool();
    prov.bfloat16_enabled = json.get("bfloat16_enabled", false).asBool();
    return prov;
}

KernelProvenance KernelProvenance::DetectCurrent() {
    KernelProvenance prov;
    
    // Compiler detection
    #ifdef _MSC_VER
    prov.compiler_name = "MSVC";
    prov.compiler_version = std::to_string(_MSC_VER);
    #elif defined(__clang__)
    prov.compiler_name = "Clang";
    prov.compiler_version = std::to_string(__clang_major__) + "." +
                           std::to_string(__clang_minor__);
    #elif defined(__GNUC__)
    prov.compiler_name = "GCC";
    prov.compiler_version = std::to_string(__GNUC__) + "." +
                           std::to_string(__GNUC_MINOR__);
    #endif
    
    // ISA detection
    #ifdef __AVX512F__
    prov.isa_path = "AVX512";
    prov.avx512_enabled = true;
    #elif defined(__AVX2__)
    prov.isa_path = "AVX2";
    prov.avx512_enabled = false;
    #else
    prov.isa_path = "AVX";
    prov.avx512_enabled = false;
    #endif
    
    #ifdef __AVX512VNNI__
    prov.vnni_enabled = true;
    #endif
    
    #ifdef __FMA__
    prov.fma_enabled = true;
    #endif
    
    // Default registry version
    prov.registry_version = "1.0.0";
    
    return prov;
}

//============================================================================
// Provenance Registry
//============================================================================

void ProvenanceRegistry::Register(const std::string& kernel_name, const KernelProvenance& prov) {
    registry_[kernel_name] = prov;
}

KernelProvenance ProvenanceRegistry::Get(const std::string& kernel_name) const {
    auto it = registry_.find(kernel_name);
    if (it != registry_.end()) {
        return it->second;
    }
    return KernelProvenance();
}

bool ProvenanceRegistry::Has(const std::string& kernel_name) const {
    return registry_.find(kernel_name) != registry_.end();
}

Json::Value ProvenanceRegistry::ToJSON() const {
    Json::Value json;
    for (const auto& [name, prov] : registry_) {
        json[name] = prov.ToJSON();
    }
    return json;
}

void ProvenanceRegistry::FromJSON(const Json::Value& json) {
    registry_.clear();
    for (const auto& member : json.getMemberNames()) {
        registry_[member] = KernelProvenance::FromJSON(json[member]);
    }
}

bool ProvenanceRegistry::IsCompatible(const KernelProvenance& a, const KernelProvenance& b) {
    // Must match on critical properties
    if (a.isa_path != b.isa_path) return false;
    if (a.fma_enabled != b.fma_enabled) return false;
    if (a.avx512_enabled != b.avx512_enabled) return false;
    if (a.vnni_enabled != b.vnni_enabled) return false;
    if (a.bfloat16_enabled != b.bfloat16_enabled) return false;
    return true;
}

} // namespace NEVM
} // namespace RawrXD
