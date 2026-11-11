#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
namespace deep2 {
struct ModelSpec {
 std::string architecture, path;
 uint64_t blocks=0, embedding=0, experts=0, experts_used=0;
 std::vector<uint32_t> tensor_types;
};
struct ComputeContract {
 std::string architecture;
 std::vector<std::string> required_ops;
 std::vector<uint32_t> supported_tensor_types;
 uint32_t abi_version=1;
};
struct ComputeHooks {
 // Hook functions must execute real work and return false on failure.
 std::function<bool(void*, uint64_t)> execute_token;
 std::function<bool(void*)> initialize;
 std::function<void(void*)> shutdown;
};
struct Plugin {
 std::string name, version;
 ComputeContract contract;
 ComputeHooks hooks;
};
struct SessionBinding {
 std::shared_ptr<const Plugin> plugin;
 ModelSpec model;
 bool valid() const { return bool(plugin); }
};
class Registry {
 mutable std::mutex mu_;
 std::unordered_map<std::string,std::shared_ptr<const Plugin>> active_;
public:
 bool install(Plugin plugin, std::string& error);
 SessionBinding bind(const ModelSpec& spec, const std::vector<std::string>& available_ops, std::string& error) const;
};
// GGUF metadata inspection; no tensor materialization, no network, no external deps.
bool inspect_gguf(const std::string& path, ModelSpec& spec, std::string& error);
// Bind before streaming or executing any model token; callback adapter is supplied by Deep2.
bool execute_checked(const SessionBinding& binding, void* runtime, uint64_t token, std::string& error);
}
