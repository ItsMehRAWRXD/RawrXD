#pragma once
#include "Deep2Authority.hpp"
#include <cstdint>
#include <string>
#include <vector>
namespace Deep2::Authority {
// External adapters must supply parsed GGUF metadata/tensors. No inferred semantics are certified.
struct GGUFEntry { std::string name; std::vector<uint64_t> dimensions; uint32_t ggml_type=0; uint64_t offset=0, bytes=0; };
struct ExpertBinding { uint32_t layer=0, expert=0; bool packed=false; std::string role, tensor; };
struct Inventory { std::vector<ExpertBinding> experts; std::vector<std::string> unknown; std::vector<std::string> errors; };
struct MemoryBudget { uint64_t host_bytes=0, device_bytes=0, state_bytes=0, scratch_bytes=0; };
struct ResourceLimits { uint64_t max_host=0, max_device=0, max_state=0, max_scratch=0; };
struct SessionContract { uint64_t plan_fingerprint=0; std::string tokenizer_identity; uint32_t state_abi=0; std::vector<StateSpec> states; };
struct GateResult { bool ok=false; std::vector<std::string> failures; };
class AuthorityGates {
public:
 // 01-04: tensor inventory, expert discovery, role completeness, physical ranges.
 static Inventory discover(const std::vector<GGUFEntry>& entries);
 static GateResult physical(const std::vector<GGUFEntry>& entries, uint64_t file_bytes, uint64_t data_start);
 static GateResult experts(const Inventory& inventory, uint32_t expected_experts, uint32_t expected_layers);
 // 05-07: shape / graph / operator checks (shape and semantics are delegated to explicit rules).
 static GateResult graph(const Graph& g, const std::vector<Capability>& capabilities);
 // 08-10: state ABI, plan identity, active session compatibility.
 static GateResult session(const SessionContract& old_session, const Graph& next, uint32_t next_abi);
 // 11-12: budget and quantization admission.
 static GateResult resources(const MemoryBudget& required, const ResourceLimits& limits);
 static GateResult quantization(const std::vector<GGUFEntry>& entries, const std::vector<uint32_t>& supported_types);
 // 13-15: provenance, reference certificate, activation admission.
 static GateResult provenance(const Graph& g, const std::string& model_digest, const std::string& tokenizer_digest);
 static GateResult certificate(const Graph& g, const Certificate& cert, uint64_t minimum_elements);
 static GateResult admission(const Graph& g, const Certificate& cert, const std::vector<Capability>& caps, const MemoryBudget& required, const ResourceLimits& limits, uint64_t minimum_elements);
};
}
