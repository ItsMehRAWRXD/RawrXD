#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace Deep2::Authority {
enum class DType : uint8_t { F32, F16, BF16, Q4_0, Q4_K, Q6_K, Unknown };
enum class Op : uint8_t { Embedding, RMSNorm, MatMul, RoPE, Attention, SiLU, Add, Multiply, Softmax, MoERoute, MoECombine, StateRead, StateWrite };
enum class StateKind : uint8_t { KV, SSM, Convolution };
struct Tensor { std::string name; std::vector<uint64_t> shape; DType dtype=DType::Unknown; uint64_t byte_offset=0, byte_size=0; };
struct Node { std::string id; Op op; std::vector<std::string> inputs; std::string output; std::vector<uint64_t> output_shape; DType output_dtype=DType::F32; std::string semantic_id; std::string state_id; };
struct StateSpec { std::string id; StateKind kind; std::vector<uint64_t> shape; DType dtype; uint32_t version=1; };
struct Graph { std::string model_identity; std::string tokenizer_identity; std::vector<Tensor> tensors; std::vector<Node> nodes; std::vector<StateSpec> states; };
struct Capability { Op op; std::string semantic_id; DType dtype; bool verified=false; };
struct Report { bool ok=false; std::vector<std::string> errors; uint64_t fingerprint=0; };
struct Certificate { uint64_t graph_fingerprint=0; std::string reference_identity; uint64_t compared_elements=0; double max_abs_error=0, max_rel_error=0; bool passed=false; };
class Validator {
public:
 static Report validate(const Graph& graph, const std::vector<Capability>& capabilities);
 static uint64_t fingerprint(const Graph& graph);
 static Certificate compare(const Graph& graph, const std::string& reference_identity, const float* actual, const float* reference, size_t count, double atol, double rtol);
};
struct Plan { Graph graph; Certificate certificate; uint64_t generation=0; };
class PlanAuthority {
 mutable std::mutex mu_;
 std::shared_ptr<const Plan> active_;
 uint64_t next_generation_=1;
public:
 std::shared_ptr<const Plan> snapshot() const;
 bool activate(Graph graph, Certificate certificate, const std::vector<Capability>& capabilities, std::string& reason);
};
}
