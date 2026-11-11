#pragma once
// Deep2 runtime execution-IR construction, C++20, no third-party dependencies.
// Adapter contract: feed tensors/blocks from the validated GGUF directory and
// architecture classifier; this module never guesses missing model semantics.
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <limits>
#include <algorithm>
namespace deep2bridge {
enum class BlockKind { DenseMLA, MoEMLA, DenseAttention, MoEAttention, SSM, SSMMoE };
enum class Op { Input, Norm, MLA, Attention, DenseFFN, Router, TopK, Experts, SharedExperts, Combine, SSMScan, Residual, Output };
struct Tensor {
 std::string name;
 std::uint32_t dtype{};
 std::vector<std::uint64_t> dims;
 std::uint64_t offset{}, bytes{};
 bool kernel_ready{};
};
struct Block { std::uint32_t layer{}; BlockKind kind{}; std::vector<std::string> tensor_names; };
struct Node {
 Op op{};
 std::uint32_t layer{};
 std::vector<std::uint32_t> inputs;
 std::vector<std::uint32_t> tensor_handles;
 std::uint32_t output{};
};
struct Plan {
 std::vector<Tensor> tensors;
 std::vector<Node> nodes;
 std::uint32_t final_handle{};
};
inline bool has(const std::string& s,const char* suffix) {
 return s.find(suffix)!=std::string::npos;
}
inline Plan build(const std::vector<Tensor>& directory,
                  const std::vector<Block>& blocks,
                  std::uint64_t file_size,
                  bool has_mla_kernel,
                  bool has_moe_kernel,
                  bool has_ssm_kernel) {
 if(directory.empty()||blocks.empty()) throw std::runtime_error("empty directory or blocks");
 Plan p; p.tensors=directory;
 std::unordered_map<std::string,std::uint32_t> index;
 for(std::size_t i=0;i<directory.size();++i) {
  const auto& t=directory[i];
  if(t.name.empty()||t.dims.empty()||t.bytes==0||t.offset>file_size||t.bytes>file_size-t.offset)
   throw std::runtime_error("invalid tensor descriptor: "+t.name);
  for(auto d:t.dims) if(!d) throw std::runtime_error("zero tensor dimension: "+t.name);
  if(!index.emplace(t.name,static_cast<std::uint32_t>(i)).second)
   throw std::runtime_error("duplicate tensor: "+t.name);
 }
 std::uint32_t next=1, prev=0;
 auto emit=[&](Op op,std::uint32_t layer,const std::vector<std::uint32_t>& tensors){
  Node n; n.op=op;n.layer=layer;n.inputs={prev};n.tensor_handles=tensors;n.output=next++;
  p.nodes.push_back(n);prev=n.output;
 };
 emit(Op::Input,0,{});
 for(std::size_t i=0;i<blocks.size();++i) {
  const auto& b=blocks[i];
  if(b.layer!=i) throw std::runtime_error("noncontiguous layer ordering");
  std::vector<std::uint32_t> all, router, experts, shared, dense;
  for(const auto& name:b.tensor_names) {
   auto it=index.find(name);
   if(it==index.end()) throw std::runtime_error("missing tensor: "+name);
   const auto& t=directory[it->second];
   if(!t.kernel_ready) throw std::runtime_error("missing dtype kernel: "+name);
   all.push_back(it->second);
   if(has(name,"shexp")) shared.push_back(it->second);
   else if(has(name,"ffn_gate_inp")||has(name,"exp_probs")) router.push_back(it->second);
   else if(has(name,"_exps")) experts.push_back(it->second);
   else if(has(name,"ffn_")) dense.push_back(it->second);
  }
  if(all.empty()) throw std::runtime_error("layer has no bound tensors");
  const bool moe=b.kind==BlockKind::MoEMLA||b.kind==BlockKind::MoEAttention||b.kind==BlockKind::SSMMoE;
  const bool mla=b.kind==BlockKind::DenseMLA||b.kind==BlockKind::MoEMLA;
  const bool ssm=b.kind==BlockKind::SSM||b.kind==BlockKind::SSMMoE;
  if(mla&&!has_mla_kernel) throw std::runtime_error("MLA kernel unavailable");
  if(ssm&&!has_ssm_kernel) throw std::runtime_error("SSM scan kernel unavailable");
  if(moe&&!has_moe_kernel) throw std::runtime_error("MoE kernel unavailable");
  if(moe&&(router.empty()||experts.empty()))
   throw std::runtime_error("MoE layer missing router or routed experts");
  if(!moe&&dense.empty()) throw std::runtime_error("dense layer missing FFN tensors");
  emit(Op::Norm,b.layer,all);
  emit(ssm?Op::SSMScan:mla?Op::MLA:Op::Attention,b.layer,all);
  emit(Op::Residual,b.layer,{});
  if(moe) {
   emit(Op::Router,b.layer,router);
   emit(Op::TopK,b.layer,router);
   emit(Op::Experts,b.layer,experts);
   if(!shared.empty()) emit(Op::SharedExperts,b.layer,shared);
   emit(Op::Combine,b.layer,{});
  } else emit(Op::DenseFFN,b.layer,dense);
  emit(Op::Residual,b.layer,{});
 }
 emit(Op::Output,static_cast<std::uint32_t>(blocks.size()),{});
 p.final_handle=prev;
 return p;
}
} // namespace deep2bridge
