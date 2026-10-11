#include "Deep2TensorIdentity.hpp"
#include <cassert>
#include <cstdint>
#include <limits>
#include <iostream>
using namespace Deep2::Authority;
int main() {
  // Same numeric code 10 is Q4_K in the old GGUF header but Q2_K in canonical GGML.
  assert(canonical_type(10,TypeDialect::LegacyGGUFHeader)==12);
  assert(canonical_type(10,TypeDialect::CanonicalGGML)==10);
  assert(canonical_type(16,TypeDialect::EngineCommonHeader)==12);
  assert(!canonical_type(99,TypeDialect::CanonicalGGML));
  auto a=adapt("blk.0.ffn_gate_exps.weight",{256,128},10,TypeDialect::LegacyGGUFHeader,4096,32768,SourceABI::LegacyGGUF);
  assert(a && a->canonical_type==12 && a->dimensions[1]==128);
  auto b=make_absolute(*a,8192,65536);assert(b && b->offset==12288);
  assert(!make_absolute(*a,65500,65536));
  assert(!adapt("x",{0,2},0,TypeDialect::CanonicalGGML,0,16,SourceABI::Deep2Reader));
  assert(!adapt("x",{std::numeric_limits<std::uint64_t>::max(),2},0,TypeDialect::CanonicalGGML,0,16,SourceABI::Deep2Reader));
  assert(!adapt("x",{2},0,TypeDialect::CanonicalGGML,std::numeric_limits<std::uint64_t>::max(),16,SourceABI::Deep2Reader));
  std::cout<<"DEEP2_TENSOR_IDENTITY_76_90_PASS\n";
}
