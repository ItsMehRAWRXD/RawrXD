#include "Deep2AuthorityGates.hpp"
#include <cassert>
#include <iostream>
using namespace Deep2::Authority;
int main() {
 std::vector<GGUFEntry> es={{"blk.0.ffn_gate_exps.weight",{128,32},12,0,256},{"blk.0.ffn_up_exps.weight",{128,32},12,256,256},{"blk.0.ffn_down_exps.weight",{128,32},14,512,256}};
 auto inv=AuthorityGates::discover(es); assert(inv.experts.size()==3);assert(AuthorityGates::experts(inv,128,1).ok);
 assert(AuthorityGates::physical(es,1024,128).ok);assert(!AuthorityGates::physical(es,700,128).ok);
 assert(AuthorityGates::quantization(es,{12,14}).ok);assert(!AuthorityGates::quantization(es,{12}).ok);
 assert(AuthorityGates::resources({10,20,30,40},{10,20,30,40}).ok);
 assert(!AuthorityGates::resources({11,20,30,40},{10,20,30,40}).ok);
 auto missing=es;missing.pop_back();assert(!AuthorityGates::experts(AuthorityGates::discover(missing),128,1).ok);
 auto dup=es;dup.push_back(es[0]);assert(!AuthorityGates::discover(dup).errors.empty());
 std::vector<GGUFEntry> indexed={{"model.layers.2.experts.3.w1.weight",{4,4},0,0,64},{"model.layers.2.experts.3.w2.weight",{4,4},0,64,64},{"model.layers.2.experts.3.w3.weight",{4,4},0,128,64}};
 assert(AuthorityGates::experts(AuthorityGates::discover(indexed),4,3).ok);
 Graph g;g.model_identity="sha256:model";g.tokenizer_identity="sha256:tokenizer";g.tensors={{"x",{2},DType::F32,0,8}};g.nodes={{"n",Op::SiLU,{"x"},"y",{2},DType::F32,"silu_v1",""}};
 std::vector<Capability> caps={{Op::SiLU,"silu_v1",DType::F32,true}};
 assert(AuthorityGates::graph(g,caps).ok);assert(!AuthorityGates::graph(g,{}).ok);
 auto fp=Validator::fingerprint(g);SessionContract session{fp,g.tokenizer_identity,1,{}};
 assert(AuthorityGates::session(session,g,1).ok);assert(!AuthorityGates::session(session,g,2).ok);
 assert(AuthorityGates::provenance(g,g.model_identity,g.tokenizer_identity).ok);
 assert(!AuthorityGates::provenance(g,"wrong",g.tokenizer_identity).ok);
 float a[2]={1,2};auto cert=Validator::compare(g,"reference",a,a,2,0,0);
 assert(AuthorityGates::certificate(g,cert,2).ok);assert(!AuthorityGates::certificate(g,cert,3).ok);
 assert(AuthorityGates::admission(g,cert,caps,{1,1,1,1},{2,2,2,2},2).ok);
 assert(!AuthorityGates::admission(g,cert,caps,{3,1,1,1},{2,2,2,2},2).ok);
 std::cout<<"AUTHORITY_GATES_01_15_PASS\n";
}
