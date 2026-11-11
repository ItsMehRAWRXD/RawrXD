#include "Deep2Authority.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
using namespace Deep2::Authority;
int main() {
 Graph g; g.model_identity="model-sha256:example"; g.tokenizer_identity="tokenizer-sha256:example";
 g.tensors.push_back({"weight",{2,2},DType::F32,0,16});
 g.nodes.push_back({"mm",Op::MatMul,{"weight"},"hidden",{2,2},DType::F32,"matmul-f32-v1",{}});
 std::vector<Capability> caps={{Op::MatMul,"matmul-f32-v1",DType::F32,true}};
 auto r=Validator::validate(g,caps); assert(r.ok);
 float a[]={1,2,3,4}, b[]={1,2,3,4}; auto cert=Validator::compare(g,"reference:verified-run",a,b,4,0,0); assert(cert.passed);
 PlanAuthority authority; std::string reason; assert(authority.activate(g,cert,caps,reason));
 auto old=authority.snapshot(); assert(old && old->generation==1);
 Graph changed=g; changed.nodes[0].semantic_id="unknown";
 assert(!authority.activate(changed,cert,caps,reason)); assert(authority.snapshot()==old);
 Graph g2=g; g2.model_identity="new-model"; assert(!authority.activate(g2,cert,caps,reason));
 auto c2=Validator::compare(g2,"reference:verified-run",a,b,4,0,0); assert(authority.activate(g2,c2,caps,reason));
 assert(authority.snapshot()->generation==2 && old->generation==1);
 auto bad=Validator::compare(g,"reference:verified-run",a,b,4,0,0); assert(bad.passed);
 float c[]={1,2,3,8}; bad=Validator::compare(g,"reference:verified-run",c,b,4,0,0); assert(!bad.passed);
 float nan[]={1,2,3,NAN}; bad=Validator::compare(g,"reference:verified-run",nan,b,4,0,0); assert(!bad.passed);
 Graph broken=g; broken.nodes[0].inputs={"not_present"}; assert(!Validator::validate(broken,caps).ok);
 broken=g; broken.states.push_back({"kv",StateKind::KV,{2,0},DType::F32,1}); assert(!Validator::validate(broken,caps).ok);
 std::cout<<"authority tests passed\n";
}
