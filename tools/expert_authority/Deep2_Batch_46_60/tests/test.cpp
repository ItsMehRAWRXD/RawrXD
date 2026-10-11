#include "ExpertAuthority.hpp"
#include <cassert>
#include <iostream>
int main(){using namespace deep2;std::vector<TensorRecord> a={{"blk.0.ffn_gate_exps.weight","Q5_0",100,128,true,true},{"blk.0.shexp.weight","Q4_K",50,128,true,false},{"blk.0.router.weight","F32",20,4,false,true},{"blk.0.attn.weight","F32",10,4,false,false}};auto r=analyze(a,180,128);assert(r.complete);assert(r.shape_count==2&&r.name_count==2&&r.intersection_count==1&&r.union_count==3);assert(r.union_bytes==170&&r.intersection_bytes==100);assert(r.dominant_dtype=="Q5_0");auto missing=analyze(a,181,128);assert(!missing.complete);std::cout<<"EXPERT_AUTHORITY_PASS\n";}
