#include "RuntimeIRBridge.hpp"
#include <cassert>
#include <iostream>
using namespace deep2bridge;
int main(){
 std::vector<Tensor> t;
 std::vector<Block> b;
 for(unsigned l=0;l<27;l++){
  const auto pre="blk."+std::to_string(l)+".";
  std::vector<std::string> names;
  auto add=[&](const std::string& suffix){
   std::string n=pre+suffix;names.push_back(n);
   t.push_back({n,12,{32,32},static_cast<std::uint64_t>(t.size())*4096,4096,true});
  };
  add("attn_q.weight");
  if(l==0){add("ffn_up.weight");b.push_back({l,BlockKind::DenseMLA,names});}
  else {add("ffn_gate_inp.weight");add("ffn_up_exps.weight");add("ffn_down_exps.weight");add("ffn_up_shexp.weight");b.push_back({l,BlockKind::MoEMLA,names});}
 }
 auto p=build(t,b,1000000,true,true,false);
 assert(p.final_handle==p.nodes.back().output);
 unsigned dense=0,moe=0;
 for(auto& n:p.nodes){dense+=n.op==Op::DenseFFN;moe+=n.op==Op::Experts;}
 assert(dense==1&&moe==26);
 bool rejected=false;
 try{build(t,b,1000000,true,false,false);}catch(const std::runtime_error&){rejected=true;}
 assert(rejected);
 auto broken=b;broken[1].tensor_names.pop_back(); // still valid MoE without shared expert
 auto q=build(t,broken,1000000,true,true,false);
 assert(q.nodes.size()<p.nodes.size());
 auto missing=b;missing[1].tensor_names={"blk.1.missing"};
 rejected=false;try{build(t,missing,1000000,true,true,false);}catch(const std::runtime_error&){rejected=true;}
 assert(rejected);
 auto invalid=t;invalid[0].bytes=10000000;
 rejected=false;try{build(invalid,b,1000000,true,true,false);}catch(const std::runtime_error&){rejected=true;}
 assert(rejected);
 std::cout<<"DEEP2_RUNTIME_IR_BRIDGE_PASS layers=27 dense=1 moe=26 nodes="<<p.nodes.size()<<"\n";
}
