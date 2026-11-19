#include "deep2/GGUFLoader.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
using json=nlohmann::json;
static void dump(const char* tag, Deep2::GGUFLoader& l, const std::string& n){
 const auto*t=l.getTensor(n); std::cout<<tag<<" "<<n;
 if(!t){std::cout<<" MISSING\n";return;} std::cout<<" type="<<(int)t->type<<" bytes="<<t->sizeBytes<<" shape="; for(size_t i=0;i<t->shape.size();++i){if(i)std::cout<<"x";std::cout<<t->shape[i];} std::cout<<"\n";
}
static bool equalSlice(Deep2::GGUFTensor*a,Deep2::GGUFTensor*b,const std::vector<uint32_t>& ids){
 if(!a||!b||a->shape.empty()||b->shape.empty()||a->shape.back()<=0||b->shape.back()!=ids.size())return false;
 const size_t stride=a->sizeBytes/static_cast<size_t>(a->shape.back());
 if(b->sizeBytes!=stride*ids.size())return false;
 for(size_t j=0;j<ids.size();++j){if(ids[j]>=static_cast<uint32_t>(a->shape.back()))return false; if(std::memcmp(a->data+stride*ids[j],b->data+stride*j,stride)!=0)return false;} return true;
}
int main(int argc,char**argv){if(argc!=4){std::cerr<<"usage: gguf_reap_compare <original> <reduced> <selection.json>\n";return 2;} Deep2::GGUFLoader o,r; if(!o.load(argv[1])||!r.load(argv[2])){std::cerr<<"LOAD_FAIL original="<<o.error()<<" reduced="<<r.error()<<"\n";return 3;} json s;{std::ifstream f(argv[3]);f>>s;} std::cout<<"ORIGINAL_SHARDS="<<o.shardCount()<<" REDUCED_SHARDS="<<r.shardCount()<<"\n"; for(auto k:{"general.architecture","split.count","split.no","deepseek2.expert_count","deepseek2.expert_used_count","deepseek2.expert_feed_forward_length"}) std::cout<<k<<" original="<<o.getMetaInt(k,-1)<<" reduced="<<r.getMetaInt(k,-1)<<"\n"; std::cout<<"TOKENS_ORIG="<<o.getMetaInt("tokenizer.ggml.vocab_size",-1)<<" TOKENS_REDUCED="<<r.getMetaInt("tokenizer.ggml.vocab_size",-1)<<"\n"; std::vector<std::string> names={"blk.1.ffn_gate_inp.weight","blk.1.exp_probs_b.bias","blk.1.ffn_gate_exps.weight","blk.1.ffn_up_exps.weight","blk.1.ffn_down_exps.weight","blk.1.attn_q.weight","token_embd.weight","output.weight","output_norm.weight"}; for(auto&n:names){dump("O",o,n);dump("R",r,n);} bool all=true; int layers=0; for(const auto&x:s["layers"]){uint32_t layer=x.value("layer",9999);std::vector<uint32_t> ids;for(const auto&e:x["selected"])ids.push_back(e.value("expert",999999)); for(auto role:{"ffn_gate_inp.weight","exp_probs_b.bias","ffn_gate_exps.weight","ffn_up_exps.weight","ffn_down_exps.weight"}){std::string n="blk."+std::to_string(layer)+"."+role; auto*a=o.getTensor(n);auto*b=r.getTensor(n);if(a&&b){bool ok=equalSlice(a,b,ids);if(!ok){std::cout<<"SLICE_MISMATCH layer="<<layer<<" tensor="<<n<<"\n";all=false;}}}++layers;} std::cout<<"LAYERS_CHECKED="<<layers<<" SLICE_CHECK="<<(all?"PASS":"FAIL")<<"\n"; return all?0:4;}
