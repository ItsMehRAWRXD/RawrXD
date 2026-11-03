#include "streaming_gguf_loader.h"
#include <iostream>
#include <string>
int main(int argc,char**argv){if(argc<2)return 2; StreamingGGUFLoader l; if(!l.Open(argv[1]))return 3; auto*qref=l.GetTensorInfo("blk.0.attn_q.weight"); auto qcopy=qref?*qref:RawrXD::TensorInfo{}; auto*kref=l.GetTensorInfo("blk.0.attn_k.weight"); auto kcopy=kref?*kref:RawrXD::TensorInfo{}; std::cout<<"DIRECT_Q="; for(auto d:qcopy.shape)std::cout<<d<<","; std::cout<<" DIRECT_K="; for(auto d:kcopy.shape)std::cout<<d<<","; std::cout<<"\n"; int n=0; for(const auto&t:l.GetTensorInfo()){if(t.name.rfind("blk.0.",0)==0||t.name=="token_embd.weight"||t.name=="output.weight"||t.name=="output_norm.weight"){std::cout<<t.name<<" type="<<static_cast<int>(t.type)<<" shape=";for(auto d:t.shape)std::cout<<d<<",";std::cout<<" off="<<t.offset<<" bytes="<<t.size<<"\n";if(++n>80)break;}} return 0;}



