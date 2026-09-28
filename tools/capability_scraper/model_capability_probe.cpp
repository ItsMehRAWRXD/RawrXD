// RAWRXD_MODEL_CAPABILITY_SCRAPER_001
// Standalone GGUF capability probe. C++17, source-only, no third-party deps.
// Read-only model inspection; does not initialize Deep2, Vulkan, shaders, or runtime paths.
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <filesystem>
#include <limits>

namespace {
enum VT : uint32_t { U8=0,I8=1,U16=2,I16=3,U32=4,I32=5,F32=6,BOOL=7,STR=8,ARR=9,U64=10,I64=11,F64=12 };

struct R {
    std::ifstream f;
    explicit R(const char* p):f(p,std::ios::binary){}
    template<class T> bool read(T& x){ f.read(reinterpret_cast<char*>(&x),sizeof(T)); return !!f; }
    bool skip(uint64_t n){ if(n > uint64_t(std::numeric_limits<std::streamoff>::max())) return false; f.seekg((std::streamoff)n,std::ios::cur); return !!f; }
    bool str(std::string& s, bool keep=true){ uint64_t n=0; if(!read(n)) return false; if(n>(1ull<<30)) return false; if(!keep) return skip(n); s.resize((size_t)n); if(n) f.read(s.data(),(std::streamsize)n); return !!f; }
};

struct V { bool text=false,uns=false,sig=false,flt=false,array=false; std::string s; uint64_t u=0,n=0; int64_t i=0; double d=0; uint32_t elem=0; };

static bool skipVal(R& r,uint32_t t,V* cap=nullptr){
    switch(t){
        case U8:{uint8_t x; if(!r.read(x))return false; if(cap){cap->uns=true;cap->u=x;} return true;}
        case I8:{int8_t x; if(!r.read(x))return false; if(cap){cap->sig=true;cap->i=x;} return true;}
        case U16:{uint16_t x; if(!r.read(x))return false; if(cap){cap->uns=true;cap->u=x;} return true;}
        case I16:{int16_t x; if(!r.read(x))return false; if(cap){cap->sig=true;cap->i=x;} return true;}
        case U32:{uint32_t x; if(!r.read(x))return false; if(cap){cap->uns=true;cap->u=x;} return true;}
        case I32:{int32_t x; if(!r.read(x))return false; if(cap){cap->sig=true;cap->i=x;} return true;}
        case F32:{float x; if(!r.read(x))return false; if(cap){cap->flt=true;cap->d=x;} return true;}
        case BOOL:{uint8_t x; if(!r.read(x))return false; if(cap){cap->uns=true;cap->u=x?1:0;} return true;}
        case STR:{std::string s; if(!r.str(s,cap!=nullptr))return false; if(cap){cap->text=true;cap->s=std::move(s);} return true;}
        case U64:{uint64_t x; if(!r.read(x))return false; if(cap){cap->uns=true;cap->u=x;} return true;}
        case I64:{int64_t x; if(!r.read(x))return false; if(cap){cap->sig=true;cap->i=x;} return true;}
        case F64:{double x; if(!r.read(x))return false; if(cap){cap->flt=true;cap->d=x;} return true;}
        case ARR:{
            uint32_t e=0; uint64_t n=0; if(!r.read(e)||!r.read(n)||n>(1ull<<34))return false;
            if(cap){cap->array=true;cap->elem=e;cap->n=n;}
            for(uint64_t k=0;k<n;++k) if(!skipVal(r,e,nullptr)) return false;
            return true;
        }
        default:return false;
    }
}

static std::string lo(std::string s){ for(char& c:s) if(c>='A'&&c<='Z') c=char(c-'A'+'a'); return s; }
static bool has(const std::string& s,const char* n){ return lo(s).find(lo(std::string(n)))!=std::string::npos; }
static uint64_t asU(const V& v){ if(v.uns)return v.u; if(v.sig&&v.i>=0)return (uint64_t)v.i; return 0; }
static double asD(const V& v){ if(v.flt)return v.d; if(v.uns)return (double)v.u; if(v.sig)return (double)v.i; return 0.0; }
static const char* qname(uint32_t t){
    switch(t){case 0:return"F32";case 1:return"F16";case 2:return"Q4_0";case 3:return"Q4_1";case 6:return"Q5_0";case 7:return"Q5_1";case 8:return"Q8_0";case 9:return"Q8_1";case 10:return"Q2_K";case 11:return"Q3_K";case 12:return"Q4_K";case 13:return"Q5_K";case 14:return"Q6_K";case 15:return"Q8_K";case 16:return"IQ2_XXS";case 17:return"IQ2_XS";case 18:return"IQ3_XXS";case 19:return"IQ1_S";case 20:return"IQ4_NL";case 21:return"IQ3_S";case 22:return"IQ2_S";case 23:return"IQ4_XS";case 29:return"IQ1_M";case 30:return"BF16";case 34:return"TQ1_0";case 35:return"TQ2_0";default:return"TYPE";}
}
}

int main(int argc,char** argv){
    if(argc<2){ std::fprintf(stderr,"usage: model_capability_probe.exe <model.gguf>\n"); return 2; }
    R r(argv[1]); if(!r.f){ std::fprintf(stderr,"ERROR=OPEN_FAILED\n"); return 3; }
    uint32_t magic=0,ver=0; uint64_t nt=0,nkv=0;
    if(!r.read(magic)||magic!=0x46554747u||!r.read(ver)||!r.read(nt)||!r.read(nkv)){ std::fprintf(stderr,"ERROR=INVALID_GGUF\n"); return 4; }
    if(ver<2||ver>3||nt>10000000ull||nkv>10000000ull){ std::fprintf(stderr,"ERROR=UNSUPPORTED_OR_CORRUPT\n"); return 5; }

    std::string arch="unknown",name,ropeScale;
    uint64_t context=0,emb=0,blocks=0,ffn=0,heads=0,kvheads=0,ropeDim=0,experts=0,expertsUsed=0,vocab=0;
    double ropeBase=0.0;
    bool chat=false, ssmMeta=false, mlaMeta=false;
    std::map<std::string,V> deferred;

    for(uint64_t m=0;m<nkv;++m){
        std::string k; uint32_t t=0; if(!r.str(k)||!r.read(t)){std::fprintf(stderr,"ERROR=META_TRUNCATED\n");return 6;}
        bool interesting = k=="general.architecture" || k=="general.name" || k=="tokenizer.chat_template" || k=="tokenizer.ggml.tokens" ||
                           has(k,"context_length") || has(k,"embedding_length") || has(k,"block_count") || has(k,"feed_forward_length") ||
                           has(k,"attention.head_count") || has(k,"rope.dimension_count") || has(k,"rope.freq_base") || has(k,"rope.scaling.type") ||
                           has(k,"expert_count") || has(k,"expert_used_count") || has(k,"ssm") || has(k,"state_size") || has(k,"q_lora_rank") || has(k,"kv_lora_rank");
        V v; if(!skipVal(r,t,interesting?&v:nullptr)){std::fprintf(stderr,"ERROR=META_VALUE key=%s type=%u\n",k.c_str(),t);return 7;}
        if(!interesting) continue;
        if(k=="general.architecture"&&v.text) arch=v.s;
        else if(k=="general.name"&&v.text) name=v.s;
        else if(k=="tokenizer.chat_template") chat=true;
        else if(k=="tokenizer.ggml.tokens"&&v.array) vocab=v.n;
        else deferred.emplace(k,std::move(v));
        if(has(k,"ssm")||has(k,"state_size")) ssmMeta=true;
        if(has(k,"q_lora_rank")||has(k,"kv_lora_rank")) mlaMeta=true;
    }

    std::string p=arch+".";
    auto get=[&](const std::string& suffix)->V{ auto it=deferred.find(p+suffix); return it==deferred.end()?V{}:it->second; };
    context=asU(get("context_length")); emb=asU(get("embedding_length")); blocks=asU(get("block_count")); ffn=asU(get("feed_forward_length"));
    heads=asU(get("attention.head_count")); kvheads=asU(get("attention.head_count_kv")); ropeDim=asU(get("rope.dimension_count")); ropeBase=asD(get("rope.freq_base"));
    {V x=get("rope.scaling.type"); if(x.text) ropeScale=x.s;}
    experts=asU(get("expert_count")); expertsUsed=asU(get("expert_used_count"));

    std::map<uint32_t,uint64_t> qc;
    bool expTensor=false,router=false,ssmTensor=false,conv=false,state=false,qnorm=false,knorm=false,embTensor=false,outTensor=false;
    for(uint64_t i=0;i<nt;++i){
        std::string n; uint32_t nd=0,t=0; uint64_t off=0;
        if(!r.str(n)||!r.read(nd)||nd>16){std::fprintf(stderr,"ERROR=TENSOR_INFO\n");return 8;}
        for(uint32_t d=0;d<nd;++d){uint64_t x; if(!r.read(x))return 9;}
        if(!r.read(t)||!r.read(off))return 10; qc[t]++;
        std::string x=lo(n);
        expTensor |= x.find("expert")!=std::string::npos || x.find(".exp")!=std::string::npos;
        router |= x.find("router")!=std::string::npos || x.find("ffn_gate_inp")!=std::string::npos;
        ssmTensor |= x.find("ssm")!=std::string::npos || x.find("mamba")!=std::string::npos;
        conv |= x.find("conv1d")!=std::string::npos || x.find("ssm_conv")!=std::string::npos;
        state |= x.find("ssm_a")!=std::string::npos || x.find("state")!=std::string::npos;
        qnorm |= x.find("q_norm")!=std::string::npos; knorm |= x.find("k_norm")!=std::string::npos;
        embTensor |= x=="token_embd.weight" || x.find("embed_tokens.weight")!=std::string::npos;
        outTensor |= x=="output.weight" || x.find("lm_head")!=std::string::npos;
    }

    bool moe=experts>0||expTensor||router; bool ssm=ssmMeta||ssmTensor||conv||state; bool gqa=heads&&kvheads&&kvheads<heads;
    uint64_t size=0; try{size=std::filesystem::file_size(argv[1]);}catch(...){ }

    std::printf("GATE=RAWRXD_MODEL_CAPABILITY_SCRAPER_001\nAUTHORITY=MODEL_FILE_ONLY\nRUNTIME_CAPABILITY_JUDGMENT=0\nTPS_JUDGMENT=0\nKERNEL_SUPPORT_JUDGMENT=0\n");
    std::printf("FILE_BYTES=%llu\nGGUF_VERSION=%u\nMETADATA_COUNT=%llu\nTENSOR_COUNT=%llu\n",(unsigned long long)size,ver,(unsigned long long)nkv,(unsigned long long)nt);
    std::printf("MODEL_ARCH=%s\nMODEL_NAME=%s\n",arch.c_str(),name.empty()?"UNKNOWN":name.c_str());
    std::printf("CONTEXT_LENGTH=%llu\nEMBEDDING_LENGTH=%llu\nBLOCK_COUNT=%llu\nFEED_FORWARD_LENGTH=%llu\nATTENTION_HEADS=%llu\nATTENTION_KV_HEADS=%llu\nGQA_PRESENT=%u\nGQA_RATIO=%llu\n",(unsigned long long)context,(unsigned long long)emb,(unsigned long long)blocks,(unsigned long long)ffn,(unsigned long long)heads,(unsigned long long)kvheads,gqa?1:0,(unsigned long long)((gqa&&kvheads)?heads/kvheads:0));
    std::printf("ROPE_DIMENSION_COUNT=%llu\nROPE_FREQ_BASE=%.9g\nROPE_SCALING_TYPE=%s\n",(unsigned long long)ropeDim,ropeBase,ropeScale.empty()?"UNKNOWN":ropeScale.c_str());
    std::printf("VOCAB_SIZE=%llu\nCHAT_TEMPLATE_PRESENT=%u\nTOKEN_EMBEDDING_PRESENT=%u\nOUTPUT_WEIGHT_PRESENT=%u\n",(unsigned long long)vocab,chat?1:0,embTensor?1:0,outTensor?1:0);
    std::printf("MOE_STRUCTURE_PRESENT=%u\nEXPERT_COUNT=%llu\nEXPERTS_USED_PER_TOKEN=%llu\nROUTER_TENSOR_PRESENT=%u\n",moe?1:0,(unsigned long long)experts,(unsigned long long)expertsUsed,router?1:0);
    std::printf("SSM_STRUCTURE_PRESENT=%u\nSSM_CONVOLUTION_PRESENT=%u\nSSM_STATE_TENSOR_PRESENT=%u\nMLA_METADATA_PRESENT=%u\nQ_NORM_PRESENT=%u\nK_NORM_PRESENT=%u\n",ssm?1:0,conv?1:0,state?1:0,mlaMeta?1:0,qnorm?1:0,knorm?1:0);
    std::printf("QUANT_TYPE_COUNT=%zu\n",qc.size());
    for(auto& z:qc) std::printf("QUANT_TYPE_%u_NAME=%s\nQUANT_TYPE_%u_TENSORS=%llu\n",z.first,qname(z.first),z.first,(unsigned long long)z.second);
    std::printf("CAPABILITY_LONG_CONTEXT=%u\nCAPABILITY_VERY_LONG_CONTEXT=%u\nCAPABILITY_GROUPED_QUERY_ATTENTION=%u\nCAPABILITY_SPARSE_EXPERT_ROUTING=%u\nCAPABILITY_RECURRENT_STATE_MODEL=%u\nCAPABILITY_LATENT_ATTENTION_METADATA=%u\nCAPABILITY_NATIVE_CHAT_TEMPLATE=%u\n",context>=32768?1:0,context>=131072?1:0,gqa?1:0,moe?1:0,ssm?1:0,mlaMeta?1:0,chat?1:0);
    std::printf("VERDICT=MODEL_CAPABILITIES_EXTRACTED\n");
    return 0;
}
