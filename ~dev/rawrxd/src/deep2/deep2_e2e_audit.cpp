#include "deep2_e2e_trace.hpp"
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <vector>
using namespace deep2;
struct Tok { std::set<uint32_t> layers; uint64_t kv=0,logits=0,sample=0,detok=0,stream=0; int64_t sid=-1,did=-1,stid=-1; std::vector<uint8_t>dbytes,sbytes; uint64_t seq_logits=0,seq_sample=0,seq_detok=0,seq_stream=0; };
static bool read_all(const std::string&p,std::vector<uint8_t>&v){std::ifstream f(p,std::ios::binary);if(!f)return false;f.seekg(0,std::ios::end);auto n=f.tellg();if(n<0)return false;v.resize((size_t)n);f.seekg(0);if(n)f.read((char*)v.data(),n);return (bool)f||n==0;}
static bool gguf_ok(const std::string&p,uint32_t&ver){std::ifstream f(p,std::ios::binary);char m[4];uint32_t v=0;if(!f.read(m,4))return false;if(!f.read((char*)&v,4))return false;ver=v;return std::memcmp(m,"GGUF",4)==0 && v>=1 && v<=3;}
static void emit(const char*k,bool p){std::cout<<k<<"="<<(p?"PASS":"HOLD")<<"\n";}
int main(int argc,char**argv){
    std::string trace,out;for(int i=1;i<argc;i++){std::string a=argv[i];if(a=="--trace"&&i+1<argc)trace=argv[++i];else if(a=="--stdout"&&i+1<argc)out=argv[++i];}
    if(trace.empty()||out.empty()){std::cerr<<"usage: deep2_e2e_audit --trace file --stdout captured_stdout\n";return 64;}
    std::ifstream f(trace,std::ios::binary);TraceHeader h{};if(!f.read((char*)&h,sizeof(h))||std::memcmp(h.magic,"D2E2TRC",7)||h.version!=D2E_TRACE_VERSION){std::cerr<<"TRACE_FORMAT=INVALID\n";return 65;}
    bool b76=h.model_files>0&&h.layers>0&&h.prompt_tokens>0&&h.model_name[0];std::vector<ModelRecord> mr(h.model_files);Sha256 modelset;
    for(auto&r:mr){if(!f.read((char*)&r,sizeof(r))){b76=false;break;}std::string p(r.path,strnlen(r.path,sizeof(r.path)));std::array<uint8_t,32>d{};uint64_t n=0;uint32_t gv=0;
        bool one=sha256_file(p,d,&n)&&n==r.claimed_bytes&&!std::memcmp(d.data(),r.claimed_sha256,32)&&gguf_ok(p,gv);b76 &= one;modelset.update(d.data(),d.size());modelset.update(&n,sizeof(n));}
    bool discover=false,opened=false,backend=false,tokenized=false,end=false;uint64_t weight=0,bad=0,expected_seq=1;std::map<uint32_t,Tok> toks;std::vector<uint8_t> replay;
    bool trace_parse=true;
    while(f){EventRecord e{};if(!f.read((char*)&e,sizeof(e))){if(f.eof())break;trace_parse=false;break;}std::vector<uint8_t>p(e.payload_bytes);if(e.payload_bytes&&!f.read((char*)p.data(),e.payload_bytes)){trace_parse=false;break;}
        if(e.seq!=expected_seq++) trace_parse=false;
        auto t=(E2EEvent)e.type;
        if(t==E2EEvent::DISCOVER)discover=true;else if(t==E2EEvent::OPEN)opened=true;else if(t==E2EEvent::BACKEND_DEEP2)backend=true;
        else if(t==E2EEvent::TOKENIZE_DONE)tokenized=e.value0==h.prompt_tokens&&e.value0>0;else if(t==E2EEvent::WEIGHT_TOUCH)weight+=e.value0;
        else if(t==E2EEvent::SYNTHETIC||t==E2EEvent::PROXY||t==E2EEvent::FALLBACK)bad++;
        else if(t==E2EEvent::END)end=true;
        else if(e.token_index!=D2E_GLOBAL){Tok&x=toks[e.token_index];if(t==E2EEvent::FORWARD_LAYER){if(e.layer_index<h.layers)x.layers.insert(e.layer_index);else trace_parse=false;}
            else if(t==E2EEvent::KV_COMMIT)x.kv++;
            else if(t==E2EEvent::LOGITS_READY){x.logits++;x.seq_logits=e.seq;if(e.value0==0)trace_parse=false;}
            else if(t==E2EEvent::SAMPLE){x.sample++;x.sid=e.token_id;x.seq_sample=e.seq;}
            else if(t==E2EEvent::DETOKENIZE){x.detok++;x.did=e.token_id;x.dbytes=p;x.seq_detok=e.seq;if(p.empty())trace_parse=false;}
            else if(t==E2EEvent::STREAM){x.stream++;x.stid=e.token_id;x.sbytes=p;x.seq_stream=e.seq;replay.insert(replay.end(),p.begin(),p.end());}
        }
    }
    bool contiguous=!toks.empty();uint32_t idx=0;for(auto&kv:toks){if(kv.first!=idx++)contiguous=false;}
    bool count_ok=toks.size()>=h.min_generated_tokens && toks.size()<=h.max_generated_tokens;
    bool b77=trace_parse&&contiguous&&count_ok,b78=b77;
    for(auto&kv:toks){auto&x=kv.second;b77 &= x.sample==1&&x.detok==1&&x.stream==1&&x.sid==x.did&&x.sid==x.stid&&x.dbytes==x.sbytes&&x.seq_sample<x.seq_detok&&x.seq_detok<x.seq_stream;
        b78 &= x.layers.size()==h.layers&&x.kv>=1&&x.logits==1&&x.seq_logits<x.seq_sample;}
    bool b79=bad==0&&backend;std::vector<uint8_t>actual;bool stdout_ok=read_all(out,actual)&&actual==replay;
    b77 &= stdout_ok;
    bool prereq=discover&&opened&&tokenized&&weight>0&&end;
    bool b80=b76&&b77&&b78&&b79&&prereq;
    std::array<uint8_t,32>th{},oh{};uint64_t tb=0,ob=0;sha256_file(trace,th,&tb);sha256_file(out,oh,&ob);auto ms=modelset.finish();
    std::cout<<"MODEL="<<h.model_name<<"\nMODEL_FILES="<<h.model_files<<"\nMODEL_SET_SHA256="<<hex32(ms)<<"\n";
    std::cout<<"TRACE_SHA256="<<hex32(th)<<"\nSTDOUT_SHA256="<<hex32(oh)<<"\n";
    std::cout<<"LAYERS="<<h.layers<<" PROMPT_TOKENS="<<h.prompt_tokens<<" GENERATED_TOKENS="<<toks.size()<<" WEIGHT_BYTES_TOUCHED="<<weight<<"\n";
    std::cout<<"DISCOVER="<<discover<<" OPEN="<<opened<<" TOKENIZE="<<tokenized<<" BACKEND_DEEP2="<<backend<<" END="<<end<<" BAD_SUBSTITUTION_EVENTS="<<bad<<"\n";
    emit("DEEP2_B76_MODEL_PROVENANCE",b76);emit("DEEP2_B77_TOKEN_LINEAGE",b77);emit("DEEP2_B78_LAYER_KV_LOGITS",b78);emit("DEEP2_B79_NO_SUBSTITUTION",b79);emit("DEEP2_B80_INDEPENDENT_REPLAY",b80);
    std::cout<<"AUDIT_INDEPENDENT=1\nDEEP2_REAL_MODEL_E2E="<<(b80?"PASS":"HOLD")<<"\nPROMOTE="<<(b80?1:0)<<"\n";return b80?0:2;
}
