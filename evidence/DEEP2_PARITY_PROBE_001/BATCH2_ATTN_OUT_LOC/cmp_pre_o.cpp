#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
static bool load(const char*p,size_t n,std::vector<float>&o){FILE*f=fopen(p,"rb");if(!f){printf("OPEN_FAIL %s\n",p);return false;}o.resize(n);bool ok=fread(o.data(),4,n,f)==n;fclose(f);return ok;}
static uint64_t fnv(const float*a,size_t n){uint64_t h=14695981039346656037ull;for(size_t i=0;i<n;++i){uint32_t b=0;memcpy(&b,&a[i],4);for(int k=0;k<4;++k){h^=(b>>(8*k))&0xff;h*=1099511628211ull;}}return h;}
static void cmp(const char*tag,const float*a,const float*b,size_t n){
  double maxa=0,maxr=0,ss=0; int first=-1,larg=-1,exact=0,b1=0,b2=0,b3=0,b4=0;
  for(size_t i=0;i<n;++i){double d=fabs((double)a[i]-(double)b[i]); ss+=d*d;
    if(d>maxa){maxa=d;larg=(int)i;}
    float den=std::max(fabs(a[i]),fabs(b[i])); double r=den>0?d/den:0; if(r>maxr)maxr=r;
    if(d==0)exact++; else if(d<=1e-6)b1++; else if(d<=1e-5)b2++; else if(d<=1e-4)b3++; else b4++;
    if(first<0 && d>1e-6) first=(int)i;
  }
  const char*gate = maxa<=1e-6?"PASS":(maxa<=1e-5?"INSPECT":"FAIL");
  printf("%s gate=%s n=%zu exact=%d max_abs=%.6e max_rel=%.6e rms=%.6e first_bad=%d largest=%d\n",
    tag,gate,n,exact,maxa,maxr,sqrt(ss/n),first,larg);
  printf("  buckets: eq=%d <1e-6=%d <1e-5=%d <1e-4=%d >=1e-4=%d fnvA=%016llx fnvB=%016llx\n",
    exact,b1,b2,b3,b4,(unsigned long long)fnv(a,n),(unsigned long long)fnv(b,n));
}
int main(){
  const char*d=R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_OUT_LOC)";
  std::vector<float> dPre,lPre,dV,lV,dOut,lOut, expand(2048);
  load((std::string(d)+"\\deep2_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq008.bin").c_str(),2048,dPre);
  load((std::string(d)+"\\llama_ATTN_PRE_O_0_pos0_layer0_full_n2048_seq102.bin").c_str(),2048,lPre);
  load((std::string(d)+"\\deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq009.bin").c_str(),2048,dOut); // may miss - find
  // find deep2 ATTN_OUT and V from dump dir via known names from this run
  // V from digests - need file; list from deep2 dump seq
  // Use ORACLE_V3 V if missing here
  auto tryLoad=[&](const char*rel,size_t n,std::vector<float>&o)->bool{
    return load((std::string(d)+"\\"+rel).c_str(),n,o);
  };
  // discover ATTN_OUT deep2
  FILE*pipe=_popen(("dir /b \""+std::string(d)+"\\deep2_ATTN_OUT_0_pos0*.bin\"").c_str(),"r");
  char line[512]; std::string aout,vout,lout;
  if(pipe){while(fgets(line,sizeof(line),pipe)){std::string s=line; while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back(); if(s.find("pos0")!=std::string::npos && aout.empty()) aout=s;} _pclose(pipe);}
  pipe=_popen(("dir /b \""+std::string(d)+"\\deep2_V_0_pos0*.bin\"").c_str(),"r");
  if(pipe){while(fgets(line,sizeof(line),pipe)){std::string s=line; while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back(); if(vout.empty())vout=s;} _pclose(pipe);}
  pipe=_popen(("dir /b \""+std::string(d)+"\\llama_ATTN_OUT_0_pos0*seq102.bin\"").c_str(),"r");
  if(pipe){while(fgets(line,sizeof(line),pipe)){std::string s=line; while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back(); if(lout.empty())lout=s;} _pclose(pipe);}
  if(aout.empty()){ // fallback from this session seq009 likely
    tryLoad("deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq009.bin",2048,dOut) ||
    tryLoad("deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq008.bin",2048,dOut);
  } else load((std::string(d)+"\\"+aout).c_str(),2048,dOut);
  if(!vout.empty()) load((std::string(d)+"\\"+vout).c_str(),256,dV);
  else load(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V3\deep2_V_0_pos0_layer0_full_n256_seq005.bin)",256,dV);
  load(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V3\llama_V_0_pos0_layer0_full_n256_seq045.bin)",256,lV);
  if(!lout.empty()) load((std::string(d)+"\\"+lout).c_str(),2048,lOut);
  else load((std::string(d)+"\\llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq105.bin").c_str(),2048,lOut); // guess

  // Find llama ATTN_OUT seq after PRE_O 102 -> 105? from dump line fnv
  pipe=_popen(("dir /b \""+std::string(d)+"\\llama_ATTN_OUT_0_pos0*.bin\"").c_str(),"r");
  std::string bestLout; int bestSeq=999999;
  if(pipe){while(fgets(line,sizeof(line),pipe)){std::string s=line; while(!s.empty()&&(s.back()=='\n'||s.back()=='\r'))s.pop_back();
    // prefer seq105 or lowest seq
    int seq=999999; auto p=s.find("seq"); if(p!=std::string::npos) seq=atoi(s.c_str()+p+3);
    if(seq<bestSeq){bestSeq=seq; bestLout=s;}
  } _pclose(pipe);}
  if(!bestLout.empty()) load((std::string(d)+"\\"+bestLout).c_str(),2048,lOut);

  printf("files: deep2_out=%s llama_out=%s deep2_v=%s\n", aout.c_str(), bestLout.c_str(), vout.c_str());
  cmp("ATTN_PRE_O_0 deep2 vs llama", dPre.data(), lPre.data(), 2048);
  for(int h=0;h<32;++h) memcpy(expand.data()+h*64, dV.data()+(h/8)*64, 64*4);
  cmp("deep2 PRE_O vs GQA_expand(V_d)", dPre.data(), expand.data(), 2048);
  for(int h=0;h<32;++h) memcpy(expand.data()+h*64, lV.data()+(h/8)*64, 64*4);
  cmp("llama PRE_O vs GQA_expand(V_l)", lPre.data(), expand.data(), 2048);
  if(dOut.size()==2048 && lOut.size()==2048)
    cmp("ATTN_OUT_0 deep2 vs llama", dOut.data(), lOut.data(), 2048);
  return 0;
}
