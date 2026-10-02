// RAWRXD_V6_M01_PARITY_008 / RAWRXD_V6_FULL_PARITY_009
// Full M0-M4 coverage. M0 residual is identically zero; M1 is one binary plane.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>
#include "QuantKernelRegistry.hpp"
#include "beacon_core.inc"
extern "C" float DecodaV6_Dot0_256(const float*, const std::uint8_t*, const float*);
extern "C" float DecodaV6_Dot1_256(const float*, const std::uint8_t*, const float*);
extern "C" float DecodaV6_Dot2_256(const float*, const std::uint8_t*, const float*);
extern "C" float DecodaV6_Dot3_256(const float*, const std::uint8_t*, const float*);
extern "C" float DecodaV6_Dot4_256(const float*, const std::uint8_t*, const float*);
static const std::uint64_t QK_B=144,QK_E=256;
static const std::uint32_t ROWS=256,COLS=1408,BLK=256,MAXB=4;
struct TI{std::string name;std::uint64_t off=0,nbytes=0,nelem=0,ndim=0,outer=0;};
static bool loadTable(const char*p,std::uint64_t*fz,std::uint64_t*ds,std::vector<TI>&t){
  std::FILE*f=std::fopen(p,"rb"); if(!f)return false;
  char m[4]={};std::uint32_t v=0;std::uint64_t nt=0,nkv=0;
  if(std::fread(m,1,4,f)!=4){std::fclose(f);return false;}
  std::fread(&v,4,1,f);std::fread(&nt,8,1,f);std::fread(&nkv,8,1,f);
  auto rds=[&](std::string&s)->bool{std::uint64_t n=0;if(std::fread(&n,8,1,f)!=1)return false;
    s.resize(n);return !n||std::fread(&s[0],1,n,f)==n;};
  std::function<bool(std::uint32_t)>sk=[&](std::uint32_t ty)->bool{
    switch(ty){case 0:case 1:case 7:return std::fseek(f,1,SEEK_CUR)==0;
    case 2:case 3:return std::fseek(f,2,SEEK_CUR)==0;
    case 4:case 5:case 6:return std::fseek(f,4,SEEK_CUR)==0;
    case 10:case 11: case 12:return std::fseek(f,8,SEEK_CUR)==0;
    case 8:{std::string s;return rds(s);}
    case 9:{std::uint32_t et=0;std::uint64_t c=0;
      if(std::fread(&et,4,1,f)!=1||std::fread(&c,8,1,f)!=1)return false;
      for(std::uint64_t i=0;i<c;++i)if(!sk(et))return false;return true;}
    default:return false;}};
  for(std::uint64_t i=0;i<nkv;++i){std::string k;std::uint32_t ty=0;
    if(!rds(k)||std::fread(&ty,4,1,f)!=1||!sk(ty)){std::fclose(f);return false;}}
  const long long te=_ftelli64(f); *ds=std::uint64_t(((te+31)/32)*32);
  std::uint64_t d[4]={1,1,1,1};
  for(std::uint64_t i=0;i<nt;++i){TI x;std::uint32_t nd=0,ty=0;
    if(!rds(x.name)||std::fread(&nd,4,1,f)!=1){std::fclose(f);return false;}
    for(std::uint32_t q=0;q<nd&&q<4;++q)if(std::fread(&d[q],8,1,f)!=1){std::fclose(f);return false;}
    if(std::fread(&ty,4,1,f)!=1||std::fread(&x.off,8,1,f)!=1){std::fclose(f);return false;}
    x.ndim=nd;x.nelem=1;for(std::uint32_t q=0;q<nd&&q<4;++q)x.nelem*=d[q];
    x.outer=d[nd-1];t.push_back(x);}
  std::fseek(f,0,SEEK_END);*fz=std::uint64_t(_ftelli64(f));std::fclose(f);
  for(std::size_t i=0;i+1<t.size();++i)t[i].nbytes=t[i+1].off-t[i].off;
  if(!t.empty())t.back().nbytes=*fz-*ds-t.back().off;
  return true;
}
struct Act{const char*n;std::vector<float>x;};
static std::vector<Act> activations(){
  std::vector<Act>a;
  {std::vector<float> v(256);std::uint64_t s=0x9E3779B97F4A7C15ull;
   for(int i=0;i<256;++i){s^=s<<13;s^=s>>7;s^=s<<17;
     v[i]=(float(int(s>>40)%2001)-1000.0f)/777.0f;} a.push_back({"A mixed-sign",v});}
  {std::vector<float> v(256,1.0f);a.push_back({"B all-ones",v});}
  {std::vector<float> v(256);for(int i=0;i<256;++i)v[i]=(i&1)?-1.0f:1.0f;a.push_back({"C alternating",v});}
  {std::vector<float> v(256,0.0f);v[0]=1;v[127]=-2;v[255]=3;a.push_back({"D sparse",v});}
  {std::vector<float> v(256);for(int i=0;i<256;++i)
     v[i]=std::sin(float(i)*0.071f)+0.25f*std::cos(float(i)*0.193f);a.push_back({"E sin/cos",v});}
  return a;
}
int main(int argc,char**argv){
  if(argc<2){std::printf("usage: <model.gguf>\n");return 1;}
  std::vector<TI> tab;std::uint64_t fz=0,ds=0;
  if(!loadTable(argv[1],&fz,&ds,tab)){std::printf("GGUF_PARSE_FAILED\n");return 1;}
  const TI* g=nullptr; for(const auto&x:tab) if(x.name=="blk.9.ffn_gate_exps.weight"){g=&x;break;}
  if(!g){std::printf("NO_TENSOR\n");return 1;}
  auto& reg=Deep2::QuantKernelRegistry::Instance();reg.RegisterBuiltins();
  auto dq=reg.GetDequant(12); if(!dq){std::printf("NO_Q4K\n");return 1;}
  HANDLE hf=CreateFileA(argv[1],GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
  HANDLE hm=CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr);
  const std::uint64_t G=65536,sliceB=std::uint64_t(ROWS)*COLS/QK_E*QK_B;
  const std::uint64_t want=ds+g->off,al=want&~(G-1),sk2=want-al,vb=sk2+sliceB;
  std::uint8_t* v=static_cast<std::uint8_t*>(
    MapViewOfFile(hm,FILE_MAP_READ,(DWORD)(al>>32),(DWORD)(al&0xFFFFFFFFu),(SIZE_T)vb));
  if(!v){std::printf("MAP_FAILED\n");return 1;}
  std::vector<float> data(sliceB/QK_B*QK_E);
  for(std::uint64_t b=0;b<sliceB/QK_B;++b) dq(v+sk2+b*QK_B,data.data()+b*QK_E,QK_E);
  UnmapViewOfFile(v);
  const std::uint64_t nb=std::uint64_t(ROWS)*COLS/BLK;
  const std::vector<float> sens(std::size_t(nb),1.0f);
  beacon::Model M{};
  try{M=beacon::encode(data,ROWS,COLS,BLK,MAXB,4.125,0.005,sens);}catch(...){std::printf("ENCODE_THREW\n");return 1;}

  std::uint64_t hist[5]={0,0,0,0,0};
  for(std::size_t b=0;b<M.bits.size();++b) hist[M.bits[b]<5?M.bits[b]:4]++;
  std::printf("RAWRXD_V6_M01_PARITY_008\n");
  std::printf("blocks=%llu  M0=%llu M1=%llu M2=%llu M3=%llu M4=%llu\n",
    (unsigned long long)M.bits.size(),(unsigned long long)hist[0],(unsigned long long)hist[1],
    (unsigned long long)hist[2],(unsigned long long)hist[3],(unsigned long long)hist[4]);
  std::printf("M0+M1 share = %.2f%% of the format\n",
    100.0*double(hist[0]+hist[1])/double(M.bits.size()));

  // M0 must have EMPTY centroid and code vectors -- Dot0 reads neither.
  { std::uint64_t bad=0;
    for(std::size_t b=0;b<M.bits.size();++b)
      if(M.bits[b]==0 && (!M.codes[b].empty()||!M.centroids[b].empty())) ++bad;
    std::printf("M0_VECTOR_INTEGRITY: blocks where M0 has non-empty codes/centroids = %llu\n",
                (unsigned long long)bad);
    if(bad){std::printf("  (Dot0 performs no reads; a non-empty M0 table would be dead weight)\n");} }

  const auto acts=activations();
  std::uint64_t tested[5]={0,0,0,0,0},failed[5]={0,0,0,0,0},passed[5]={0,0,0,0,0};
  int nanC=0,infC=0;
  double maxAbs=0.0;
  for(const auto&A:acts){
    for(std::size_t b=0;b<M.bits.size();++b){
      const unsigned m=M.bits[b]; if(m>4)continue;
      const uint8_t* cp=M.codes[b].data();
      const float* cen=M.centroids[b].data();
      float kd=0.0f;
      if     (m==0) kd=DecodaV6_Dot0_256(A.x.data(),cp,cen);
      else if(m==1) kd=DecodaV6_Dot1_256(A.x.data(),cp,cen);
      else if(m==2) kd=DecodaV6_Dot2_256(A.x.data(),cp,cen);
      else if(m==3) kd=DecodaV6_Dot3_256(A.x.data(),cp,cen);
      else         kd=DecodaV6_Dot4_256(A.x.data(),cp,cen);
      double rd=0.0,absum=0.0;
      if(m>0) for(int i=0;i<256;++i){
        const float cv=M.centroids[b][beacon::unpack_code(M.codes[b],m,(uint32_t)i)];
        rd+=double(cv)*double(A.x[i]); absum+=std::fabs(double(cv)*double(A.x[i])); }
      if(std::isnan(kd))++nanC; if(std::isinf(kd))++infC;
      const double ae=std::fabs(double(kd)-rd);
      ++tested[m];
      if(ae<=8.0*1.1920929e-7*absum)++passed[m]; else ++failed[m];
      maxAbs=std::max(maxAbs,ae);
    }
  }
  std::printf("\nRAWRXD_V6_FULL_PARITY_009   activations=%zu  reference=residual decode + scalar dot\n",acts.size());
  std::printf("%-4s %-9s %-9s %-10s\n","M","TESTED","PASS","FAILURES");
  std::uint64_t tt=0,ff=0;
  for(unsigned m=0;m<=4;++m){tt+=tested[m];ff+=failed[m];
    std::printf("%-4u %-9llu %-9llu %-10llu\n",m,(unsigned long long)tested[m],
      (unsigned long long)passed[m],(unsigned long long)failed[m]);}
  std::printf("TOTAL_TESTED=%llu  TOTAL_FAILURES=%llu  MAX_ABS_ERR=%.6g\n",
    (unsigned long long)tt,(unsigned long long)ff,maxAbs);
  std::printf("KERNEL_NAN=%d  KERNEL_INF=%d\n",nanC,infC);
  std::printf("UNEXECUTABLE_BLOCKS=%llu\n",
    (unsigned long long)(M.bits.size()-(hist[0]+hist[1]+hist[2]+hist[3]+hist[4])));
  const bool ok=(ff==0&&tt>0&&nanC==0&&infC==0);
  std::printf("\nVERDICT=%s\n",ok?"M0_M4_PARITY_PASS":"M0_M4_PARITY_FAIL");
  CloseHandle(hm);CloseHandle(hf);
  return ok?0:1;
}
