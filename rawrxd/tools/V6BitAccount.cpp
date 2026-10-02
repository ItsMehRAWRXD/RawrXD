// RAWRXD_V6_BITACCOUNT_006
// M semantics, measured. Does not assume what M means -- prints the payload
// definition from block_bytes() and the actual serialized size.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>
#include "QuantKernelRegistry.hpp"
#include "beacon_core.inc"

static const std::uint64_t QK_B=144, QK_E=256;
static const std::uint32_t ROWS=256, COLS=1408, BLK=256, MAXB=4;

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
    case 10:case 11:case 12:return std::fseek(f,8,SEEK_CUR)==0;
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

int main(int argc,char**argv){
  if(argc<2){std::printf("usage: <model.gguf>\n");return 1;}
  std::vector<TI>tab;std::uint64_t fz=0,ds=0;
  if(!loadTable(argv[1],&fz,&ds,tab)){std::printf("GGUF_PARSE_FAILED\n");return 1;}
  const TI*g=nullptr; for(const auto&x:tab) if(x.name=="blk.9.ffn_gate_exps.weight"){g=&x;break;}
  if(!g){std::printf("NO_TENSOR\n");return 1;}
  auto&reg=Deep2::QuantKernelRegistry::Instance();reg.RegisterBuiltins();
  auto dq=reg.GetDequant(12); if(!dq){std::printf("NO_Q4K\n");return 1;}
  HANDLE hf=CreateFileA(argv[1],GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
  HANDLE hm=CreateFileMappingA(hf,nullptr,PAGE_READONLY,0,0,nullptr);
  const std::uint64_t G=65536;
  const std::uint64_t sliceB=std::uint64_t(ROWS)*COLS/QK_E*QK_B;
  const std::uint64_t expByte=(g->nbytes/g->outer)*0;
  const std::uint64_t want=ds+g->off+expByte;
  const std::uint64_t al=want&~(G-1), sk2=want-al, vb=sk2+sliceB;
  std::uint8_t* v=static_cast<std::uint8_t*>(
    MapViewOfFile(hm,FILE_MAP_READ,(DWORD)(al>>32),(DWORD)(al&0xFFFFFFFFu),(SIZE_T)vb));
  if(!v){std::printf("MAP_FAILED err=%lu\n",GetLastError());return 1;}
  std::vector<float> data(sliceB/QK_B*QK_E);
  for(std::uint64_t b=0;b<sliceB/QK_B;++b) dq(v+sk2+b*QK_B,data.data()+b*QK_E,QK_E);
  UnmapViewOfFile(v);

  const std::uint64_t nb=std::uint64_t(ROWS)*COLS/BLK;
  const std::vector<float> sens(std::size_t(nb),1.0f);
  beacon::Model M{};
  try{ M=beacon::encode(data,ROWS,COLS,BLK,MAXB,4.125,0.005,sens);}catch(...){}

  // ---- M SEMANTICS, read off block_bytes() ----
  std::uint64_t h[6]={0,0,0,0,0,0};
  for(std::size_t b=0;b<M.bits.size();++b) h[std::min<unsigned>(M.bits[b],5)]++;
  std::printf("RAWRXD_V6_BITACCOUNT_006\n");
  std::printf("slice %ux%u  weights=%llu  blocks=%llu  max_bits=%u\n",
    ROWS,COLS,(unsigned long long)(std::uint64_t(ROWS)*COLS),(unsigned long long)nb,MAXB);
  std::printf("\nM SEMANTICS from block_bytes(count,bits):\n");
  std::printf("  residual payload = (count*bits+7)/8 bytes for `count` weights\n");
  for(unsigned m=0;m<=4;++m)
    std::printf("    M=%u -> code %3llu B + centroids %3llu B + flag 1 B = %3llu B per 256-weight block"
                "  => residual %.4f bits/weight\n", m,
      (unsigned long long)(256u*m+7)/8,(unsigned long long)((1ull<<m)*4),
      (unsigned long long)(1+(256ull*m+7)/8+(1ull<<m)*4), double(m));
  std::printf("\nCENSUS\n");
  for(unsigned m=0;m<=4;++m) std::printf("  M%u_BLOCKS=%llu\n",m,(unsigned long long)h[m]);

  std::uint64_t tot=0; double weighted=0;
  for(unsigned m=0;m<=4;++m){tot+=h[m];weighted+=double(m)*double(h[m]);}
  const double meanM=weighted/double(tot);
  std::printf("\nCORRECTED ARITHMETIC\n");
  std::printf("  MEAN_M                 = %.5f\n",meanM);
  std::printf("  MEAN_RESIDUAL_BPW      = %.5f   (M IS bits per weight; do NOT divide by 256)\n",meanM);

  // ---- actual bytes, from the encoder's own accounting ----
  std::uint64_t codeB=0, centB=0, flagB=0;
  for(std::size_t b=0;b<M.bits.size();++b){
    const unsigned m=M.bits[b];
    if(m){ codeB += (256ull*m+7)/8; centB += (1ull<<m)*4ull; flagB += 1; }
    else flagB += 1;
  }
  const std::uint64_t shared = 52 + M.rows + M.cols + std::uint64_t(M.outliers.size())*6;
  const std::uint64_t total = codeB + centB + flagB + shared + std::uint64_t(nb);
  const double W = double(std::uint64_t(ROWS)*COLS);
  std::printf("\nACTUAL SERIALIZED BYTES (encoder's own accounting)\n");
  std::printf("  residual code planes   %9llu B  %7.4f b/w\n",(unsigned long long)codeB, double(codeB)*8/W);
  std::printf("  LLOYD CENTROIDS       %9llu B  %7.4f b/w   <-- dominates\n",(unsigned long long)centB, double(centB)*8/W);
  std::printf("  per-block flags       %9llu B  %7.4f b/w\n",(unsigned long long)flagB, double(flagB)*8/W);
  std::printf("  shared (52+r+c+out*6)%9llu B  %7.4f b/w\n",(unsigned long long)shared, double(shared)*8/W);
  std::printf("  block-index array     %9llu B  %7.4f b/w\n",(unsigned long long)nb, double(nb)*8/W);
  std::printf("  ----------------------------------------------\n");
  std::printf("  TOTAL                 %9llu B  %7.4f b/w\n",(unsigned long long)total, double(total)*8/W);
  std::printf("  Q4_K source           %9llu B  %7.5000 b/w\n",
              (unsigned long long)(sliceB), double(sliceB)*8/W);
  std::printf("\n  V6_TOTAL_BPW          = %.4f\n", double(total)*8/W);
  std::printf("  V6_VERSUS_Q4K         = %.3fx  %s\n",
              (double(total)*8/W)/4.5, ((double(total)*8/W) < 4.5 ? "COMPRESSES" : "IS WORSE THAN Q4_K"));
  CloseHandle(hm);CloseHandle(hf);
  return 0;
}
