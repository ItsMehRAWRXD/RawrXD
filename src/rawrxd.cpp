// =============================================================================
// rawrxd.cpp — Unified inference engine with Orchestrator integration
// Zero dependencies. C++17. Single file.
//
// Commands:
//   rawrxd run      <model> "prompt" [--temp 0.7] [-n 4096]
//   rawrxd validate <model> "prompt"
//   rawrxd bench    <model>
//   rawrxd ctx      <model> "prompt"
// =============================================================================
#define _CRT_SECURE_NO_WARNINGS
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <set>
#include <deque>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <chrono>
#include <random>
#include <atomic>
#include <mutex>
#include <sstream>
#include <memory>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "rawrxd_orchestrator.hpp"

// =============================================================================
// FP CONVERSIONS
// =============================================================================
static float f16_to_f32(uint16_t h){
    uint32_t s=(h>>15)&1,e=(h>>10)&0x1F,f=h&0x3FF,v;
    if(e==0){if(f==0){v=s<<31;}else{e=1;do{e--;f<<=1;}while(!(f&0x400));f&=0x3FF;v=(s<<31)|(e<<23)|(f<<13);}}
    else if(e==31){v=(s<<31)|0x7F800000|(f<<13);}
    else{v=(s<<31)|((e+112)<<23)|(f<<13);}
    return*(float*)&v;
}
static float bf16_to_f32(uint16_t b){uint32_t f=(uint32_t)b<<16;return*(float*)&f;}

// =============================================================================
// MMAP
// =============================================================================
struct MMap{
    void*d=nullptr;size_t sz=0;
#ifdef _WIN32
    HANDLE hf=INVALID_HANDLE_VALUE,hm=nullptr;
#else
    int fd=-1;
#endif
    bool map(const std::string&p){
#ifdef _WIN32
        hf=CreateFileA(p.c_str(),GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
        if(hf==INVALID_HANDLE_VALUE)return false;
        LARGE_INTEGER li;GetFileSizeEx(hf,&li);sz=(size_t)li.QuadPart;
        hm=CreateFileMapping(hf,0,PAGE_READONLY,0,0,0);
        if(!hm){CloseHandle(hf);return false;}
        d=MapViewOfFile(hm,FILE_MAP_READ,0,0,0);return d!=nullptr;
#else
        fd=open(p.c_str(),O_RDONLY);if(fd<0)return false;
        struct stat st;fstat(fd,&st);sz=st.st_size;
        d=mmap(0,sz,PROT_READ,MAP_PRIVATE,fd,0);return d!=MAP_FAILED;
#endif
    }
    ~MMap(){
#ifdef _WIN32
        if(d)UnmapViewOfFile(d);if(hm)CloseHandle(hm);if(hf!=INVALID_HANDLE_VALUE)CloseHandle(hf);
#else
        if(d)munmap(d,sz);if(fd>=0)close(fd);
#endif
    }
};

// =============================================================================
// GGUF
// =============================================================================
static uint64_t qt_blk(uint32_t t){switch(t){case 2:case 3:case 6:case 7:case 8:case 9:return 32;case 10:case 11:case 12:case 13:case 14:case 15:return 256;default:return 1;}}
static uint64_t qt_sz(uint32_t t){switch(t){case 0:return 4;case 1:case 30:return 2;case 2:return 18;case 3:return 20;case 6:return 22;case 7:return 24;case 8:return 34;case 9:return 36;case 10:return 84;case 11:return 108;case 12:return 144;case 13:return 176;case 14:return 210;case 15:return 292;case 24:return 1;case 25:return 2;case 26:return 4;case 27:return 8;case 28:return 8;default:return 0;}}

struct GGTensor{std::string name;uint32_t type;std::vector<uint64_t> dims;uint64_t offset;uint64_t nbytes;const uint8_t* data;int shard;uint64_t elems()const{uint64_t e=1;for(auto d:dims)e*=d;return e;}};
struct GGUF{
    std::vector<MMap> maps;std::vector<GGTensor> tensors;
    std::unordered_map<std::string,size_t> tmap;
    uint32_t ver=3,align=32;
    std::map<std::string,std::string> ms;std::map<std::string,int64_t> mi;
    std::map<std::string,double> mf;std::map<std::string,bool> mb;
    std::map<std::string,std::vector<std::string>> msa;
    std::map<std::string,std::vector<int32_t>> mia;
    std::map<std::string,std::vector<float>> mfa;

    bool load(const std::string&path){
        std::vector<std::string> shards;
        auto pos=path.find("-00001-of-");
        if(pos!=std::string::npos){
            std::string b=path.substr(0,pos),ext=path.substr(pos+11);
            auto d=ext.find('-');if(d!=std::string::npos){
                int tot=std::stoi(ext.substr(0,d));ext=ext.substr(d);
                for(int i=1;i<=tot;i++){char b2[16];snprintf(b2,sizeof(b2),"%05d",i);shards.push_back(b+"-"+b2+"-"+std::to_string(tot)+ext);}
            }
        }else shards.push_back(path);
        maps.resize(shards.size());
        for(size_t i=0;i<shards.size();i++){if(!maps[i].map(shards[i])){fprintf(stderr,"Cannot open: %s\n",shards[i].c_str());return false;}if(!parse(i))return false;}
        return true;
    }
    GGTensor*get(const std::string&n){auto it=tmap.find(n);return it!=tmap.end()?&tensors[it->second]:nullptr;}
    bool has(const std::string&n)const{return tmap.count(n);}
    int64_t I(const std::string&k,int64_t d=0)const{auto it=mi.find(k);return it!=mi.end()?it->second:d;}
    float F(const std::string&k,float d=0)const{auto it=mf.find(k);return it!=mf.end()?(float)it->second:d;}
    std::string S(const std::string&k,std::string d="")const{auto it=ms.find(k);return it!=ms.end()?it->second:d;}
private:
    bool parse(int si){
        auto*base=(const uint8_t*)maps[si].d;size_t sz=maps[si].sz;
        const uint8_t*p=base,*end=base+sz;
        #define RD(d,s){if(p+s>end)return false;memcpy(&(d),p,s);p+=s;}
        #define RDS(str){if(p+8>end)return false;uint64_t l;memcpy(&l,p,8);p+=8;if(l>1048576||p+l>end)return false;str.assign((const char*)p,l);p+=l;}
        if(sz<12||memcmp(p,"GGUF",4))return false;p+=4;
        RD(ver,4);if(ver<2||ver>3)return false;
        uint64_t nt,nk;RD(nt,8);RD(nk,8);
        if(nt>1000000||nk>1000000)return false;
        for(uint64_t i=0;i<nk;i++){
            std::string k;RDS(k);uint32_t vt;RD(vt,4);
            switch(vt){
                case 0:{uint8_t v;RD(v,1);mi[k]=v;break;}
                case 1:{int8_t v;RD(v,1);mi[k]=v;break;}
                case 2:{uint16_t v;RD(v,2);mi[k]=v;break;}
                case 3:{int16_t v;RD(v,2);mi[k]=v;break;}
                case 4:{uint32_t v;RD(v,4);mi[k]=v;break;}
                case 5:{int32_t v;RD(v,4);mi[k]=v;break;}
                case 6:{float v;RD(v,4);mf[k]=v;break;}
                case 7:{int8_t v;RD(v,1);mb[k]=v;break;}
                case 8:{std::string v;RDS(v);ms[k]=v;break;}
                case 9:{uint32_t at;RD(at,4);uint64_t an;RD(an,8);
                    if(at==8){auto&a=msa[k];a.resize(an);for(uint64_t j=0;j<an;j++)RDS(a[j]);}
                    else if(at==5){auto&a=mia[k];a.resize(an);for(uint64_t j=0;j<an;j++){int32_t v;RD(v,4);a[j]=v;}}
                    else if(at==6){auto&a=mfa[k];a.resize(an);for(uint64_t j=0;j<an;j++){float v;RD(v,4);a[j]=v;}}
                    else for(uint64_t j=0;j<an;j++)if(!skip(p,end,at))return false;
                    break;}
                case 10:{uint64_t v;RD(v,8);mi[k]=(int64_t)v;break;}
                case 11:{int64_t v;RD(v,8);mi[k]=v;break;}
                case 12:{double v;RD(v,8);mf[k]=v;break;}
                default:return false;
            }
        }
        auto ait=mi.find("general.alignment");if(ait!=mi.end())align=(uint32_t)ait->second;
        if(!align||(align&(align-1)))align=32;
        size_t first=tensors.size();
        for(uint64_t i=0;i<nt;i++){
            GGTensor t;RDS(t.name);uint32_t nd;RD(nd,4);
            if(nd==0||nd>4)return false;t.dims.resize(nd);
            for(uint32_t j=0;j<nd;j++){RD(t.dims[j],8);if(!t.dims[j])return false;}
            RD(t.type,4);if(!qt_sz(t.type))return false;RD(t.offset,8);
            uint64_t el=1;for(auto d:t.dims){if(d>UINT64_MAX/el)return false;el*=d;}
            t.nbytes=qt_blk(t.type)==1?el*qt_sz(t.type):(el/qt_blk(t.type))*qt_sz(t.type);
            uint64_t dp=p-base,ap=(dp+align-1)&~(uint64_t)(align-1),fo=ap+t.offset;
            if(fo+t.nbytes>sz){fprintf(stderr,"OOB: %s\n",t.name.c_str());return false;}
            t.data=base+fo;t.shard=si;
            if(tmap.count(t.name)){fprintf(stderr,"Dup: %s\n",t.name.c_str());return false;}
            tensors.push_back(std::move(t));tmap[tensors.back().name]=tensors.size()-1;
        }
        for(size_t i=first;i<tensors.size();i++)for(size_t j=i+1;j<tensors.size();j++)
            if(tensors[i].shard==tensors[j].shard){
                uint64_t as=tensors[i].offset,ae=as+tensors[i].nbytes,bs=tensors[j].offset,be=bs+tensors[j].nbytes;
                if(as<be&&bs<ae){fprintf(stderr,"Overlap: %s & %s\n",tensors[i].name.c_str(),tensors[j].name.c_str());return false;}
            }
        return true;
    }
    static bool skip(const uint8_t*&p,const uint8_t*end,uint32_t t){
        switch(t){case 0:case 1:case 7:p+=1;return p<=end;case 2:case 3:p+=2;return p<=end;case 4:case 5:case 6:p+=4;return p<=end;case 8:{uint64_t l;if(p+8>end)return false;memcpy(&l,p,8);p+=8;if(p+l>end)return false;p+=l;return true;}case 10:case 11:case 12:p+=8;return p<=end;default:return false;}
    }
};

// =============================================================================
// DEQUANT
// =============================================================================
static void deq_f32(const uint8_t*s,float*d,uint64_t n){memcpy(d,s,n*4);}
static void deq_f16(const uint8_t*s,float*d,uint64_t n){for(uint64_t i=0;i<n;i++){uint16_t h;memcpy(&h,s+i*2,2);d[i]=f16_to_f32(h);}}
static void deq_bf16(const uint8_t*s,float*d,uint64_t n){for(uint64_t i=0;i<n;i++){uint16_t h;memcpy(&h,s+i*2,2);d[i]=bf16_to_f32(h);}}
static void deq_q4_0(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/32;b++){uint16_t dr;memcpy(&dr,s,2);s+=2;float sc=f16_to_f32(dr);for(int i=0;i<16;i++){uint8_t q=s[i];d[b*32+i]=sc*((float)(q&0xF)-8.0f);d[b*32+i+16]=sc*((float)(q>>4)-8.0f);}s+=16;}}
static void deq_q4_1(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/32;b++){uint16_t dr,mr;memcpy(&dr,s,2);s+=2;memcpy(&mr,s,2);s+=2;float sc=f16_to_f32(dr),mn=f16_to_f32(mr);for(int i=0;i<16;i++){uint8_t q=s[i];d[b*32+i]=sc*(float)(q&0xF)+mn;d[b*32+i+16]=sc*(float)(q>>4)+mn;}s+=16;}}
static void deq_q8_0(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/32;b++){uint16_t dr;memcpy(&dr,s,2);s+=2;float sc=f16_to_f32(dr);for(int i=0;i<32;i++){int8_t q;memcpy(&q,s+i,1);d[b*32+i]=sc*(float)q;}s+=32;}}
static void deq_q8_1(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/32;b++){uint16_t dr,mr;memcpy(&dr,s,2);s+=2;memcpy(&mr,s,2);s+=2;float sc=f16_to_f32(dr),mn=f16_to_f32(mr);for(int i=0;i<32;i++){int8_t q;memcpy(&q,s+i,1);d[b*32+i]=sc*(float)q+mn;}s+=32;}}
static inline void get_sc_min_k4(int j,const uint8_t*q,uint8_t*sc,uint8_t*m){if(j<2){*sc=q[j]&63;*m=q[j+2]&63;}else{*sc=(q[j]>>4)|((q[j-2]&0x30)<<2);*m=(q[j+2]>>4)|((q[j]&0x30)<<2);}}
static void deq_q4_k(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/256;b++){uint16_t dr,dmr;memcpy(&dr,s,2);s+=2;memcpy(&dmr,s,2);s+=2;float dd=f16_to_f32(dr),dmn=f16_to_f32(dmr);const uint8_t*sc=s;s+=12;const uint8_t*qs=s;int is=0;for(int j=0;j<256;j+=64){uint8_t sc2,m;get_sc_min_k4(is,sc,&sc2,&m);float d1=dd*sc2,m1=dmn*m;for(int ii=0;ii<32;ii++){d[b*256+j+ii]=d1*(float)(qs[ii]&0xF)-m1;d[b*256+j+ii+32]=d1*(float)(qs[ii]>>4)-m1;}qs+=32;is++;}s+=128;}}
static void deq_q5_k(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/256;b++){uint16_t dr,dmr;memcpy(&dr,s,2);s+=2;memcpy(&dmr,s,2);s+=2;float dd=f16_to_f32(dr),dmn=f16_to_f32(dmr);const uint8_t*sc=s;s+=12;const uint8_t*qh=s;s+=64;const uint8_t*qs=s;int is=0;for(int j=0;j<256;j+=64){uint8_t sc2,m;get_sc_min_k4(is,sc,&sc2,&m);float d1=dd*sc2,m1=dmn*m;for(int ii=0;ii<32;ii++){uint8_t q5l=(qs[ii]&0xF)|(((qh[is*32+ii/2]>>((ii%2)*4))&1)<<4);uint8_t q5h=(qs[ii]>>4)|(((qh[is*32+ii/2]>>((ii%2)*4+1))&1)<<4);d[b*256+j+ii]=d1*(float)q5l-m1;d[b*256+j+ii+32]=d1*(float)q5h-m1;}qs+=32;is++;}s+=128;}}
static void deq_q6_k(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/256;b++){uint16_t dr;memcpy(&dr,s,2);s+=2;float dd=f16_to_f32(dr);const uint8_t*ql=s;s+=128;const uint8_t*qh=s;s+=64;const int8_t*sc=(const int8_t*)s;s+=16;for(int n128=0;n128<256;n128+=128){for(int l=0;l<32;l++){int si=n128/16+l/16;uint8_t lo2=(qh[n128/4+l/2]>>((l%2)*4))&0x03,hi2=(qh[n128/4+l/2]>>((l%2)*4+2))&0x03;int8_t q1=(int8_t)((ql[n128+l]&0xF)|(lo2<<4))-32;int8_t q2=(int8_t)((ql[n128+l]>>4)|(hi2<<4))-32;d[b*256+n128+l]=dd*sc[si]*q1;d[b*256+n128+l+32]=dd*sc[si+2]*q2;}for(int l=0;l<32;l++){int si=n128/16+l/16+2;uint8_t lo2=(qh[n128/4+16+l/2]>>((l%2)*4))&0x03,hi2=(qh[n128/4+16+l/2]>>((l%2)*4+2))&0x03;int8_t q1=(int8_t)((ql[n128+32+l]&0xF)|(lo2<<4))-32;int8_t q2=(int8_t)((ql[n128+32+l]>>4)|(hi2<<4))-32;d[b*256+n128+64+l]=dd*sc[si]*q1;d[b*256+n128+64+l+32]=dd*sc[si+2]*q2;}}}
static void deq_q2_k(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/256;b++){uint16_t dr,dmr;memcpy(&dr,s,2);s+=2;memcpy(&dmr,s,2);s+=2;float dd=f16_to_f32(dr),dmn=f16_to_f32(dmr);const uint8_t*sc=s;s+=12;const uint8_t*qs=s;s+=64;for(int sb=0;sb<8;sb++){uint8_t sc2=sc[sb]&0x0F,m=sc[sb+4]&0x0F;float d1=dd*sc2,m1=dmn*m;for(int i=0;i<32;i++){uint8_t byte=qs[sb*8+i/4];uint8_t q2=(byte>>((i%4)*2))&0x03;d[b*256+sb*32+i]=d1*(float)q2-m1;}}}}
static void deq_q3_k(const uint8_t*s,float*d,uint64_t n){for(uint64_t b=0;b<n/256;b++){uint16_t dr;memcpy(&dr,s,2);s+=2;float dd=f16_to_f32(dr);const uint8_t*sc=s;s+=12;const uint8_t*qs=s;s+=94;for(int sb=0;sb<8;sb++){uint8_t sc2=sc[sb]&0x3F;float d1=dd*(sc2-32);for(int i=0;i<32;i++){int idx=sb*32+i;uint8_t q3=(qs[idx/2]>>((idx%2)*4))&7;uint8_t hb=sc[6+idx/8];q3|=((hb>>(idx%8))&1)<<3;d[b*256+idx]=d1*(float)(q3-4);}}}}

void dequant(const GGTensor&t,float*out){uint64_t e=t.elems();switch(t.type){case 0:deq_f32(t.data,out,e);break;case 1:deq_f16(t.data,out,e);break;case 30:deq_bf16(t.data,out,e);break;case 2:deq_q4_0(t.data,out,e);break;case 3:deq_q4_1(t.data,out,e);break;case 8:deq_q8_0(t.data,out,e);break;case 9:deq_q8_1(t.data,out,e);break;case 10:deq_q2_k(t.data,out,e);break;case 11:deq_q3_k(t.data,out,e);break;case 12:deq_q4_k(t.data,out,e);break;case 13:deq_q5_k(t.data,out,e);break;case 14:deq_q6_k(t.data,out,e);break;default:memset(out,0,e*4);}}

// =============================================================================
// TOKENIZER
// =============================================================================
struct Tok{std::vector<std::string> vocab;std::vector<float> scores;std::vector<int32_t> types;std::vector<std::pair<std::string,std::string>> merges;std::unordered_map<std::string,uint32_t> id;uint32_t bos=1,eos=2,unk=0;std::string model="gpt2";std::unordered_map<uint8_t,std::string> b2u;std::unordered_map<std::string,uint8_t> u2b;
    void build_b2u(){std::vector<int> bs,cs;for(int i='!';i<='~';i++)bs.push_back(i);for(int i=0xA1;i<=0xAC;i++)bs.push_back(i);for(int i=0xAE;i<=0xFF;i++)bs.push_back(i);cs=bs;int n=0;for(int b=0;b<256;b++){if(std::find(bs.begin(),bs.end(),b)==bs.end()){bs.push_back(b);cs.push_back(256+n);n++;}}for(size_t i=0;i<bs.size();i++){std::string s;int cp=cs[i];if(cp<0x80)s+=(char)cp;else if(cp<0x800){s+=(char)(0xC0|(cp>>6));s+=(char)(0x80|(cp&0x3F));}else{s+=(char)(0xE0|(cp>>12));s+=(char)(0x80|((cp>>6)&0x3F));s+=(char)(0x80|(cp&0x3F));}b2u[(uint8_t)bs[i]]=s;u2b[s]=(uint8_t)bs[i];}}
    void load(const GGUF&g){build_b2u();auto it=g.msa.find("tokenizer.ggml.tokens");if(it!=g.msa.end())vocab=it->second;auto si=g.mfa.find("tokenizer.ggml.scores");if(si!=g.mfa.end())scores=si->second;auto ti=g.mia.find("tokenizer.ggml.token_type");if(ti!=g.mia.end())types=ti->second;auto mi=g.msa.find("tokenizer.ggml.merges");if(mi!=g.msa.end())for(const auto&m:mi->second){auto sp=m.find(' ');if(sp!=std::string::npos)merges.push_back({m.substr(0,sp),m.substr(sp+1)});}model=g.S("tokenizer.ggml.model","gpt2");for(uint32_t i=0;i<vocab.size();i++)id[vocab[i]]=i;for(uint32_t i=0;i<vocab.size();i++){if(vocab[i]=="<|begin_of_sentence|>"||vocab[i]=="<s>")bos=i;if(vocab[i]=="<|end_of_sentence|>"||vocab[i]=="</s>")eos=i;if(i<types.size()&&types[i]==2)unk=i;}bos=(uint32_t)g.I("tokenizer.ggml.bos_token_id",bos);eos=(uint32_t)g.I("tokenizer.ggml.eos_token_id",eos);}
    std::vector<uint32_t> encode(const std::string&text,bool add_bos=true){std::vector<uint32_t> ids;if(add_bos)ids.push_back(bos);if(model=="llama"||model=="spm"){std::string cur="\xe2\x96\x81";for(size_t i=0;i<text.size();i++){if(text[i]==' '){if(cur.size()>3)ids.push_back(sp(cur));cur="\xe2\x96\x81";}else{cur+=text[i];if(id.count(cur)){ids.push_back(id[cur]);cur="\xe2\x96\x81";}}}if(cur.size()>3)ids.push_back(sp(cur));}else{std::string mapped;for(size_t i=0;i<text.size();i++)mapped+=b2u[(uint8_t)text[i]];std::vector<std::string> words;std::string cur;for(char c:mapped){if(c==' '||c=='\n'||c=='\t'){if(!cur.empty()){words.push_back(cur);cur.clear();}words.push_back(b2u[(uint8_t)' ']);}else cur+=c;}if(!cur.empty())words.push_back(cur);for(const auto&w:words){if(id.count(w)){ids.push_back(id[w]);continue;}auto toks=bpe(w);for(auto t:toks)ids.push_back(t);}}return ids;}
    std::string decode(const std::vector<uint32_t>&ids,bool skip_special=true){std::string mapped;for(auto t:ids){if(t>=vocab.size())continue;const auto&tk=vocab[t];if(skip_special&&tk.size()>1&&tk[0]=='<'&&tk.back()=='>'&&tk.find("0x")==std::string::npos)continue;if(tk.size()==6&&tk[0]=='<'&&tk[1]=='0'&&tk[2]=='x'){uint8_t b=0;for(int i=3;i<5;i++){char c=tk[i];b<<=4;if(c>='0'&&c<='9')b|=c-'0';else if(c>='a'&&c<='f')b|=c-'a'+10;}mapped+=b2u[b];}else if(model=="llama"||model=="spm"){std::string t2=tk;size_t p=0;while((p=t2.find("\xe2\x96\x81"))!=std::string::npos)t2.replace(p,3," ");mapped+=t2;}else mapped+=tk;}if(model!="llama"&&model!="spm"){std::string r;size_t i=0;while(i<mapped.size()){unsigned char c=mapped[i];int l=1;if(c>=0xC0&&c<0xE0)l=2;else if(c>=0xE0&&c<0xF0)l=3;else if(c>=0xF0)l=4;std::string ch=mapped.substr(i,l);auto it=u2b.find(ch);if(it!=u2b.end())r+=(char)it->second;else r+=ch;i+=l;}return r;}return mapped;}
    std::string decode_token(uint32_t t,bool s=true){return decode({t},s);}
private:
    uint32_t sp(const std::string&w){auto it=id.find(w);return it!=id.end()?it->second:unk;}
    std::vector<uint32_t> bpe(const std::string&w){std::vector<std::string> syms;size_t i=0;while(i<w.size()){unsigned char c=w[i];int l=1;if(c>=0xC0&&c<0xE0)l=2;else if(c>=0xE0&&c<0xF0)l=3;else if(c>=0xF0)l=4;syms.push_back(w.substr(i,l));i+=l;}while(syms.size()>1){int best=-1,rank=(int)merges.size();size_t pos=0;for(size_t j=0;j+1<syms.size();j++)for(int k=0;k<(int)merges.size();k++)if(merges[k].first==syms[j]&&merges[k].second==syms[j+1]&&k<rank){rank=k;best=k;pos=j;break;}if(best<0)break;syms[pos]+=syms[pos+1];syms.erase(syms.begin()+pos+1);}std::vector<uint32_t> r;for(const auto&s:syms){auto it=id.find(s);if(it!=id.end())r.push_back(it->second);else for(char c:s){char h[8];snprintf(h,sizeof(h),"<0x%02X>",(uint8_t)c);auto hi=id.find(h);r.push_back(hi!=id.end()?hi->second:unk);}}return r;}
};

// =============================================================================
// ATTENTION GEOMETRY
// =============================================================================
struct AttentionGeometry{uint32_t n_heads=0,n_kv_heads=0,head_dim=0;
    uint32_t q_dim()const{return n_heads*head_dim;}
    uint32_t kv_dim()const{return n_kv_heads*head_dim;}
    uint32_t qkv_dim()const{return q_dim()+kv_dim()*2;}
    uint32_t group()const{return n_heads/std::max(1u,n_kv_heads);}
    uint32_t kv_group(uint32_t q_head)const{return q_head/group();}
    void resolve(const GGUF&g,const std::string&arch){std::string p=arch+".";n_heads=(uint32_t)g.I(p+"attention.head_count",0);n_kv_heads=(uint32_t)g.I(p+"attention.head_count_kv",0);int64_t embd=g.I(p+"embedding_length",7168);int64_t key_len=g.I(p+"attention.key_length",0);head_dim=(uint32_t)(key_len>0?key_len:(n_heads>0?embd/n_heads:128));if(n_heads==0)n_heads=128;if(n_kv_heads==0)n_kv_heads=n_heads;}
    std::string str()const{std::ostringstream s;s<<"H="<<n_heads<<" KHV="<<n_kv_heads<<" D="<<head_dim<<" QD="<<q_dim()<<" KVD="<<kv_dim()<<" QKVD="<<qkv_dim()<<" grp="<<group();return s.str();}
};

// =============================================================================
// RNG
// =============================================================================
struct TokenRNG{uint64_t state;explicit TokenRNG(uint64_t s):state(s?s:12345ULL){}void seed(uint64_t s){state=s?s:12345ULL;}uint32_t next(){state^=state<<13;state^=state>>17;state^=state<<5;return(uint32_t)state;}float probability(){return next()/float(UINT32_MAX);}};

// =============================================================================
// CONTEXT ENGINE
// =============================================================================
enum KVT{FULL,KV_INT8,BIN,MERGED,EVICTED};
struct KVE{KVT t=FULL;std::vector<float> d;std::vector<int8_t> i8;std::vector<uint8_t> bn;std::vector<float> bs;int mc=1;float a=0;bool sink=false;uint32_t tok=0;
    size_t bytes()const{switch(t){case FULL:return d.size()*4;case KV_INT8:return i8.size()+d.size()*4;case BIN:return bn.size()+bs.size()*4;default:return 0;}}
    void get(std::vector<float>&o)const{if(t==FULL||t==MERGED){o=d;return;}if(t==KV_INT8){o.resize(i8.size());for(size_t i=0;i<i8.size();i++){int b=i/32;float s=b<(int)d.size()?d[b]:1.0f;o[i]=(float)i8[i]*s;}return;}if(t==BIN){int n=bn.size()*8;o.resize(n);for(int i=0;i<n;i++){int b=i/256;float s=b<(int)bs.size()?bs[b]:1.0f;o[i]=((bn[i/8]>>(i%8))&1)?s:-s;}return;}o.assign(d.size(),0);}
    void compress(KVT nt){if(t==EVICTED||sink)return;std::vector<float>v;get(v);int n=(int)v.size();if(!n)return;if(nt==KV_INT8){int b=32,nb=(n+b-1)/b;d.resize(nb);i8.resize(n);for(int bi=0;bi<nb;bi++){int st=bi*b,en=std::min(st+b,n);float mx=0;for(int i=st;i<en;i++)mx=std::max(mx,std::abs(v[i]));float s=mx/127;d[bi]=s;for(int i=st;i<en;i++)i8[i]=(int8_t)(v[i]/(s+1e-12f));}t=KV_INT8;return;}if(nt==BIN){int b=256,nb=(n+b-1)/b;bn.resize((n+7)/8,0);bs.resize(nb);for(int bi=0;bi<nb;bi++){int st=bi*b,en=std::min(st+b,n);float ma=0;for(int i=st;i<en;i++)ma+=std::abs(v[i]);ma/=std::max(1,en-st);bs[bi]=ma;for(int i=st;i<en;i++)if(v[i]>=0)bn[i/8]|=(1<<(i%8));}t=BIN;return;}}
};
struct CtxState{std::vector<uint32_t> tokens;std::vector<std::vector<KVE>> kk,kv;int pos=0,win=8192,dim=0,sinks=4;std::set<int> sink_pos;bool mla=false;
    void init(int nl,int d,int w,bool m){dim=d;win=w;mla=m;kk.resize(nl);kv.resize(nl);}
    void add(uint32_t tok,int l,const float*kd,const float*vd){if(l==0){tokens.push_back(tok);bool s=(int)tokens.size()-1<sinks;if(s)sink_pos.insert((int)tokens.size()-1);}KVE e;e.d.assign(kd,kd+dim);e.t=FULL;e.sink=(int)tokens.size()-1<sinks;e.tok=tok;kk[l].push_back(e);e.d.assign(vd,vd+dim);kv[l].push_back(e);}
    void get(int l,int p,std::vector<float>&k,std::vector<float>&v)const{if(l<(int)kk.size()&&p<(int)kk[l].size())kk[l][p].get(k);else k.assign(dim,0);if(l<(int)kv.size()&&p<(int)kv[l].size())kv[l][p].get(v);else v.assign(dim,0);}
    bool full()const{return(int)tokens.size()>=win;}
    size_t bytes()const{size_t b=0;for(const auto&l:kk)for(const auto&e:l)b+=e.bytes();for(const auto&l:kv)for(const auto&e:l)b+=e.bytes();return b;}
    std::vector<int> valid(int l=0)const{std::vector<int>v;for(size_t i=0;i<tokens.size();i++)if(l<(int)kk.size()&&i<(int)kk[l].size()&&kk[l][i].t!=EVICTED)v.push_back((int)i);return v;}
    void compress_age(){int n=(int)tokens.size();int fs=n-(int)(win*0.25),is=n-(int)(win*0.5),bs=n-(int)(win*0.75);for(int l=0;l<(int)kk.size();l++)for(int p=0;p<n;p++){if(sink_pos.count(p))continue;KVT tgt=p>=fs?FULL:p>=is?KV_INT8:p>=bs?BIN:MERGED;if(kk[l][p].t>tgt)kk[l][p].compress(tgt);if(kv[l][p].t>tgt)kv[l][p].compress(tgt);}}
    std::string report()const{std::ostringstream s;int c[5]={0};for(const auto&l:kk)for(const auto&e:l)c[e.t]++;s<<"Ctx: "<<tokens.size()<<"/"<<win<<" KV:"<<bytes()/(1024*1024)<<"MB F="<<c[0]<<" I8="<<c[2]<<" B="<<c[3]<<" M="<<c[4]<<" E="<<c[5]<<"\n";return s.str();}
};
struct CtxEngine{CtxState st;void init(int nl,int d,int w,bool m){st.init(nl,d,w,m);}void add(uint32_t tok,const float*kd,const float*vd){for(int l=0;l<(int)st.kk.size();l++)st.add(tok,l,kd,vd);if(st.full())st.compress_age();}void get(int l,int p,std::vector<float>&k,std::vector<float>&v)const{st.get(l,p,k,v);}auto valid()const{return st.valid();}void record(int l,int p,float a){if(l<(int)st.kk.size()&&p<(int)st.kk[l].size())st.kk[l][p].a+=a;}void compress(){st.compress_age();}std::string report()const{return st.report();}};

// =============================================================================
// MODEL — with Orchestrator integration
// =============================================================================
struct Model {
    GGUF gguf;
    Tok tok;
    CtxEngine ctx;
    AttentionGeometry geom;
    HotPatchRegistry registry;
    Orchestrator decider;

    int nl=61, ne=7168, ffd=2048, nv=129280, nexp=256, neu=8;
    int qlr=1536, klr=512;
    float rf=10000, reps=1e-6f;
    bool mla=false, moe=false, shrd=false;

    Model() : decider(&registry, &gguf) {}

    bool load(const std::string& path) {
        if (!gguf.load(path)) return false;
        tok.load(gguf);

        std::string a = gguf.S("general.architecture", "deepseek2"), pr = a + ".";
        nl = (int)gguf.I(pr+"block_count", 61);
        ne = (int)gguf.I(pr+"embedding_length", 7168);
        nv = (int)gguf.I(pr+"vocab_size", gguf.has("output.weight") ? (int)gguf.tensors[gguf.tmap["output.weight"]].dims[0] : 129280);
        nexp = (int)gguf.I(pr+"expert_count", 0);
        neu = (int)gguf.I(pr+"expert_used_count", 0);
        ffd = (int)gguf.I(pr+"feed_forward_length", 2048);
        qlr = (int)gguf.I(pr+"attention.q_lora_rank", 0);
        klr = (int)gguf.I(pr+"attention.kv_lora_rank", 0);
        rf = gguf.F(pr+"rope.freq_base", 10000);
        reps = gguf.F(pr+"attention.layer_norm_rms_epsilon", 1e-6f);

        geom.resolve(gguf, a);
        mla = qlr > 0 && klr > 0;
        moe = nexp > 1;
        shrd = gguf.has("blk.0.ffn_gate_shrd.weight");

        int kv_d = mla ? (klr + geom.head_dim) : geom.kv_dim();
        ctx.init(nl, kv_d, 8192, mla);

        // Register all tensors in HotPatch registry
        for (const auto& t : gguf.tensors) {
            uint64_t exp_bytes = t.elems() * 4;
            int layer = -1, expert = -1;
            if (t.name.find("blk.") == 0) {
                auto dot = t.name.find('.', 4);
                if (dot != std::string::npos) layer = std::stoi(t.name.substr(4, dot - 4));
            }
            if (t.name.find("_exp.") != std::string::npos) {
                auto exp_pos = t.name.find("_exp.") + 5;
                auto dot = t.name.find('.', exp_pos);
                if (dot != std::string::npos) expert = std::stoi(t.name.substr(exp_pos, dot - exp_pos));
            }
            registry.register_tensor(t.name, t.nbytes, exp_bytes, layer, expert);
        }

        decider.init_model(nl);
        decider.pin_critical();

        fprintf(stderr, "[Model] %s L=%d D=%d %s mla=%d moe=%d/%d shrd=%d\n",
                a.c_str(), nl, ne, geom.str().c_str(), mla, moe, nexp, shrd);
        fprintf(stderr, "[HotPatch] %zu tensors registered\n", registry.entries.size());

        return true;
    }

    const float* S(const std::string& name) { return decider.uncold(name); }
    void release(const std::string& name) { /* let decider handle via eviction */ }
    void evict_layer(int layer) { decider.evict_layer(layer); }
    void evict_non_selected_experts(int layer, const std::vector<int>& selected) { decider.evict_non_selected_experts(layer, selected); }
    bool has(const std::string& n) const { return gguf.has(n); }

    void mm(const float* W, const float* A, float* C, int M, int K) {
        for (int m = 0; m < M; m++) {
            double s = 0;
            const float* w = W + (size_t)m * K;
            for (int k = 0; k < K; k++) s += (double)w[k] * A[k];
            C[m] = (float)s;
        }
    }

    void rmsn(float* x, const float* w, int n, float e) {
        double ss = 0;
        for (int i = 0; i < n; i++) ss += (double)x[i] * x[i];
        ss = 1.0 / sqrt(ss / n + e);
        for (int i = 0; i < n; i++) x[i] = (float)(x[i] * ss * w[i]);
    }

    void rope(float* x, int nh, int dim, int pos, float base) {
        for (int d = 0; d < dim; d += 2) {
            float f = 1.0f / powf(base, (float)d / dim), a = pos * f, c = cosf(a), s = sinf(a);
            for (int h = 0; h < nh; h++) {
                float* xh = x + h * dim;
                xh[d] = xh[d] * c - xh[d+1] * s;
                xh[d+1] = xh[d] * s + xh[d+1] * c;
            }
        }
    }

    float silu(float x) { return x / (1.0f + expf(-x)); }

    std::vector<float> forward(uint32_t tid, int pos) {
        const float* emb = S("token_embd.weight");
        std::vector<float> h(ne);
        memcpy(h.data(), emb + (size_t)tid * ne, ne * 4);

        for (int l = 0; l < nl; l++) {
            std::string p = "blk." + std::to_string(l) + ".";

            decider.prefetch_layers(l, nl);
            decider.drain_prefetch();
            decider.pin_layer_attention(l);

            auto hc = h;
            const float* attn_norm = S(p + "attn_norm.weight");
            rmsn(h.data(), attn_norm, ne, reps);

            if (mla) fwd_mla(l, h, pos, tid, p);
            else fwd_gqa(l, h, pos, tid, p);

            for (int i = 0; i < ne; i++) h[i] = hc[i] + h[i];

            auto hc2 = h;
            const float* ffn_norm = S(p + "ffn_norm.weight");
            rmsn(h.data(), ffn_norm, ne, reps);

            if (moe) fwd_moe(l, h, p);
            else fwd_ffn(l, h, p);

            for (int i = 0; i < ne; i++) h[i] = hc2[i] + h[i];

            evict_layer(l);
            if (l + 1 < nl) decider.wait_prefetch();
        }

        const float* out_norm = S("output_norm.weight");
        rmsn(h.data(), out_norm, ne, reps);

        const float* out_w = S("output.weight");
        std::vector<float> logits(nv);
        mm(out_w, h.data(), logits.data(), nv, ne);

        decider.demote("output.weight");
        return logits;
    }

private:
    void fwd_mla(int l, std::vector<float>& h, int pos, uint32_t tid, const std::string& p) {
        const float* qa_w = S(p + "attn_q_a.weight");
        std::vector<float> qa(qlr);
        mm(qa_w, h.data(), qa.data(), qlr, ne);

        if (has(p + "attn_q_a_norm.weight")) {
            const float* qan = S(p + "attn_q_a_norm.weight");
            rmsn(qa.data(), qan, qlr, reps);
        }

        const float* qb_w = S(p + "attn_q_b.weight");
        std::vector<float> q(geom.q_dim());
        mm(qb_w, qa.data(), q.data(), geom.q_dim(), qlr);

        int kva = klr + geom.head_dim;
        const float* kva_w = S(p + "attn_kv_a_mqa.weight");
        std::vector<float> ka(kva);
        mm(kva_w, h.data(), ka.data(), kva, ne);

        std::vector<float> kc(ka.begin(), ka.begin() + klr), kr(ka.begin() + klr, ka.end());
        if (has(p + "attn_kv_a_norm.weight")) {
            const float* kvn = S(p + "attn_kv_a_norm.weight");
            rmsn(kc.data(), kvn, klr, reps);
        }

        std::vector<float> comb(kva);
        memcpy(comb.data(), kc.data(), klr * 4);
        memcpy(comb.data() + klr, kr.data(), geom.head_dim * 4);
        ctx.add(tid, comb.data(), comb.data());

        rope(q.data(), geom.n_heads, geom.head_dim, pos, rf);

        auto vp = ctx.valid();
        float scale = 1.0f / sqrtf((float)geom.head_dim);
        std::vector<float> ao(ne, 0);

        const float* kb_w = S(p + "attn_k_b.weight");
        const float* vb_w = S(p + "attn_v_b.weight");

        for (int hi = 0; hi < geom.n_heads; hi++) {
            float* qh = q.data() + hi * geom.head_dim;
            std::vector<float> sc;
            sc.reserve(vp.size());

            for (int p2 : vp) {
                std::vector<float> kd;
                ctx.get(l, p2, kd, kd);
                std::vector<float> kk(geom.q_dim());
                mm(kb_w, kd.data(), kk.data(), geom.q_dim(), klr);
                float s = 0;
                for (int d = 0; d < geom.head_dim; d++) s += qh[d] * kk[hi * geom.head_dim + d];
                sc.push_back(s * scale);
                ctx.record(l, p2, std::abs(s * scale));
            }

            float mx = *std::max_element(sc.begin(), sc.end());
            float sm = 0;
            for (auto& s : sc) { s = expf(s - mx); sm += s; }
            for (auto& s : sc) s /= sm;

            for (size_t i = 0; i < vp.size(); i++) {
                int p2 = vp[i];
                std::vector<float> kd;
                ctx.get(l, p2, kd, kd);
                std::vector<float> vv(geom.q_dim());
                mm(vb_w, kd.data(), vv.data(), geom.q_dim(), klr);
                for (int d = 0; d < geom.head_dim; d++)
                    ao[hi * geom.head_dim + d] += sc[i] * vv[hi * geom.head_dim + d];
            }
        }

        const float* ao_w = S(p + "attn_output.weight");
        std::vector<float> r(ne);
        mm(ao_w, ao.data(), r.data(), ne, ne);
        std::copy(r.begin(), r.end(), h.begin());
    }

    void fwd_gqa(int l, std::vector<float>& h, int pos, uint32_t tid, const std::string& p) {
        int qd = geom.q_dim(), kvd = geom.kv_dim();
        std::vector<float> q(qd), k(kvd), v(kvd);

        if (has(p + "attn_qkv.weight")) {
            int qkv_total = geom.qkv_dim();
            const float* qkv_w = S(p + "attn_qkv.weight");
            std::vector<float> qkv(qkv_total);
            mm(qkv_w, h.data(), qkv.data(), qkv_total, ne);
            memcpy(q.data(), qkv.data(), qd * 4);
            memcpy(k.data(), qkv.data() + qd, kvd * 4);
            memcpy(v.data(), qkv.data() + qd + kvd, kvd * 4);
        } else {
            const float* qw = S(p + "attn_q.weight");
            mm(qw, h.data(), q.data(), qd, ne);
            const float* kw = S(p + "attn_k.weight");
            mm(kw, h.data(), k.data(), kvd, ne);
            const float* vw = S(p + "attn_v.weight");
            mm(vw, h.data(), v.data(), kvd, ne);
        }

        rope(q.data(), geom.n_heads, geom.head_dim, pos, rf);
        rope(k.data(), geom.n_kv_heads, geom.head_dim, pos, rf);
        ctx.add(tid, k.data(), v.data());

        auto vp = ctx.valid();
        float scale = 1.0f / sqrtf((float)geom.head_dim);
        std::vector<float> ao(ne, 0);

        for (int qh = 0; qh < (int)geom.n_heads; qh++) {
            int kvh = geom.kv_group(qh);
            float* qh_ptr = q.data() + qh * geom.head_dim;
            std::vector<float> sc;
            sc.reserve(vp.size());

            for (int p2 : vp) {
                std::vector<float> kd, vd;
                ctx.get(l, p2, kd, vd);
                float* kh = kd.data() + kvh * geom.head_dim;
                float s = 0;
                for (int d = 0; d < geom.head_dim; d++) s += qh_ptr[d] * kh[d];
                sc.push_back(s * scale);
                ctx.record(l, p2, std::abs(s * scale));
            }

            float mx = *std::max_element(sc.begin(), sc.end());
            float sm = 0;
            for (auto& s : sc) { s = expf(s - mx); sm += s; }
            for (auto& s : sc) s /= sm;

            for (size_t i = 0; i < vp.size(); i++) {
                int p2 = vp[i];
                std::vector<float> kd, vd;
                ctx.get(l, p2, kd, vd);
                float* vh = vd.data() + kvh * geom.head_dim;
                for (int d = 0; d < geom.head_dim; d++)
                    ao[qh * geom.head_dim + d] += sc[i] * vh[d];
            }
        }

        const float* ao_w = S(p + "attn_output.weight");
        std::vector<float> r(ne);
        mm(ao_w, ao.data(), r.data(), ne, ne);
        std::copy(r.begin(), r.end(), h.begin());
    }

    void fwd_moe(int l, std::vector<float>& h, const std::string& p) {
        const float* gate_w = S(p + "ffn_gate_inp.weight");
        std::vector<float> rl(nexp);
        mm(gate_w, h.data(), rl.data(), nexp, ne);

        float mx = *std::max_element(rl.begin(), rl.end());
        float sm = 0;
        std::vector<float> pr(nexp);
        for (int e = 0; e < nexp; e++) { pr[e] = expf(rl[e] - mx); sm += pr[e]; }
        for (auto& x : pr) x /= sm;

        std::vector<int> idx(nexp);
        std::iota(idx.begin(), idx.end(), 0);
        std::partial_sort(idx.begin(), idx.begin() + neu, idx.end(),
            [&](int a, int b) { return pr[a] > pr[b]; });

        std::vector<int> selected(idx.begin(), idx.begin() + neu);

        // Record selected experts for affinity cache
        decider.record_experts(l, selected);
        evict_non_selected_experts(l, selected);

        float ts = 0;
        for (int i = 0; i < neu; i++) ts += pr[idx[i]];

        std::vector<float> fo(ne, 0);

        for (int i = 0; i < neu; i++) {
            int e = idx[i];
            float w = pr[e] / ts;

            std::string ep = p + "ffn_gate_exp." + std::to_string(e) + ".weight";
            std::string up = p + "ffn_up_exp." + std::to_string(e) + ".weight";
            std::string dn = p + "ffn_down_exp." + std::to_string(e) + ".weight";

            const float* gw = S(ep);
            const float* uw = S(up);
            const float* dw = S(dn);
            if (!gw || !uw || !dw) continue;

            std::vector<float> g(ffd), u(ffd), d(ne);
            mm(gw, h.data(), g.data(), ffd, ne);
            for (auto& x : g) x = silu(x);
            mm(uw, h.data(), u.data(), ffd, ne);
            for (int j = 0; j < ffd; j++) g[j] *= u[j];
            mm(dw, g.data(), d.data(), ne, ffd);
            for (int j = 0; j < ne; j++) fo[j] += w * d[j];
        }

        if (shrd) {
            const float* gw = S(p + "ffn_gate_shrd.weight");
            const float* uw = S(p + "ffn_up_shrd.weight");
            const float* dw = S(p + "ffn_down_shrd.weight");
            if (gw && uw && dw) {
                std::vector<float> g(ffd), u(ffd), d(ne);
                mm(gw, h.data(), g.data(), ffd, ne);
                for (auto& x : g) x = silu(x);
                mm(uw, h.data(), u.data(), ffd, ne);
                for (int j = 0; j < ffd; j++) g[j] *= u[j];
                mm(dw, g.data(), d.data(), ne, ffd);
                for (int j = 0; j < ne; j++) fo[j] += d[j];
            }
        }

        std::copy(fo.begin(), fo.end(), h.begin());
    }

    void fwd_ffn(int l, std::vector<float>& h, const std::string& p) {
        const float* gw = S(p + "ffn_gate.weight");
        const float* uw = S(p + "ffn_up.weight");
        const float* dw = S(p + "ffn_down.weight");
        if (!gw || !uw || !dw) { std::fill(h.begin(), h.end(), 0); return; }
        std::vector<float> g(ffd), u(ffd), d(ne);
        mm(gw, h.data(), g.data(), ffd, ne);
        for (auto& x : g) x = silu(x);
        mm(uw, h.data(), u.data(), ffd, ne);
        for (int j = 0; j < ffd; j++) g[j] *= u[j];
        mm(dw, g.data(), d.data(), ne, ffd);
        std::copy(d.begin(), d.end(), h.begin());
    }
};

// =============================================================================
// SAMPLER
// =============================================================================
struct Sampler {
    TokenRNG rng{42};
    float temp=0.7f, top_p=0.9f, min_p=0.05f, rep=1.0f, freq=0, pres=0;
    int top_k=40;
    std::vector<uint32_t> recent;

    void apply_pen(std::vector<float>& l) {
        if (rep==1 && freq==0 && pres==0) return;
        std::unordered_map<uint32_t,int> c;
        for (auto t : recent) c[t]++;
        for (auto& [t,n] : c) {
            if (t >= l.size()) continue;
            if (rep != 1) l[t] < 0 ? l[t] *= rep : l[t] /= rep;
            if (freq > 0) l[t] -= freq * n;
            if (pres > 0) l[t] -= pres;
        }
    }

    uint32_t sample(std::vector<float>& l) {
        apply_pen(l);
        if (temp <= 0.01f) return argmax(l);
        std::vector<std::pair<uint32_t,float>> sc(l.size());
        for (uint32_t i = 0; i < l.size(); i++) sc[i] = {i, l[i]/temp};
        std::sort(sc.begin(), sc.end(), [](auto&a, auto&b) { return a.second > b.second; });
        if (top_k > 0 && top_k < (int)sc.size()) sc.resize(top_k);
        float mx = sc[0].second, sm = 0;
        for (auto& s : sc) { s.second = expf(s.second - mx); sm += s.second; }
        if (min_p > 0) {
            float th = min_p * sc[0].second;
            size_t c = 0;
            for (size_t i = 0; i < sc.size(); i++) { if (sc[i].second >= th) c = i+1; else break; }
            sc.resize(std::max(c, (size_t)1));
            sm = 0; for (auto& s : sc) sm += s.second;
        }
        if (top_p < 1) {
            float cu = 0; size_t c = sc.size();
            for (size_t i = 0; i < sc.size(); i++) { cu += sc[i].second/sm; if (cu >= top_p) { c = i+1; break; } }
            sc.resize(c); sm = 0; for (auto& s : sc) sm += s.second;
        }
        float r = rng.probability() * sm, c = 0;
        for (const auto& s : sc) { c += s.second; if (r <= c) return s.first; }
        return sc[0].first;
    }

    uint32_t argmax(const std::vector<float>& v) {
        return (uint32_t)std::distance(v.begin(), std::max_element(v.begin(), v.end()));
    }

    void obs(uint32_t t) { recent.push_back(t); }
};

// =============================================================================
// MAIN
// =============================================================================
#ifndef RAWRXD_LIBRARY
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n"
            "  rawrxd run      <model> \"prompt\" [--temp 0.7] [-n 4096]\n"
            "  rawrxd validate <model> \"prompt\"\n"
            "  rawrxd bench    <model>\n"
            "  rawrxd ctx      <model> \"prompt\"\n");
        return 1;
    }

    std::string cmd = argv[1], mp, prompt;
    float temp=0.7f, top_p=0.9f, min_p=0.05f, rep=1.0f, freq=0, pres=0;
    int top_k=40, max_t=4096;
    bool det=false;
    uint64_t token_seed=42;

    if (argc < 3) { fprintf(stderr, "Need model\n"); return 1; }
    mp = argv[2];
    if (argc >= 4) prompt = argv[3];

    for (int i = 4; i < argc; i++) {
        std::string f = argv[i];
        auto next = [&]() { return i+1 < argc ? argv[++i] : nullptr; };
        if (f=="--temp"||f=="-t") { if(auto v=next()) temp=std::stof(v); }
        else if (f=="--top-k") { if(auto v=next()) top_k=std::stoi(v); }
        else if (f=="--top-p") { if(auto v=next()) top_p=std::stof(v); }
        else if (f=="--min-p") { if(auto v=next()) min_p=std::stof(v); }
        else if (f=="--rep-pen") { if(auto v=next()) rep=std::stof(v); }
        else if (f=="--freq-pen") { if(auto v=next()) freq=std::stof(v); }
        else if (f=="--pres-pen") { if(auto v=next()) pres=std::stof(v); }
        else if (f=="--max-tokens"||f=="-n") { if(auto v=next()) max_t=std::stoi(v); }
        else if (f=="--deterministic") det=true;
        else if (f=="--seed") { if(auto v=next()) token_seed=std::stoull(v); }
    }

    auto find_model = [](std::string n) -> std::string {
        if (std::filesystem::exists(n)) return n;
        std::string ps[] = {"F:\\OllamaModels\\"+n+".gguf", "F:\\OllamaModels\\"+n,
                           "D:\\rawrxd\\models\\"+n+".gguf", n+".gguf", "F:\\OllamaModels\\blobs\\"+n};
        for (const auto& p : ps) if (std::filesystem::exists(p)) return p;
        return n;
    };
    mp = find_model(mp);
    if (!std::filesystem::exists(mp)) { fprintf(stderr, "Not found: %s\n", mp.c_str()); return 1; }

    fprintf(stderr, "╔══════════════════════════════════════╗\n"
                    "║  RawrXD Inference Engine + Orchestrator ║\n"
                    "╚══════════════════════════════════════╝\n");

    Model m;
    if (!m.load(mp)) { fprintf(stderr, "Load failed\n"); return 1; }

    if (cmd == "validate") {
        fprintf(stderr, "=== VALIDATION ===\n\n--- Dequant ---\n");
        int pa=0, fa=0;
        for (const auto& t : m.gguf.tensors) {
            uint64_t e = t.elems();
            std::vector<float> d1(e), d2(e);
            dequant(t, d1.data()); dequant(t, d2.data());
            bool ok = true;
            for (uint64_t i = 0; i < e; i++) if (d1[i] != d2[i]) { ok = false; break; }
            if (ok) pa++; else { fa++; if (fa < 10) fprintf(stderr, "FAIL: %s (type=%u)\n", t.name.c_str(), t.type); }
        }
        fprintf(stderr, "Dequant: %d pass %d fail\n\n--- Tokenizer ---\n", pa, fa);
        std::string test = "The quick brown fox 123 world!";
        auto enc = m.tok.encode(test, true);
        auto dec = m.tok.decode(enc, false);
        fprintf(stderr, "Encode: %zu tokens\nDecode: %s\n", enc.size(), dec.find("quick")!=std::string::npos ? "PASS" : "FAIL");
        fprintf(stderr, "\n--- Geometry ---\n%s\n", m.geom.str().c_str());
        fprintf(stderr, "\n--- HotPatch ---\n%s\n", m.registry.report().c_str());

        auto toks = m.tok.encode("Hello", true);
        auto t0 = std::chrono::steady_clock::now();
        auto lg = m.forward(toks[0], 0);
        auto t1 = std::chrono::steady_clock::now();
        fprintf(stderr, "\n--- Forward ---\nForward: %.1f ms\nLogits[0..4]: %.4f %.4f %.4f %.4f %.4f\n",
                std::chrono::duration<double,std::milli>(t1-t0).count(), lg[0], lg[1], lg[2], lg[3], lg[4]);
        fprintf(stderr, "\n--- Orchestrator ---\n%s", m.decider.report().c_str());
        fprintf(stderr, "\n--- Model ---\nTensors: %zu MLA=%d MoE=%d/%d Shrd=%d\n",
                m.gguf.tensors.size(), m.mla, m.moe, m.nexp, m.shrd);
        return 0;
    }

    if (cmd == "bench") {
        fprintf(stderr, "=== BENCH ===\n");
        auto toks = m.tok.encode("Benchmark test prompt for throughput measurement xyz 123", true);
        auto t0 = std::chrono::steady_clock::now();
        std::vector<float> lg;
        for (size_t i = 0; i < toks.size(); i++) lg = m.forward(toks[i], (int)i);
        auto t1 = std::chrono::steady_clock::now();
        double pf = std::chrono::duration<double,std::milli>(t1-t0).count();
        fprintf(stderr, "Prefill: %zu tokens %.0fms (%.1f tps)\n", toks.size(), pf, toks.size()/(pf/1000));
        auto t2 = std::chrono::steady_clock::now();
        Sampler s; s.temp=temp; s.top_k=top_k; s.top_p=top_p;
        int pos = (int)toks.size();
        for (int i = 0; i < 50; i++) { uint32_t t = s.sample(lg); lg = m.forward(t, pos++); }
        auto t3 = std::chrono::steady_clock::now();
        double gm = std::chrono::duration<double,std::milli>(t3-t2).count();
        fprintf(stderr, "Gen: 50 tokens %.0fms (%.1f tps)\n", gm, 50.0/(gm/1000));
        fprintf(stderr, "%s%s", m.decider.report().c_str(), m.ctx.report().c_str());
        return 0;
    }

    if (cmd == "ctx") {
        fprintf(stderr, "=== CONTEXT ENGINE ===\n");
        auto toks = m.tok.encode(prompt, true);
        auto lg = m.forward(toks[0], 0);
        fprintf(stderr, "1 token: %s", m.ctx.report().c_str());
        for (size_t i = 1; i < std::min(toks.size(), (size_t)20); i++) lg = m.forward(toks[i], (int)i);
        fprintf(stderr, "%zu tokens: %s", std::min(toks.size(), (size_t)20), m.ctx.report().c_str());
        m.ctx.compress();
        fprintf(stderr, "After compress: %s", m.ctx.report().c_str());
        return 0;
    }

    // run
    std::string chat = "<|begin_of_sentence|>User: " + prompt + "\nAssistant:";
    auto toks = m.tok.encode(chat, false);
    toks.insert(toks.begin(), m.tok.bos);
    fprintf(stderr, "Prompt: %zu tokens\n", toks.size());

    auto t0 = std::chrono::steady_clock::now();
    std::vector<float> lg;
    for (size_t i = 0; i < toks.size(); i++) lg = m.forward(toks[i], (int)i);
    auto t1 = std::chrono::steady_clock::now();
    double pf = std::chrono::duration<double,std::milli>(t1-t0).count();
    fprintf(stderr, "Prefill: %.0fms (%.1f tps)\n", pf, toks.size()/(pf/1000));
    fprintf(stderr, "\n──────────────────────\n");

    Sampler s; s.temp=temp; s.top_k=top_k; s.top_p=top_p; s.min_p=min_p; s.rep=rep; s.freq=freq; s.pres=pres;
    if (det) s.rng.seed(token_seed);

    int pos = (int)toks.size();
    uint64_t gen = 0;
    auto t2 = std::chrono::steady_clock::now();

    for (int i = 0; i < max_t; i++) {
        uint32_t t = s.sample(lg);
        if (t == m.tok.eos) break;
        printf("%s", m.tok.decode_token(t).c_str());
        fflush(stdout);
        s.obs(t);
        lg = m.forward(t, pos++);
        gen++;
        if (gen % 25 == 0) {
            auto nw = std::chrono::steady_clock::now();
            double el = std::chrono::duration<double,std::milli>(nw-t2).count();
            fprintf(stderr, "\r[%.1f tps] HOT:%lluMB evict:%llu promote:%llu",
                    gen/(el/1000),
                    (unsigned long long)m.decider.current_hot_bytes/(1024*1024),
                    (unsigned long long)m.decider.evictions.load(),
                    (unsigned long long)m.decider.promotes.load());
        }
    }

    auto t3 = std::chrono::steady_clock::now();
    double gm = std::chrono::duration<double,std::milli>(t3-t2).count();
    fprintf(stderr, "\n──────────────────────\n");
    fprintf(stderr, "Tokens: %llu TPS: %.1f Time: %.1fs\n", (unsigned long long)gen, gen/(gm/1000), gm/1000);
    fprintf(stderr, "%s%s", m.decider.report().c_str(), m.ctx.report().c_str());

    return 0;
}

#endif // RAWRXD_LIBRARY
