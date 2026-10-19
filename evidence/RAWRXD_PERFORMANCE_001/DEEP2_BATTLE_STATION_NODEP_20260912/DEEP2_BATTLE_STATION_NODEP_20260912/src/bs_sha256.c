#include "bs_sha256.h"
#include <stdio.h>
#include <string.h>
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static uint32_t be32(const uint8_t*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static void block(BsSha256*s,const uint8_t*b){uint32_t w[64],a,bv,c,d,e,f,g,h,t1,t2;int i;for(i=0;i<16;i++)w[i]=be32(b+4*i);for(i=16;i<64;i++){uint32_t x=w[i-15],y=w[i-2];w[i]=(ROR(x,7)^ROR(x,18)^(x>>3))+w[i-16]+(ROR(y,17)^ROR(y,19)^(y>>10))+w[i-7];}a=s->h[0];bv=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];for(i=0;i<64;i++){uint32_t S1=ROR(e,6)^ROR(e,11)^ROR(e,25),ch=(e&f)^((~e)&g),S0=ROR(a,2)^ROR(a,13)^ROR(a,22),maj=(a&bv)^(a&c)^(bv&c);t1=h+S1+ch+K[i]+w[i];t2=S0+maj;h=g;g=f;f=e;e=d+t1;d=c;c=bv;bv=a;a=t1+t2;}s->h[0]+=a;s->h[1]+=bv;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;}
void bs_sha256_init(BsSha256*s){static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(s->h,iv,sizeof iv);s->bits=0;s->used=0;}
void bs_sha256_update(BsSha256*s,const void*vp,size_t n){const uint8_t*p=(const uint8_t*)vp;s->bits+=(uint64_t)n*8;while(n){size_t k=64-s->used;if(k>n)k=n;memcpy(s->buf+s->used,p,k);s->used+=k;p+=k;n-=k;if(s->used==64){block(s,s->buf);s->used=0;}}}
void bs_sha256_final(BsSha256*s,uint8_t out[32]){size_t i;s->buf[s->used++]=0x80;if(s->used>56){while(s->used<64)s->buf[s->used++]=0;block(s,s->buf);s->used=0;}while(s->used<56)s->buf[s->used++]=0;for(i=0;i<8;i++)s->buf[63-i]=(uint8_t)(s->bits>>(8*i));block(s,s->buf);for(i=0;i<8;i++){out[4*i]=(uint8_t)(s->h[i]>>24);out[4*i+1]=(uint8_t)(s->h[i]>>16);out[4*i+2]=(uint8_t)(s->h[i]>>8);out[4*i+3]=(uint8_t)s->h[i];}}
int bs_sha256_file_hex(const char*path,char out[65]){FILE*f=fopen(path,"rb");uint8_t buf[65536],dig[32];size_t n,i;BsSha256 s;if(!f)return 0;bs_sha256_init(&s);while((n=fread(buf,1,sizeof buf,f))>0)bs_sha256_update(&s,buf,n);if(ferror(f)){fclose(f);return 0;}fclose(f);bs_sha256_final(&s,dig);for(i=0;i<32;i++)sprintf(out+2*i,"%02x",dig[i]);out[64]=0;return 1;}
