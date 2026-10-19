#include "d2u.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

static float f16(uint16_t h){
    uint32_t s=(uint32_t)(h>>15),e=(h>>10)&31u,m=h&1023u,u;
    if(e==0){if(m==0)u=s<<31;else{int ee=1;while((m&1024u)==0){m<<=1;ee--;}m&=1023u;u=(s<<31)|((uint32_t)(ee+112)<<23)|(m<<13);}}
    else if(e==31)u=(s<<31)|0x7f800000u|(m<<13);
    else u=(s<<31)|((e+112u)<<23)|(m<<13);
    {float x;memcpy(&x,&u,4);return x;}
}
static float bf16(uint16_t b){uint32_t u=(uint32_t)b<<16;float x;memcpy(&x,&u,4);return x;}
static uint16_t u16le(const uint8_t*p){uint16_t v;memcpy(&v,p,2);return v;}
static float f32le(const uint8_t*p){float v;memcpy(&v,p,4);return v;}
static void scale_min_k4(const uint8_t*s,int j,int*sc,int*mn){
    if(j<4){*sc=s[j]&63;*mn=s[j+4]&63;}
    else{*sc=(s[j+4]&15)|((s[j-4]>>6)<<4);*mn=(s[j+4]>>4)|((s[j]>>6)<<4);}
}
int d2u_dequant_block(uint32_t type,const uint8_t*b,float*y,size_t cap,size_t*nout){
    size_t i; if(!b||!y||!nout)return D2U_E_ARG;
#define NEED(N) do{if(cap<(N))return D2U_E_RANGE;*nout=(N);}while(0)
    switch(type){
    case D2U_F32: NEED(1); y[0]=f32le(b); return 0;
    case D2U_F16: NEED(1); y[0]=f16(u16le(b)); return 0;
    case D2U_BF16:NEED(1); y[0]=bf16(u16le(b));return 0;
    case D2U_Q4_0:{float d=f16(u16le(b));const uint8_t*q=b+2;NEED(32);for(i=0;i<16;i++){y[i]=d*((int)(q[i]&15)-8);y[i+16]=d*((int)(q[i]>>4)-8);}return 0;}
    case D2U_Q4_1:{float d=f16(u16le(b)),m=f16(u16le(b+2));const uint8_t*q=b+4;NEED(32);for(i=0;i<16;i++){y[i]=d*(q[i]&15)+m;y[i+16]=d*(q[i]>>4)+m;}return 0;}
    case D2U_Q5_0:{float d=f16(u16le(b));uint32_t h;const uint8_t*q=b+6;memcpy(&h,b+2,4);NEED(32);for(i=0;i<16;i++){int a=(q[i]&15)|(((h>>i)&1u)<<4);int c=(q[i]>>4)|(((h>>(i+16))&1u)<<4);y[i]=d*(a-16);y[i+16]=d*(c-16);}return 0;}
    case D2U_Q5_1:{float d=f16(u16le(b)),m=f16(u16le(b+2));uint32_t h;const uint8_t*q=b+8;memcpy(&h,b+4,4);NEED(32);for(i=0;i<16;i++){int a=(q[i]&15)|(((h>>i)&1u)<<4);int c=(q[i]>>4)|(((h>>(i+16))&1u)<<4);y[i]=d*a+m;y[i+16]=d*c+m;}return 0;}
    case D2U_Q8_0:{float d=f16(u16le(b));const int8_t*q=(const int8_t*)(b+2);NEED(32);for(i=0;i<32;i++)y[i]=d*q[i];return 0;}
    case D2U_Q2_K:{const uint8_t*sc=b,*q=b+16;float d=f16(u16le(b+80)),dm=f16(u16le(b+82));int g,l;NEED(256);for(g=0;g<16;g++){int chunk=g/8,rem=g%8,sh=2*(rem/2),sub=rem&1;float ds=d*(sc[g]&15),ms=dm*(sc[g]>>4);for(l=0;l<16;l++)y[g*16+l]=ds*((q[chunk*32+sub*16+l]>>sh)&3)-ms;}return 0;}
    case D2U_Q3_K:{const uint8_t*hm=b,*q=b+32,*sc=b+96;float d=f16(u16le(b+108));int g,l;NEED(256);for(g=0;g<16;g++){int lo=(g<8?((sc[g]&15)):((sc[g-8]>>4)&15));int hi=(sc[8+(g&3)]>>(2*(g/4)))&3;int ss=(lo|(hi<<4))-32;int chunk=g/8,rem=g%8,qsh=2*(rem/2),qsub=rem&1,hsh=g/2,hsub=g&1;for(l=0;l<16;l++){int ql=(q[chunk*32+qsub*16+l]>>qsh)&3;int hb=(hm[hsub*16+l]>>hsh)&1;int v=ql-((hb^1)<<2);y[g*16+l]=d*ss*v;}}return 0;}
    case D2U_Q4_K:{float d=f16(u16le(b)),dm=f16(u16le(b+2));const uint8_t*sc=b+4,*q=b+16;int g,l;NEED(256);for(g=0;g<8;g++){int s,m;scale_min_k4(sc,g,&s,&m);int chunk=g/2,sh=(g&1)*4;float ds=d*s,ms=dm*m;for(l=0;l<32;l++)y[g*32+l]=ds*((q[chunk*32+l]>>sh)&15)-ms;}return 0;}
    case D2U_Q5_K:{float d=f16(u16le(b)),dm=f16(u16le(b+2));const uint8_t*sc=b+4,*qh=b+16,*q=b+48;int g,l;NEED(256);for(g=0;g<8;g++){int s,m;scale_min_k4(sc,g,&s,&m);int chunk=g/2,sh=(g&1)*4;float ds=d*s,ms=dm*m;for(l=0;l<32;l++){int v=((q[chunk*32+l]>>sh)&15)|(((qh[l]>>g)&1)<<4);y[g*32+l]=ds*v-ms;}}return 0;}
    case D2U_Q6_K:{const uint8_t*ql=b,*qh=b+128;const int8_t*sc=(const int8_t*)(b+192);float d=f16(u16le(b+208));int g,l;NEED(256);for(g=0;g<16;g++){int chunk=g/8,rem=g%8,nsh=(rem/4)*4,nsub=rem%4,hsh=2*(rem/2),hsub=rem&1;float ds=d*sc[g];for(l=0;l<16;l++){int lo=(ql[chunk*64+nsub*16+l]>>nsh)&15;int hi=(qh[chunk*32+hsub*16+l]>>hsh)&3;int v=(lo|(hi<<4))-32;y[g*16+l]=ds*v;}}return 0;}
    case D2U_Q8_K:{float d=f32le(b);const int8_t*q=(const int8_t*)(b+4);NEED(256);for(i=0;i<256;i++)y[i]=d*q[i];return 0;}
    default:return D2U_E_TYPE;
    }
#undef NEED
}

static int row_layout(const d2u_tensor*t,uint64_t*row_elems,uint64_t*row_bytes,uint64_t*rows){
    size_t bs,bb;uint64_t r=1;uint32_t i;if(!t||!t->n_dims)return D2U_E_ARG;bs=d2u_type_block_size(t->type);bb=d2u_type_bytes_per_block(t->type);if(!bs||!bb||t->dims[0]%bs)return D2U_E_FORMAT;*row_elems=t->dims[0];*row_bytes=(t->dims[0]/bs)*bb;for(i=1;i<t->n_dims;i++){if(r>UINT64_MAX/t->dims[i])return D2U_E_RANGE;r*=t->dims[i];}*rows=r;return 0;
}
int d2u_tensor_read_row_f32(const d2u_model*m,d2u_authority*a,uint64_t ticket,const d2u_tensor*t,uint64_t row,float*dst,size_t n,d2u_io_reason reason){
    uint64_t re,rb,rows;size_t bs,bb,blocks,i,pos=0,nv;uint8_t*raw;float tmp[256];int rc;
    if(!dst)return D2U_E_ARG;
    if((rc=row_layout(t,&re,&rb,&rows)))return rc;
    if(row>=rows||n!=re)return D2U_E_RANGE;
    bs=d2u_type_block_size(t->type);bb=d2u_type_bytes_per_block(t->type);blocks=(size_t)(re/bs);raw=(uint8_t*)malloc((size_t)rb);if(!raw)return D2U_E_OOM;rc=d2u_tensor_read(m,a,ticket,t,row*rb,raw,(size_t)rb,reason);if(rc){free(raw);return rc;}
    for(i=0;i<blocks;i++){rc=d2u_dequant_block(t->type,raw+i*bb,tmp,256,&nv);if(rc){free(raw);return rc;}memcpy(dst+pos,tmp,nv*sizeof(float));pos+=nv;}free(raw);return pos==n?0:D2U_E_FORMAT;
}
int d2u_tensor_dot_row(const d2u_model*m,d2u_authority*a,uint64_t ticket,const d2u_tensor*t,uint64_t row,const float*x,size_t xn,float*out,d2u_io_reason reason){
    uint64_t re,rb,rows;size_t bs,bb,blocks,i,j,nv,pos=0;uint8_t*raw;float tmp[256],sum=0;int rc;if(!x||!out)return D2U_E_ARG;if((rc=row_layout(t,&re,&rb,&rows)))return rc;if(row>=rows||xn!=re)return D2U_E_RANGE;bs=d2u_type_block_size(t->type);bb=d2u_type_bytes_per_block(t->type);blocks=(size_t)(re/bs);raw=(uint8_t*)malloc((size_t)rb);if(!raw)return D2U_E_OOM;rc=d2u_tensor_read(m,a,ticket,t,row*rb,raw,(size_t)rb,reason);if(rc){free(raw);return rc;}
    for(i=0;i<blocks;i++){rc=d2u_dequant_block(t->type,raw+i*bb,tmp,256,&nv);if(rc){free(raw);return rc;}for(j=0;j<nv;j++)sum+=tmp[j]*x[pos+j];pos+=nv;}free(raw);*out=sum;return 0;
}
int d2u_tensor_gemv(const d2u_model*m,d2u_authority*a,uint64_t ticket,const d2u_tensor*t,const float*x,size_t xn,float*y,size_t yn,d2u_io_reason reason){
    uint64_t re,rb,rows;size_t bs,bb,blocks,r,bi,j,nv,pos;uint8_t*raw;float tmp[256];int rc;if(!t||!x||!y||t->n_dims<2)return D2U_E_ARG;if((rc=row_layout(t,&re,&rb,&rows)))return rc;if(xn!=re||yn>t->dims[1]||yn>rows)return D2U_E_RANGE;if(yn && rb>SIZE_MAX/yn)return D2U_E_RANGE;raw=(uint8_t*)malloc((size_t)rb*yn);if(!raw)return D2U_E_OOM;rc=d2u_tensor_read(m,a,ticket,t,0,raw,(size_t)rb*yn,reason);if(rc){free(raw);return rc;}bs=d2u_type_block_size(t->type);bb=d2u_type_bytes_per_block(t->type);blocks=(size_t)(re/bs);for(r=0;r<yn;r++){float sum=0;pos=0;for(bi=0;bi<blocks;bi++){rc=d2u_dequant_block(t->type,raw+r*(size_t)rb+bi*bb,tmp,256,&nv);if(rc){free(raw);return rc;}for(j=0;j<nv;j++)sum+=tmp[j]*x[pos+j];pos+=nv;}y[r]=sum;}free(raw);return 0;
}
