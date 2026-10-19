#include "d2u.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static int ws(FILE*f,const char*s){uint64_t n=(uint64_t)strlen(s);return fwrite(&n,8,1,f)==1&&fwrite(s,1,(size_t)n,f)==n;}
static int fixture(const char*path){FILE*f=fopen(path,"wb");uint32_t magic=D2U_GGUF_MAGIC,ver=3,type;uint64_t nt=1,nk=1,dim=4,off=0;uint32_t nd=1;float x[4]={1,2,3,4};long p;char zero[32]={0};if(!f)return 0;
 if(fwrite(&magic,4,1,f)!=1||fwrite(&ver,4,1,f)!=1||fwrite(&nt,8,1,f)!=1||fwrite(&nk,8,1,f)!=1)return 0;
 if(!ws(f,"general.architecture"))return 0;
 type=8;if(fwrite(&type,4,1,f)!=1||!ws(f,"deepseek2"))return 0;
 if(!ws(f,"x"))return 0;
 if(fwrite(&nd,4,1,f)!=1||fwrite(&dim,8,1,f)!=1)return 0;
 type=D2U_F32;if(fwrite(&type,4,1,f)!=1||fwrite(&off,8,1,f)!=1)return 0;
 p=ftell(f);while((p&31)!=0){if(fwrite(zero,1,1,f)!=1)return 0;p++;}if(fwrite(x,sizeof(float),4,f)!=4)return 0;fclose(f);return 1;}
int main(void){const char*path="d2u_smoke_fixture.gguf";const char*paths[1]={path};d2u_model m;d2u_authority a;const d2u_tensor*t;uint64_t tk;float v[4];int rc;uint8_t q4[144]={0};float y[256];size_t n;
 if(!fixture(path)){puts("FIXTURE=FAIL");return 1;}rc=d2u_model_open(&m,1,paths);if(rc){printf("GGUF_OPEN=FAIL:%d\n",rc);return 2;}t=d2u_tensor_find(&m,"x");if(!t||t->size_bytes!=16){puts("GGUF_INDEX=FAIL");return 3;}
 if(d2u_authority_init(&a,0x671B)||d2u_scheduler_claim(&a,0x671B))return 4;
 if(d2u_op_begin(&a,0x671B,0,0,D2U_OP_EMBED,D2U_IO_CURRENT_TENSOR,&tk))return 5;
 rc=d2u_tensor_read_row_f32(&m,&a,tk,t,0,v,4,D2U_IO_CURRENT_TENSOR);if(rc||v[0]!=1||v[3]!=4)return 6;if(d2u_op_end(&a,0x671B,tk,1))return 7;
 rc=d2u_tensor_read_row_f32(&m,&a,tk,t,0,v,4,D2U_IO_CURRENT_TENSOR);if(rc!=D2U_E_AUTH||a.rejected_io==0)return 8;
 /* Real Q4_K layout smoke: fp16 d=1, dmin=0, first 32-value group scale=1, q=2. */
 q4[0]=0x00;q4[1]=0x3c;q4[4]=1;memset(q4+16,0x02,32);rc=d2u_dequant_block(D2U_Q4_K,q4,y,256,&n);if(rc||n!=256||fabsf(y[0]-2.0f)>1e-6f||fabsf(y[31]-2.0f)>1e-6f)return 9;
 d2u_model_close(&m);remove(path);
 {d2u_authority z;if(d2u_authority_init(&z,7)||d2u_scheduler_claim(&z,7))return 10;z.product_open_pass=1;z.session_enter_pass=1;if(d2u_note_layer_complete(&z,0,2)||d2u_note_layer_complete(&z,1,2))return 11;if(d2u_mint_decode_authority(&z,2,1,1))return 12;if(d2u_commit_token(&z,7,42))return 13;if(d2u_try_promote(&z,1))return 14;if(!z.promoted||z.background_submits||z.predictive_loads)return 15;}
 puts("GGUF_V3_INDEX=PASS");puts("CURRENT_OP_IO_AUTHORITY=PASS");puts("Q4_K_144B_LAYOUT=PASS");puts("SCHEDULER_AUTHORITY=PASS");puts("DECODE_AUTHORITY=PASS");puts("RUNTIME_LOCAL_PROMOTION_GATE=PASS");puts("BACKGROUND_SUBMITS=0");puts("PREDICTIVE_LOADS=0");return 0;}
