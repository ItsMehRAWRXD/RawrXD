#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static int rd(FILE*f,void*p,size_t n){return fread(p,1,n,f)==n;}
static int seekn(FILE*f,uint64_t n){
#ifdef _WIN32
 while(n){__int64 k=n>0x7fffffffULL?0x7fffffff:(__int64)n;if(_fseeki64(f,k,SEEK_CUR))return 0;n-=k;}return 1;
#else
 while(n){long k=n>0x7fffffffULL?0x7fffffff:(long)n;if(fseek(f,k,SEEK_CUR))return 0;n-=k;}return 1;
#endif
}
static int skipv(FILE*f,uint32_t t);
static int skips(FILE*f){uint64_t n;if(!rd(f,&n,8))return 0;return seekn(f,n);}
static int skipa(FILE*f){uint32_t t;uint64_t n,i;if(!rd(f,&t,4)||!rd(f,&n,8))return 0;for(i=0;i<n;i++)if(!skipv(f,t))return 0;return 1;}
static int skipv(FILE*f,uint32_t t){static const uint8_t z[13]={1,1,2,2,4,4,4,1,0,0,8,8,8};if(t>12)return 0;if(t==8)return skips(f);if(t==9)return skipa(f);return seekn(f,z[t]);}
static int strread(FILE*f,char**out){uint64_t n;if(!rd(f,&n,8)||n>1048576)return 0;char*p=(char*)malloc((size_t)n+1);if(!p)return 0;if(!rd(f,p,(size_t)n)){free(p);return 0;}p[n]=0;*out=p;return 1;}
static int target(const char*k){return !strncmp(k,"deepseek2.",10)||!strcmp(k,"general.architecture")||!strcmp(k,"general.name");}
static int val(FILE*f,uint32_t t,const char*k){uint64_t u64;int64_t i64;uint32_t u32;int32_t i32;float fl;double d;char*s=0;
 if(t==4&&rd(f,&u32,4)){printf("%s = %u [u32]\n",k,u32);return 1;}if(t==5&&rd(f,&i32,4)){printf("%s = %d [i32]\n",k,i32);return 1;}
 if(t==10&&rd(f,&u64,8)){printf("%s = %llu [u64]\n",k,(unsigned long long)u64);return 1;}if(t==11&&rd(f,&i64,8)){printf("%s = %lld [i64]\n",k,(long long)i64);return 1;}
 if(t==6&&rd(f,&fl,4)){printf("%s = %.9g [f32]\n",k,(double)fl);return 1;}if(t==12&&rd(f,&d,8)){printf("%s = %.17g [f64]\n",k,d);return 1;}
 if(t==8&&strread(f,&s)){printf("%s = %s [str]\n",k,s);free(s);return 1;}return skipv(f,t);}
int main(int ac,char**av){FILE*f;char m[5]={0};uint32_t ver,t;uint64_t nt,nk,i;if(ac!=2){fprintf(stderr,"usage: gguf_v3_numeric_probe shard1.gguf\n");return 2;}
 f=fopen(av[1],"rb");if(!f)return 3;if(!rd(f,m,4)||memcmp(m,"GGUF",4)||!rd(f,&ver,4)||!rd(f,&nt,8)||!rd(f,&nk,8)){fclose(f);return 4;}
 printf("MAGIC=GGUF VER=%u N_TENSOR=%llu N_KV=%llu\n",ver,(unsigned long long)nt,(unsigned long long)nk);
 for(i=0;i<nk;i++){char*k=0;if(!strread(f,&k)||!rd(f,&t,4)){free(k);fclose(f);return 5;}if(target(k)){if(!val(f,t,k)){free(k);fclose(f);return 6;}}else if(!skipv(f,t)){free(k);fclose(f);return 7;}free(k);}fclose(f);return 0;}
