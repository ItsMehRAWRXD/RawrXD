#include "deep2_endurance.h"
#include <stdlib.h>
#include <string.h>
int d2_scan_forbidden_symbols(const char *p,const char *const *s,size_t n,size_t *m){FILE *f;long z;char *b;size_t i,c=0;if(!p||!s||!m)return D2_EINVAL;*m=0;f=fopen(p,"rb");if(!f)return D2_EIO;if(fseek(f,0,SEEK_END)||((z=ftell(f))<0)||fseek(f,0,SEEK_SET)){fclose(f);return D2_EIO;}b=(char*)malloc((size_t)z+1);if(!b){fclose(f);return D2_ECAP;}if(fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return D2_EIO;}b[z]=0;for(i=0;i<n;i++)if(s[i]&&*s[i]){char *q=b;while((q=strstr(q,s[i]))!=NULL){c++;q++;}}free(b);fclose(f);*m=c;return c?D2_ESTATE:D2_OK;}
