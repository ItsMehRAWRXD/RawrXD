#include "deep2_endurance.h"
#include <string.h>
int d2_journal_open(D2Journal *j,const char *p){if(!j||!p)return D2_EINVAL;memset(j,0,sizeof *j);j->fp=fopen(p,"wb");return j->fp?D2_OK:D2_EIO;}
int d2_journal_record(D2Journal *j,const char *k,const char *v){if(!j||!j->fp||!k||!v||strchr(k,'\n')||strchr(v,'\n'))return D2_EINVAL;if(fprintf(j->fp,"%s=%s\n",k,v)<0||fflush(j->fp))return D2_EIO;j->records++;return D2_OK;}
int d2_journal_record_u64(D2Journal *j,const char *k,uint64_t v){char b[32];snprintf(b,sizeof b,"%llu",(unsigned long long)v);return d2_journal_record(j,k,b);}
int d2_journal_close(D2Journal *j){int rc;if(!j||!j->fp)return D2_EINVAL;rc=fclose(j->fp);j->fp=NULL;return rc?D2_EIO:D2_OK;}
