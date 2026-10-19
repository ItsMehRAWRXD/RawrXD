#include "bs_logscan.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static uint64_t after_u64(const char*line,const char*key){const char*p=strstr(line,key);return p?(uint64_t)strtoull(p+strlen(key),0,10):0;}
int bs_scan_smoke_file(const char*path,const char*key){FILE*f=fopen(path,"rb");char line[BS_LINE_MAX];int ok=0;if(!f)return 0;while(fgets(line,sizeof line,f))if(strstr(line,key)&&strstr(line,"PASS")){ok=1;break;}fclose(f);return ok;}
int bs_scan_cert_log(const char*path,BsState*s){FILE*f=fopen(path,"rb");char line[BS_LINE_MAX];if(!f)return 0;while(fgets(line,sizeof line,f)){
 const char*p=strstr(line,"AR_FORWARD pos=");if(p){int pos=atoi(p+15);if(pos>s->highest_pos)s->highest_pos=pos;if(strstr(line,"sealed_logits_reuse=1"))s->sealed_reuse_seen=1;}
 if(strstr(line,"DEEP2_FULL_DECODE_TOKEN_REAL=PASS"))s->terminal_pass_seen=1;
 if(strstr(line,"DEEP2_FULL_DECODE_TOKEN_REAL=FAIL"))s->terminal_fail_seen=1;
 if(strstr(line,"FORWARD_CALLS="))s->forward_calls=after_u64(line,"FORWARD_CALLS=");
 if(strstr(line,"FULL_BLOCK_FORWARD_CALLS="))s->full_block_calls=after_u64(line,"FULL_BLOCK_FORWARD_CALLS=");
 if(strstr(line,"COMMIT_CALLS="))s->commit_calls=after_u64(line,"COMMIT_CALLS=");
 if(strstr(line,"ADVANCE_CALLS="))s->advance_calls=after_u64(line,"ADVANCE_CALLS=");
 if(strstr(line,"GENERATED_TOKENS="))s->generated_tokens=after_u64(line,"GENERATED_TOKENS=");
 p=strstr(line,"AUTHORIZATION_STOP_REASON=");if(p){p+=26;sscanf(p,"%127s",s->last_stop_reason);} }
 fclose(f);return 1;}
