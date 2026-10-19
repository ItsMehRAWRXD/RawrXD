#include "bs_common.h"
#include "bs_sha256.h"
#include "bs_logscan.h"
#include "bs_process.h"
#include "bs_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void usage(void){puts("battle_station --pid N --cert EXE --sha256 HEX --log FILE --vendor FILE --local FILE [--once] [--interval-ms N]");}
static const char*arg(int argc,char**argv,const char*k){int i;for(i=1;i+1<argc;i++)if(strcmp(argv[i],k)==0)return argv[i+1];return 0;}
static int has(int argc,char**argv,const char*k){int i;for(i=1;i<argc;i++)if(strcmp(argv[i],k)==0)return 1;return 0;}
static void print_state(const BsState*s){
 printf("VENDOR_SMOKE=%s LOCAL_SMOKE=%s\n",s->vendor_smoke_pass?"PASS":"NOT_PASS",s->local_smoke_pass?"PASS":"NOT_PASS");
 printf("PID_%u=%s CERT_BINARY_TOUCHED=%d\n",s->pid,s->pid_alive?"ALIVE":"NOT_ALIVE",s->cert_binary_touched);
 printf("TARGET64_OBSERVED_POS=%d SEALED_LOGITS_REUSE_OBSERVED=%d\n",s->highest_pos,s->sealed_reuse_seen);
 printf("ENDURANCE_PRODUCT_MERGE=%s PROMOTE=%d\n",s->merge_deferred?"DEFERRED":"NOT_DEFERRED",s->promote);
 printf("COUNTERS forward=%llu full_block=%llu commit=%llu advance=%llu generated=%llu\n",(unsigned long long)s->forward_calls,(unsigned long long)s->full_block_calls,(unsigned long long)s->commit_calls,(unsigned long long)s->advance_calls,(unsigned long long)s->generated_tokens);
 printf("LIVE_INVARIANTS=%s TARGET64_OBSERVED_PASS=%d\n",bs_live_invariants_ok(s)?"PASS":"HOLD",bs_terminal_target64_observed_pass(s));
}
int main(int argc,char**argv){const char*pid_s=arg(argc,argv,"--pid"),*cert=arg(argc,argv,"--cert"),*sha=arg(argc,argv,"--sha256"),*log=arg(argc,argv,"--log"),*vendor=arg(argc,argv,"--vendor"),*local=arg(argc,argv,"--local"),*iv=arg(argc,argv,"--interval-ms");uint32_t interval=iv?(uint32_t)strtoul(iv,0,10):5000;int once=has(argc,argv,"--once");if(!pid_s||!cert||!sha||!log||!vendor||!local){usage();return 2;}for(;;){BsState s;memset(&s,0,sizeof s);s.pid=(uint32_t)strtoul(pid_s,0,10);s.highest_pos=-1;s.merge_deferred=1;s.promote=0;strncpy(s.cert_sha256_expected,sha,64);s.cert_sha256_expected[64]=0;s.pid_alive=bs_process_alive(s.pid);s.vendor_smoke_pass=bs_scan_smoke_file(vendor,"VENDOR_SMOKE");s.local_smoke_pass=bs_scan_smoke_file(local,"LOCAL_SMOKE");if(!bs_sha256_file_hex(cert,s.cert_sha256_observed)){puts("CERT_SHA256_READ=FAIL");return 3;}s.cert_binary_touched=(strcmp(s.cert_sha256_expected,s.cert_sha256_observed)!=0);if(!bs_scan_cert_log(log,&s)){puts("CERT_LOG_READ=FAIL");return 4;}print_state(&s);fflush(stdout);if(once||!s.pid_alive)break;bs_sleep_ms(interval);}return 0;}
