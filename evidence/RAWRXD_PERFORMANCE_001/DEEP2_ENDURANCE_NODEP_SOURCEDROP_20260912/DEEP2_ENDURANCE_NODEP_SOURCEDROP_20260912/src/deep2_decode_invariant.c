#include "deep2_endurance.h"
#include <string.h>
#include <stdio.h>
static void stop(D2DecodeInvariant *s,const char *r){ if(!s->stopped){s->stopped=1; snprintf(s->stop_reason,sizeof s->stop_reason,"%s",r?r:"UNKNOWN");}}
int d2_inv_init(D2DecodeInvariant *s,uint64_t t){if(!s||!t)return D2_EINVAL;memset(s,0,sizeof *s);s->target_tokens=t;return D2_OK;}
int d2_inv_forward(D2DecodeInvariant *s,uint64_t pos,int full,int sealed){if(!s||s->stopped)return D2_ESTATE;if(pos!=s->expected_position){stop(s,"POSITION_MISMATCH");return D2_ESTATE;}s->forward_calls++;if(full)s->full_block_forward_calls++;if(sealed)s->sealed_logits_reuse_count++;if(pos==0&&full)s->token0_full_forward_real=1;if(!full){stop(s,"NON_FULL_FORWARD");return D2_ESTATE;}if(sealed){stop(s,"SEALED_LOGITS_REUSE_FORBIDDEN");return D2_ESTATE;}return D2_OK;}
int d2_inv_commit(D2DecodeInvariant *s,uint64_t pos){if(!s||s->stopped)return D2_ESTATE;if(pos!=s->expected_position||s->commit_calls>=s->forward_calls){stop(s,"COMMIT_ORDER");return D2_ESTATE;}s->commit_calls++;s->generated_tokens++;return D2_OK;}
int d2_inv_advance(D2DecodeInvariant *s,uint64_t np){if(!s||s->stopped)return D2_ESTATE;if(s->advance_calls>=s->commit_calls||np!=s->expected_position+1){stop(s,"ADVANCE_ORDER");return D2_ESTATE;}s->advance_calls++;s->expected_position=np;return D2_OK;}
int d2_inv_device_result(D2DecodeInvariant *s,int lost,const char *r){if(!s)return D2_EINVAL;if(lost){s->device_lost=1;stop(s,r?r:"DEVICE_LOST");return D2_ESTATE;}return D2_OK;}
int d2_inv_finalize(D2DecodeInvariant *s){if(!s)return D2_EINVAL;if(s->stopped||s->device_lost)return D2_ESTATE;if(!s->token0_full_forward_real)return D2_ESTATE;if(s->sealed_logits_reuse_count)return D2_ESTATE;if(s->forward_calls!=s->target_tokens||s->full_block_forward_calls!=s->target_tokens||s->commit_calls!=s->target_tokens||s->advance_calls!=s->target_tokens||s->generated_tokens!=s->target_tokens)return D2_ESTATE;return D2_OK;}
