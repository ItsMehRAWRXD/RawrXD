#include "../src/bs_common.h"
#include "../src/bs_policy.h"
#include <stdio.h>
int main(void){BsState s={0};s.pid_alive=1;s.vendor_smoke_pass=1;s.local_smoke_pass=1;s.merge_deferred=1;s.promote=0;s.highest_pos=63;s.forward_calls=s.full_block_calls=s.commit_calls=s.advance_calls=s.generated_tokens=64;s.terminal_pass_seen=1;if(!bs_live_invariants_ok(&s))return 2;if(!bs_terminal_target64_observed_pass(&s))return 3;puts("BATTLE_STATION_SMOKE=PASS");puts("AUTHORITY_MINTED_BY_BATTLE_STATION=0");return 0;}
