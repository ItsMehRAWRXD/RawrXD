#pragma once
/* Context compaction = same addressability law as BG~BM~, chat surface. */
#define RAWRXD_CONTEXT_COMPACT_001 1
#define CONTEXT_SPINE_ALWAYS_RESIDENT 1
#define CONTEXT_RIBS_ON_DEMAND 1
#define CONTEXT_HANDOFF_FORWARD 1
#define CONTEXT_HANDOFF_BACKWARD 1
#define CONTEXT_HANDOFF_RESET 1
#define CONTEXT_EFFECTIVE_BYTES_EQ_SPINE_PLUS_ACTIVE_RIBS 1
#define CONTEXT_TOTAL_HISTORY_NE_WORKING_SET 1
#define REGEN_TPS_FROM_MISSED_DEADLINES 0
#define TLS_FORK_BOMB_POISON_OVERLOAD 0
#define AGENT_CANCEL_EQ_RELEASE_JOB 1
/*
  Compact conversation so EFFECTIVE context bytes stay under window.
  Cancel agent = release job + free buffers. Not kinetic TPS theater.
  Deep2 hotpath unchanged.
*/
