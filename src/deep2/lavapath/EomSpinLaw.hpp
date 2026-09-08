#pragma once
/* EOM_SPIN_001 — token = one closed request-spin, not a model sweep. */
#define EOM_SPIN_001 1
#define SPIN_OPEN_ON_TOKEN 1
#define SPIN_WHILE_REQUIRED_REQUESTS_EXIST 1
#define SPIN_STOP_ON_DEPENDENCY_CLOSURE 1
#define TOKEN_CLOSE_ON_SPIN_STOP 1
#define TOKEN_EMIT_AFTER_CLOSE 1
#define WORK_COMPLETED_NE_TOKEN_TIME 1
/*
  SPIN_OPEN → required deps enter → execute/reuse/substitute/fuse →
  unresolved_required_dependencies == 0 → SPIN_STOP → TOKEN_CLOSE →
  LOGITS → SAMPLE → EMIT → SPIN_OPEN(N+1)

  TOKEN_TIME_NS = SPIN_CLOSE_NS - SPIN_OPEN_NS
  TPS = CLOSED_SPINS / WALL_SECOND

  For 150 TPS: MAX_SPIN_LIFETIME ≈ 6.667 ms
  Parallel/fused work may exceed that; only the exposed dep chain counts.
*/
