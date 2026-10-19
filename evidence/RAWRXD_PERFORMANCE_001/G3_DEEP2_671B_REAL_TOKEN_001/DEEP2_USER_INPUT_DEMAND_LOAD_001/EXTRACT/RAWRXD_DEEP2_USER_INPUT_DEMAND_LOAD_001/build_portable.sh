#!/usr/bin/env sh
set -eu
CFLAGS='-std=c11 -O2 -Wall -Wextra -Werror'
cc $CFLAGS d2u_smoke.c d2u_authority.c d2u_gguf.c d2u_quant.c -lm -o d2u_smoke
./d2u_smoke
cc $CFLAGS d2u_inspect.c d2u_gguf.c -lm -o d2u_inspect
cc $CFLAGS d2u_run_tokens.c d2u_authority.c d2u_gguf.c d2u_quant.c d2u_router.c d2u_mla.c d2u_expert.c d2u_runtime.c -lm -o d2u_run_tokens
printf '%s\n' 'PORTABLE_BUILD=PASS'
