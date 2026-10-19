#!/bin/sh
set -eu
cc -std=c99 -O2 -Wall -Wextra -Werror -Isrc src/d2_range.c src/d2_locality.c src/d2_residency.c src/d2_dual_gpu.c src/d2_stream.c src/d2_plan.c src/d2_runtime.c tests/smoke.c -o deep2_locality_stream_dualgpu_smoke
./deep2_locality_stream_dualgpu_smoke
