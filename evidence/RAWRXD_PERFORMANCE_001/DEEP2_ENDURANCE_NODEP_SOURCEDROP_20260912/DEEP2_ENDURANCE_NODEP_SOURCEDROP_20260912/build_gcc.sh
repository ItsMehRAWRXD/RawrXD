#!/usr/bin/env sh
set -eu
mkdir -p build
cc -std=c11 -O2 -Wall -Wextra -Werror -Isrc src/*.c tests/smoke.c -o build/deep2_endurance_smoke
(cd build && ./deep2_endurance_smoke)
