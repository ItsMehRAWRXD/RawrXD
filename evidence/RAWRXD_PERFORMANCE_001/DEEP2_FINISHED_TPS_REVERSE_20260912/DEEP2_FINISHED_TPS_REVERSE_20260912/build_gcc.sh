#!/bin/sh
set -eu
mkdir -p out
cc -std=c11 -O2 -Wall -Wextra -Werror -Iinclude src/d2_perf_authority.c src/d2_perf_cli.c -o out/d2_perf_gate
./out/d2_perf_gate --mode project --weight-bytes 25000000000 --peak-bw-gbs 640
