#!/usr/bin/env bash
set -euo pipefail
mkdir -p bin
g++ -std=c++17 -O2 -Iinclude src/d2_gen_quality.cpp -o bin/d2_gen_quality
bin/d2_gen_quality tests/good.txt tests/good.trace.txt
if bin/d2_gen_quality tests/bad.txt tests/good.trace.txt; then
  echo "bad repetition sample unexpectedly passed" >&2; exit 3
fi
echo DEEP2_POST_ENDURANCE_VALUE_GATES_SELFTEST=PASS
