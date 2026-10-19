#!/usr/bin/env bash
set -euo pipefail
c++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror -pthread \
  -Iinclude src/ds_parallel_device_partial.cpp tests/selftest.cpp -o dsdp_selftest
./dsdp_selftest
