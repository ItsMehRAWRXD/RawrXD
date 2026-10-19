#!/usr/bin/env sh
set -eu
mkdir -p build
c++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror \
  -Iinclude src/EnterpriseDualStickLocality.cpp tests/selftest.cpp \
  -o build/dualstick_locality_selftest
(cd build && ./dualstick_locality_selftest)
