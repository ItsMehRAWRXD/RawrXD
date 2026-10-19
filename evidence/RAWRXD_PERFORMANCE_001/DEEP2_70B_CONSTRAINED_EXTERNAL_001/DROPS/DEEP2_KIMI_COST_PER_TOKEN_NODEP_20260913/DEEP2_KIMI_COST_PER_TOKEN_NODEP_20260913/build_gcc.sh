#!/bin/sh
set -eu
${CXX:-g++} -std=c++17 -O2 KimiCostAuthority_Core.cpp \
 KimiCostAuthority_Compare.cpp KimiCostAuthority_Emit.cpp selftest.cpp \
 -o kimi_cost_selftest
./kimi_cost_selftest
