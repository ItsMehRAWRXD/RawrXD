#!/usr/bin/env sh
set -eu
mkdir -p out
g++ -std=c++17 -O2 -Iinclude src/*.cpp tests/smoke.cpp -o out/d2_audit_smoke
