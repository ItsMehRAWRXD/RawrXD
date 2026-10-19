#!/usr/bin/env sh
set -eu
mkdir -p build
g++ -std=c++17 -O2 -Isrc smoke.cpp src/*.cpp -o build/d2_missing15_smoke
./build/d2_missing15_smoke
