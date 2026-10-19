#!/usr/bin/env sh
set -eu
CXX="${CXX:-c++}"
CC="${CC:-cc}"
"$CXX" -std=c++17 -O2 -Wall -Wextra -pedantic d2_request_compiler.cpp selftest.cpp -o d2_request_compiler_selftest
./d2_request_compiler_selftest
"$CC" -std=c11 -O2 -Wall -Wextra -pedantic -c c_api_selftest.c -o c_api_selftest.o
"$CXX" -std=c++17 -O2 -Wall -Wextra -pedantic -c d2_request_compiler.cpp -o d2_request_compiler.o
"$CXX" d2_request_compiler.o c_api_selftest.o -o d2_request_compiler_c_abi_selftest
./d2_request_compiler_c_abi_selftest
