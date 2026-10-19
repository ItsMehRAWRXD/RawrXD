#!/bin/sh
set -eu
${CC:-cc} -O2 -Wall -Wextra -pedantic -std=c99 selftest.c -o selftest
./selftest
