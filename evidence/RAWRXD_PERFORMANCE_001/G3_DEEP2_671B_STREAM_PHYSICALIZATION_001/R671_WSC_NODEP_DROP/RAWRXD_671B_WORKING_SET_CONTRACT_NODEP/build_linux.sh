#!/usr/bin/env sh
set -eu
cc -std=c11 -O2 -Wall -Wextra -pedantic wsc15.c wsc15_probe.c -o wsc15_probe
./wsc15_probe
