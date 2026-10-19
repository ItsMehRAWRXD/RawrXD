#!/usr/bin/env sh
set -eu
cc -std=c11 -D_FILE_OFFSET_BITS=64 -D_XOPEN_SOURCE=700 -O2 -Wall -Wextra -pedantic \
  r671_stream.c r671_probe.c -o r671_probe
./r671_probe
