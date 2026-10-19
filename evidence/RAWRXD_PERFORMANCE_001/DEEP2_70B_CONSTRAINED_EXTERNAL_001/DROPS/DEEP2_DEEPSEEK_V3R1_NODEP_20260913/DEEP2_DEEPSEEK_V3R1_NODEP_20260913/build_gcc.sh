#!/bin/sh
set -eu
${CXX:-g++} -std=c++17 -O2 \
 Deep2DeepSeekRuntime_Core.cpp Deep2DeepSeekRuntime_Router.cpp \
 Deep2DeepSeekRuntime_Schedule.cpp Deep2DeepSeekRuntime_Residency.cpp \
 Deep2DeepSeekRuntime_KvPrefill.cpp Deep2DeepSeekRuntime_MtpQuant.cpp \
 Deep2DeepSeekRuntime_Prefetch.cpp Deep2DeepSeekDualStickAdapter.cpp \
 selftest.cpp -o deepseek_nodep_selftest
./deepseek_nodep_selftest
