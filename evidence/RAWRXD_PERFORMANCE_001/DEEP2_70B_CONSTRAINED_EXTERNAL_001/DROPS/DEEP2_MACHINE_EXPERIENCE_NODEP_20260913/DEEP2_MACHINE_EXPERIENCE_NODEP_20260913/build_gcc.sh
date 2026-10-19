#!/bin/sh
set -eu
${CXX:-g++} -std=c++17 -O2 \
 Deep2MachineExperience_Key.cpp Deep2MachineExperience_Core.cpp \
 Deep2MachineExperience_Predict.cpp Deep2MachineExperience_Persist.cpp \
 DualStickExperienceAdapter.cpp selftest.cpp -o mx_selftest
./mx_selftest
