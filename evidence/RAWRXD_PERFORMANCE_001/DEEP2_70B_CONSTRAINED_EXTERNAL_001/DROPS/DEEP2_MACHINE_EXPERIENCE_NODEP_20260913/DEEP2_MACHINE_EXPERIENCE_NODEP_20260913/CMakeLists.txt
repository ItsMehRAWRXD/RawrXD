cmake_minimum_required(VERSION 3.16)
project(deep2_machine_experience_nodep CXX)
set(CMAKE_CXX_STANDARD 17)
add_executable(mx_selftest
  Deep2MachineExperience_Key.cpp
  Deep2MachineExperience_Core.cpp
  Deep2MachineExperience_Predict.cpp
  Deep2MachineExperience_Persist.cpp
  DualStickExperienceAdapter.cpp
  selftest.cpp)
