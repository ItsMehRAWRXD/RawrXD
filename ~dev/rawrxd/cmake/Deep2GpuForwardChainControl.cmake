# Optional integration fragment.
# This adds only the parser/comparison library. The PowerShell controller can
# operate independently and does not require this target.
add_library(deep2_gpu_forward_chain_control STATIC
    ${CMAKE_SOURCE_DIR}/src/deep2/control/GpuForwardChain.cpp
)
target_include_directories(deep2_gpu_forward_chain_control PUBLIC
    ${CMAKE_SOURCE_DIR}/src/deep2/control
)
target_compile_features(deep2_gpu_forward_chain_control PUBLIC cxx_std_17)
