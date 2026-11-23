# Native, dependency-free GGUF tensor compressor.
# The executable emits standard GGML Q2_K..Q6_K and Q8_K blocks; Deep2's existing
# GGUFLoader/QuantKernelRegistry already own the corresponding load/decode path.
option(RAWRXD_BUILD_NATIVE_GGUF_COMPRESSOR "Build native GGUF precision-gated compressor" ON)
if(RAWRXD_BUILD_NATIVE_GGUF_COMPRESSOR)
    get_filename_component(RAWRXD_TENSOR_REPO_ROOT
        "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
    set(RAWRXD_NATIVE_GGUF_COMPRESSOR_SOURCE
        "${RAWRXD_TENSOR_REPO_ROOT}/tools/native_gguf_f16.cpp")
    if(NOT EXISTS "${RAWRXD_NATIVE_GGUF_COMPRESSOR_SOURCE}")
        message(FATAL_ERROR "Native GGUF compressor source missing: ${RAWRXD_NATIVE_GGUF_COMPRESSOR_SOURCE}")
    endif()
    add_executable(rawrxd-native-gguf-compress
        "${RAWRXD_NATIVE_GGUF_COMPRESSOR_SOURCE}")
    target_compile_features(rawrxd-native-gguf-compress PRIVATE cxx_std_17)
    target_include_directories(rawrxd-native-gguf-compress PRIVATE
        "${RAWRXD_TENSOR_REPO_ROOT}/src/deep2")
    set_target_properties(rawrxd-native-gguf-compress PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()
