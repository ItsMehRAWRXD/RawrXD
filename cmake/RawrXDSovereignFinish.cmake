# RawrXD Sovereign Finish-Hour targets
# Included once from root CMakeLists.txt behind RAWRXD_SOVEREIGN_FINISH_HOUR_INCLUDE.

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/models/model_catalog_cert.cpp")
    add_executable(rawrxd_model_catalog_cert
        src/models/model_catalog_cert.cpp
        src/models/ModelCatalog.cpp)
    target_compile_features(rawrxd_model_catalog_cert PRIVATE cxx_std_20)
    target_include_directories(rawrxd_model_catalog_cert PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/models")
    if(MSVC)
        target_compile_options(rawrxd_model_catalog_cert PRIVATE /EHsc /W4 /std:c++20)
    endif()
    set_target_properties(rawrxd_model_catalog_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

if(TARGET InferenceEngine AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/deep2_lifecycle_cert.cpp")
    add_executable(deep2_lifecycle_cert_candidate
        src/deep2/deep2_lifecycle_cert.cpp
        src/models/ModelCatalog.cpp)
    target_compile_features(deep2_lifecycle_cert_candidate PRIVATE cxx_std_20)
    target_include_directories(deep2_lifecycle_cert_candidate PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/agentic"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/models")
    target_link_libraries(deep2_lifecycle_cert_candidate PRIVATE InferenceEngine)
    if(MSVC)
        target_compile_options(deep2_lifecycle_cert_candidate PRIVATE /O2 /EHsc /W4 /std:c++20)
    endif()
    set_target_properties(deep2_lifecycle_cert_candidate PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

if(TARGET InferenceEngine AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/deep2_attn_cert.cpp")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/AttnCertProbe.cpp")
        target_sources(InferenceEngine PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/AttnCertProbe.cpp")
    endif()
    add_executable(deep2_attn_cert
        src/deep2/deep2_attn_cert.cpp
        src/models/ModelCatalog.cpp)
    target_compile_features(deep2_attn_cert PRIVATE cxx_std_20)
    target_include_directories(deep2_attn_cert PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/agentic"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/models")
    target_link_libraries(deep2_attn_cert PRIVATE InferenceEngine)
    if(MSVC)
        target_compile_options(deep2_attn_cert PRIVATE /O2 /EHsc /W4 /std:c++20)
    endif()
    set_target_properties(deep2_attn_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

if(TARGET InferenceEngine AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/deep2_ssm_cert.cpp")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/SsmCertProbe.cpp")
        target_sources(InferenceEngine PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2/SsmCertProbe.cpp")
    endif()
    add_executable(deep2_ssm_cert
        src/deep2/deep2_ssm_cert.cpp
        src/models/ModelCatalog.cpp)
    target_compile_features(deep2_ssm_cert PRIVATE cxx_std_20)
    target_include_directories(deep2_ssm_cert PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/agentic"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/models")
    target_link_libraries(deep2_ssm_cert PRIVATE InferenceEngine)
    if(MSVC)
        target_compile_options(deep2_ssm_cert PRIVATE /O2 /EHsc /W4 /std:c++20)
    endif()
    set_target_properties(deep2_ssm_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

# Ensure RawrXD-Agentic can resolve models through ModelCatalog.
if(TARGET RawrXD-Agentic)
    target_sources(RawrXD-Agentic PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/models/ModelCatalog.cpp")
    target_include_directories(RawrXD-Agentic PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/models")
endif()
