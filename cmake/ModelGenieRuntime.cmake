#=============================================================================
# ModelGenieRuntime - the certified Deep2 IR executor as a reusable library
# RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
#
# One implementation, consumed by:
#   * tools/rawrxd_modelgenie_ir_executor (standalone verification harness)
#   * RawrXDCore.dll                              (production inference)
#=============================================================================
include_guard(GLOBAL)

if(NOT TARGET ModelGenieRuntime)
    add_library(ModelGenieRuntime STATIC
        ${RAWRXD_SOURCE_DIR}/src/modelgenie/ModelGenieExecutor.cpp
        ${RAWRXD_SOURCE_DIR}/src/modelgenie/ModelGenieRuntime.cpp
        ${RAWRXD_SOURCE_DIR}/src/tokenizer/gguf_embedded_tokenizer.cpp
        ${RAWRXD_SOURCE_DIR}/src/deep2/modelgenie/ModelGenome.cpp
        ${RAWRXD_SOURCE_DIR}/src/deep2/modelgenie/ModelGenomeReader.cpp
    )

    # RawrXDCore links this library PRIVATE and installs an EXPORT set
    # (RawrXDCoreTargets). A PRIVATE link dependency still belongs to the
    # export set for linking purposes, so the target must be part of one.
    # Declaring it here lets install(TARGETS ... EXPORT RawrXDCoreTargets)
    # in src/core/dll/CMakeLists.txt pick it up.
    install(TARGETS ModelGenieRuntime
        EXPORT RawrXDCoreTargets
        ARCHIVE DESTINATION lib
    )

    set_target_properties(ModelGenieRuntime PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE OFF
        FOLDER "Deep2"
        EXPORT_NAME ModelGenieRuntime
    )

    # Wrapped in $<BUILD_INTERFACE:...> so these source-tree paths stay out of
    # the exported RawrXDCoreTargets interface. RawrXDCore links this library
    # PRIVATE and installs an EXPORT set, and install(EXPORT) refuses
    # interface paths prefixed in the source directory.
    target_include_directories(ModelGenieRuntime PUBLIC
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/src/deep2>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/src/deep2/modelgenie>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/src/modelgenie>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/src/tokenizer>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/tools>
        $<BUILD_INTERFACE:${RAWRXD_SOURCE_DIR}/generated/DeepSeek-V2-Lite-Chat>
    )

    if(MSVC)
        target_compile_options(ModelGenieRuntime PRIVATE
            /W1 /permissive- /O2 /GL
            $<$<CONFIG:Debug>:/Zi /Od>
        )
        target_compile_definitions(ModelGenieRuntime PRIVATE
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )
    else()
        target_compile_options(ModelGenieRuntime PRIVATE -w)
    endif()

    # OpenMP is used by the verified MatMul kernel; keep it available but do
    # not make the library fail to build on toolchains lacking it.
    include(FindOpenMP)
    if(OPENMP_FOUND)
        target_link_libraries(ModelGenieRuntime PUBLIC OpenMP::OpenMP_CXX)
    endif()
endif()
