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

    set_target_properties(ModelGenieRuntime PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE OFF
        FOLDER "Deep2"
    )

    target_include_directories(ModelGenieRuntime PRIVATE
        ${RAWRXD_SOURCE_DIR}
        ${RAWRXD_SOURCE_DIR}/include
        ${RAWRXD_SOURCE_DIR}/src
        ${RAWRXD_SOURCE_DIR}/src/deep2
        ${RAWRXD_SOURCE_DIR}/src/deep2/modelgenie
        ${RAWRXD_SOURCE_DIR}/src/modelgenie
        ${RAWRXD_SOURCE_DIR}/src/tokenizer
        ${RAWRXD_SOURCE_DIR}/tools
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

# Export ModelGenieRuntime into RawrXDCoreTargets export set when called from DLL build
if(TARGET ModelGenieRuntime)
    get_property(_already_installed TARGET ModelGenieRuntime PROPERTY EXPORT_NAME SET)
    if(NOT _already_installed)
        install(TARGETS ModelGenieRuntime
            EXPORT RawrXDCoreTargets
            ARCHIVE DESTINATION lib
            LIBRARY DESTINATION lib
            RUNTIME DESTINATION bin
        )
        set_property(TARGET ModelGenieRuntime PROPERTY EXPORT_NAME ModelGenieRuntime)
    endif()
endif()
