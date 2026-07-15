# LoRA (Low-Rank Adaptation) Module
# Phase 18C: Personalized Embedding Fine-tuning
# Phase 21: CMake Build System Integration - MASM Kernel Support

# =============================================================================
# C++ Sources
# =============================================================================
set(LORA_SOURCES
    AdapterRegistry.cpp
    AdapterTrainer.cpp
    LoRAAdapterManager.cpp
    AdapterSerializer.cpp
    LoRABeaconInterface.cpp
    BeaconChainManager.cpp
)

set(LORA_HEADERS
    AdapterRegistry.h
    AdapterTrainer.h
    LoRAAdapterManager.h
    AdapterSerializer.h
    LoRABeaconInterface.h
    BeaconChainManager.h
)

# =============================================================================
# ASM Kernel Sources (Phase 21: MASM Integration)
# =============================================================================
set(LORA_ASM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ApplyLoRA_Optimized.asm
    ${CMAKE_CURRENT_SOURCE_DIR}/ApplyLoRA_Clean.asm
    ${CMAKE_CURRENT_SOURCE_DIR}/LoRABeacon_MASM.asm
    ${CMAKE_CURRENT_SOURCE_DIR}/LoRABeaconChain_MASM.asm
)

# =============================================================================
# ASM Kernel Library (Object Library for linking)
# =============================================================================
if(RAWR_HAS_MASM)
    # Create object library for ASM kernels
    add_library(rawrxd_lora_kernels OBJECT ${LORA_ASM_SOURCES})
    
    # Set ASM-specific compile options
    target_compile_options(rawrxd_lora_kernels PRIVATE
        /c              # Compile only (no link)
        /Zi             # Debug info
        /Zd             # Line number info
        /W3             # Warning level 3
    )
    
    # Include directories for ASM
    target_include_directories(rawrxd_lora_kernels PRIVATE
        ${CMAKE_SOURCE_DIR}/src/include
        ${CMAKE_SOURCE_DIR}/src/lora
        ${CMAKE_SOURCE_DIR}/src/fusion/kernels
    )
    
    # Set source properties for ASM files
    set_source_files_properties(${LORA_ASM_SOURCES} 
        PROPERTIES 
        LANGUAGE ASM_MASM
        COMPILE_FLAGS "/c /Zi /Zd"
    )
    
    message(STATUS "[Phase 21] LoRA ASM kernels enabled: ${LORA_ASM_SOURCES}")
else()
    message(WARNING "[Phase 21] MASM not available - LoRA kernels will use C++ fallbacks")
    set(LORA_ASM_SOURCES "")
endif()

# =============================================================================
# LoRA Core Library (C++ + ASM Objects)
# =============================================================================
add_library(rawrxd_lora STATIC
    ${LORA_SOURCES}
    ${LORA_HEADERS}
    $<$<BOOL:${RAWR_HAS_MASM}>:$<TARGET_OBJECTS:rawrxd_lora_kernels>>
)

target_include_directories(rawrxd_lora PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/include
    ${CMAKE_SOURCE_DIR}/src/fusion
)

target_link_libraries(rawrxd_lora PUBLIC
    jsoncpp_lib
    ${CMAKE_THREAD_LIBS_INIT}
)

# Enable optimizations for the matrix math hot path
target_compile_options(rawrxd_lora PRIVATE
    $<$<CONFIG:Release>:-O3 -ffast-math>
    $<$<CONFIG:RelWithDebInfo>:-O2>
)

# Group sources for IDE
target_sources(rawrxd_lora PRIVATE ${LORA_HEADERS})
set_target_properties(rawrxd_lora PROPERTIES 
    FOLDER "Modules/LoRA"
    OUTPUT_NAME "lora"
)

# =============================================================================
# Build-Time Validation Tests (Phase 21)
# =============================================================================
if(RAWR_HAS_MASM AND RAWRXD_BUILD_TESTS)
    # Kernel validation executable
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_lora_shadow.cpp)
        add_executable(test_lora_kernel_validation
            ${CMAKE_CURRENT_SOURCE_DIR}/test_lora_shadow.cpp
        )
        
        target_link_libraries(test_lora_kernel_validation PRIVATE
            rawrxd_lora
            rawrxd_core
        )
        
        target_include_directories(test_lora_kernel_validation PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/tests
        )
        
        # Add to test suite
        add_test(NAME LoRA_Kernel_Validation
            COMMAND test_lora_kernel_validation
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        
        set_tests_properties(LoRA_Kernel_Validation PROPERTIES
            LABELS "kernel;lora;validation"
            TIMEOUT 30
            ENVIRONMENT "RAWRXD_TEST_MODE=1"
        )
        
        message(STATUS "[Phase 21] LoRA kernel validation test enabled")
    endif()
    
    # Performance benchmark test
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/benchmark_kernel.cpp)
        add_executable(benchmark_lora_kernel
            ${CMAKE_CURRENT_SOURCE_DIR}/benchmark_kernel.cpp
        )
        
        target_link_libraries(benchmark_lora_kernel PRIVATE
            rawrxd_lora
            rawrxd_core
        )
        
        target_include_directories(benchmark_lora_kernel PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/tests
        )
        
        add_test(NAME LoRA_Kernel_Benchmark
            COMMAND benchmark_lora_kernel 1048576 8
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        
        set_tests_properties(LoRA_Kernel_Benchmark PROPERTIES
            LABELS "kernel;lora;benchmark;performance"
            TIMEOUT 60
            ENVIRONMENT "RAWRXD_BENCHMARK_MODE=1"
        )
        
        message(STATUS "[Phase 21] LoRA kernel benchmark test enabled")
    endif()
endif()

# =============================================================================
# Summary
# =============================================================================
message(STATUS "[Phase 21] LoRA Module Configuration:")
message(STATUS "  ASM Sources: ${LORA_ASM_SOURCES}")
message(STATUS "  C++ Sources: ${LORA_SOURCES}")
message(STATUS "  MASM Enabled: ${RAWR_HAS_MASM}")
message(STATUS "  Tests Enabled: ${RAWRXD_BUILD_TESTS}")
