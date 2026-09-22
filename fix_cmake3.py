import re

with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix duplicate ASM_KERNEL_SOURCES filter in else() branch
content = content.replace(
    '''else()
    set(ASM_KERNEL_SOURCES "")
rawrxd_filter_missing_sources(ASM_KERNEL_SOURCES)
endif()''',
    '''else()
    set(ASM_KERNEL_SOURCES "")
endif()''')

# Wrap RawrXD-InferenceEngine (single missing source file)
old = '''add_executable(RawrXD-InferenceEngine EXCLUDE_FROM_ALL
    src/inference/inference_standalone_main.cpp
)'''
new = '''if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/inference/inference_standalone_main.cpp")
    add_executable(RawrXD-InferenceEngine EXCLUDE_FROM_ALL
        src/inference/inference_standalone_main.cpp
    )'''
content = content.replace(old, new)

# Find the end of RawrXD-InferenceEngine properties block
old2 = '''endif()

# Unified Generation CLI'''
new2 = '''endif()
endif()

# Unified Generation CLI'''
content = content.replace(old2, new2, 1)

# Wrap RawrXD-Generate
old3 = '''# Unified Generation CLI - uses GenerationBouncer
add_executable(RawrXD-Generate EXCLUDE_FROM_ALL
    src/cli/generate_cli.cpp
    src/runtime/GenerationBouncer.cpp
    src/runtime/shared/SharedModelRuntime.cpp
    src/runtime/shared/BP1BraidIndex.cpp
    src/runtime/shared/BP1BraidStreamer.cpp
)'''
new3 = '''# Unified Generation CLI - uses GenerationBouncer
set(RawrXD_Generate_SOURCES
    src/cli/generate_cli.cpp
    src/runtime/GenerationBouncer.cpp
    src/runtime/shared/SharedModelRuntime.cpp
    src/runtime/shared/BP1BraidIndex.cpp
    src/runtime/shared/BP1BraidStreamer.cpp
)
rawrxd_filter_missing_sources(RawrXD_Generate_SOURCES)
if(RawrXD_Generate_SOURCES)
    add_executable(RawrXD-Generate EXCLUDE_FROM_ALL
        ${RawrXD_Generate_SOURCES}
    )'''
content = content.replace(old3, new3)

# Find the end of RawrXD-Generate block and add endif()
# The block ends before "target_compile_definitions(InferenceEngine PRIVATE RAWRXD_STRICT_PRODUCTION_PROFILE"
old4 = '''if(RAWRXD_PRODUCTION_STRIP_STUB_SOURCES)
    set_target_properties(RawrXD-Generate PROPERTIES
        EXCLUDE_FROM_ALL FALSE
        EXCLUDE_FROM_DEFAULT_BUILD FALSE
    )
endif()

target_compile_definitions(InferenceEngine PRIVATE
    RAWRXD_STRICT_PRODUCTION_PROFILE=$<IF:$<BOOL:${RAWRXD_PRODUCTION_STRIP_STUB_SOURCES}>,1,0>'''
new4 = '''if(RAWRXD_PRODUCTION_STRIP_STUB_SOURCES)
    set_target_properties(RawrXD-Generate PROPERTIES
        EXCLUDE_FROM_ALL FALSE
        EXCLUDE_FROM_DEFAULT_BUILD FALSE
    )
endif()
endif()

target_compile_definitions(InferenceEngine PRIVATE
    RAWRXD_STRICT_PRODUCTION_PROFILE=$<IF:$<BOOL:${RAWRXD_PRODUCTION_STRIP_STUB_SOURCES}>,1,0>'''
content = content.replace(old4, new4, 1)

# Wrap rawrxd-monaco-gen
old5 = '''message(STATUS "[Phase 6] Standalone inference engine target: RawrXD-InferenceEngine")

add_executable(rawrxd-monaco-gen
    src/monaco_gen.cpp
    src/engine/react_ide_generator.cpp
)'''
new5 = '''message(STATUS "[Phase 6] Standalone inference engine target: RawrXD-InferenceEngine")

set(rawrxd_monaco_gen_SOURCES
    src/monaco_gen.cpp
    src/engine/react_ide_generator.cpp
)
rawrxd_filter_missing_sources(rawrxd_monaco_gen_SOURCES)
if(rawrxd_monaco_gen_SOURCES)
    add_executable(rawrxd-monaco-gen
        ${rawrxd_monaco_gen_SOURCES}
    )'''
content = content.replace(old5, new5)

# Find the end of rawrxd-monaco-gen and add endif()
old6 = '''set_target_properties(rawrxd-monaco-gen PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY bin
    OUTPUT_NAME rawrxd-monaco-gen
)

# Win32 GUI IDE'''
new6 = '''set_target_properties(rawrxd-monaco-gen PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY bin
    OUTPUT_NAME rawrxd-monaco-gen
)
endif()

# Win32 GUI IDE'''
content = content.replace(old6, new6, 1)

# Wrap RawrXD-Win32IDE in if(WIN32IDE_SOURCES)
old7 = '''    add_executable(RawrXD-Win32IDE WIN32 ${WIN32IDE_SOURCES} ${_WIN32IDE_ASM} ${WIN32IDE_EXTRA_ASM})
    rawrxd_apply_p1_product_runtime_authority(RawrXD-Win32IDE)'''
new7 = '''    if(WIN32IDE_SOURCES OR _WIN32IDE_ASM OR WIN32IDE_EXTRA_ASM)
        add_executable(RawrXD-Win32IDE WIN32 ${WIN32IDE_SOURCES} ${_WIN32IDE_ASM} ${WIN32IDE_EXTRA_ASM})
        rawrxd_apply_p1_product_runtime_authority(RawrXD-Win32IDE)
    else()
        message(STATUS "[RAWRXD_BUILD_AUTHORITY_BASELINE_001] RawrXD-Win32IDE skipped: no sources available")
    endif()'''
content = content.replace(old7, new7)

# Wrap MultiWindow Kernel in if(MW_KERNEL_ASM EXISTS) and if(src/core/multiwindow_scheduler.cpp exists)
old8 = '''        add_library(RawrXD_MultiWindow_Kernel SHARED
            ${MW_KERNEL_ASM}
            src/core/multiwindow_scheduler.cpp
        )'''
new8 = '''        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${MW_KERNEL_ASM}" AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/core/multiwindow_scheduler.cpp")
            add_library(RawrXD_MultiWindow_Kernel SHARED
                ${MW_KERNEL_ASM}
                src/core/multiwindow_scheduler.cpp
            )'''
content = content.replace(old8, new8)

# Close the MultiWindow block: after target_compile_definitions(RawrXD_MultiWindow_Kernel PRIVATE RAWRXD_MW_KERNEL_EXPORTS=1)
old9 = '''        target_compile_definitions(RawrXD_MultiWindow_Kernel PRIVATE
            RAWRXD_MW_KERNEL_EXPORTS=1
        )
        set(RAWRXD_HAS_MW_KERNEL_FLAG 1)
        message(STATUS "MultiWindow Kernel DLL target enabled")
    else()
        message(STATUS "MultiWindow Kernel DLL skipped (no MASM)")'''
new9 = '''        target_compile_definitions(RawrXD_MultiWindow_Kernel PRIVATE
            RAWRXD_MW_KERNEL_EXPORTS=1
        )
        set(RAWRXD_HAS_MW_KERNEL_FLAG 1)
        message(STATUS "MultiWindow Kernel DLL target enabled")
        else()
            message(STATUS "[RAWRXD_BUILD_AUTHORITY_BASELINE_001] RawrXD_MultiWindow_Kernel skipped: source files missing")
        endif()
    else()
        message(STATUS "MultiWindow Kernel DLL skipped (no MASM)")'''
content = content.replace(old9, new9)

# Wrap DynamicPromptEngine in if(PROMPT_ENGINE_ASM exists AND src/core/dynamic_prompt_engine_glue.cpp exists)
old10 = '''        add_library(RawrXD_DynamicPromptEngine SHARED ${_RAWRXD_PROMPT_ENGINE_EXCLUDE}
            ${PROMPT_ENGINE_ASM}
            src/core/dynamic_prompt_engine_glue.cpp
        )'''
new10 = '''        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${PROMPT_ENGINE_ASM}" AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/core/dynamic_prompt_engine_glue.cpp")
            add_library(RawrXD_DynamicPromptEngine SHARED ${_RAWRXD_PROMPT_ENGINE_EXCLUDE}
                ${PROMPT_ENGINE_ASM}
                src/core/dynamic_prompt_engine_glue.cpp
            )'''
content = content.replace(old10, new10)

# Close DynamicPromptEngine block: after target_compile_definitions(RawrXD_DynamicPromptEngine PRIVATE RAWRXD_PROMPT_ENGINE_EXPORTS=1)
old11 = '''        target_compile_definitions(RawrXD_DynamicPromptEngine PRIVATE
            RAWRXD_PROMPT_ENGINE_EXPORTS=1
        )
        set(RAWRXD_HAS_PROMPT_ENGINE_FLAG 1)
        message(STATUS "DynamicPromptEngine DLL target enabled (Unity/Unreal compatible)")'''
new11 = '''        target_compile_definitions(RawrXD_DynamicPromptEngine PRIVATE
            RAWRXD_PROMPT_ENGINE_EXPORTS=1
        )
        set(RAWRXD_HAS_PROMPT_ENGINE_FLAG 1)
        message(STATUS "DynamicPromptEngine DLL target enabled (Unity/Unreal compatible)")
        else()
            message(STATUS "[RAWRXD_BUILD_AUTHORITY_BASELINE_001] RawrXD_DynamicPromptEngine skipped: source files missing")
        endif()'''
content = content.replace(old11, new11)

with open('rawrxd/CMakeLists.txt', 'w', encoding='utf-8') as f:
    f.write(content)

print("All target guards applied")
print("Saved")
