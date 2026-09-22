import re, os
os.chdir(r'F:\~dev')

with open('rawrxd/CMakeLists.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Wrap target_compile_definitions(RawrXD-InferenceEngine ... after the endif() for add_executable
old = '''target_compile_definitions(RawrXD-InferenceEngine PRIVATE
    RAWRXD_STRICT_PRODUCTION_PROFILE=$<IF:$<BOOL:${RAWRXD_PRODUCTION_STRIP_STUB_SOURCES}>,1,0>
    RAWR_STANDALONE_INFERENCE=1
    RAWR_HAS_SOVEREIGN_ENGINES=1
    RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=$<IF:$<BOOL:${RAWRXD_PRODUCTION_STRIP_STUB_SOURCES}>,1,0>
)
'''
new = '''if(TARGET RawrXD-InferenceEngine)
    target_compile_definitions(RawrXD-InferenceEngine PRIVATE
        RAWRXD_STRICT_PRODUCTION_PROFILE=$<IF:$<BOOL:${RAWRXD_PRODUCTION_STRIP_STUB_SOURCES}>,1,0>
        RAWR_STANDALONE_INFERENCE=1
        RAWR_HAS_SOVEREIGN_ENGINES=1
        RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=$<IF:$<BOOL:${RAWRXD_PRODUCTION_STRIP_STUB_SOURCES}>,1,0>
    )
endif()
'''
content = content.replace(old, new)

# 2. Wrap add_dependencies(RawrXD-InferenceEngine masm_kernels) inside if(RAWR_HAS_MASM)
old = '''    add_dependencies(InferenceEngine masm_kernels)
    add_dependencies(RawrXD-InferenceEngine masm_kernels)
'''
new = '''    add_dependencies(InferenceEngine masm_kernels)
    if(TARGET RawrXD-InferenceEngine)
        add_dependencies(RawrXD-InferenceEngine masm_kernels)
    endif()
'''
content = content.replace(old, new)

# 3. Wrap set_target_properties(RawrXD-InferenceEngine ...) and the following target_link_options
old = '''set_target_properties(RawrXD-InferenceEngine PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY bin
    OUTPUT_NAME RawrXD-InferenceEngine
)
'''
new = '''if(TARGET RawrXD-InferenceEngine)
    set_target_properties(RawrXD-InferenceEngine PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY bin
        OUTPUT_NAME RawrXD-InferenceEngine
    )
'''
content = content.replace(old, new)

# 4. Wrap target_link_options(RawrXD-InferenceEngine ...) - find the if(MSVC) block containing target_link_options
old = '''    target_link_options(RawrXD-InferenceEngine PRIVATE /LARGEADDRESSAWARE:NO)
    if(RAWRXD_PRODUCTION_STRIP_STUB_SOURCES)'''
new = '''    target_link_options(RawrXD-InferenceEngine PRIVATE /LARGEADDRESSAWARE:NO)
    if(RAWRXD_PRODUCTION_STRIP_STUB_SOURCES)'''
content = content.replace(old, new)

# 5. Find the end of the if(MSVC) block that contains target_link_options for RawrXD-InferenceEngine
# and add endif() for if(TARGET RawrXD-InferenceEngine) before RAWRXD_PRODUCTION_STRIP_STUB_SOURCES comment
old = '''        target_link_options(RawrXD-InferenceEngine PRIVATE
            "/MAP:${_RAWR_INFERENCE_MAP_PATH}"
            /MAPINFO:EXPORTS
        )
    endif()
endif()

# RAWRXD_PRODUCTION_STRIP_STUB_SOURCES:'''
new = '''        target_link_options(RawrXD-InferenceEngine PRIVATE
            "/MAP:${_RAWR_INFERENCE_MAP_PATH}"
            /MAPINFO:EXPORTS
        )
    endif()
endif()
endif()

# RAWRXD_PRODUCTION_STRIP_STUB_SOURCES:'''
content = content.replace(old, new)

with open('rawrxd/CMakeLists.txt', 'w', encoding='utf-8') as f:
    f.write(content)

print("RawrXD-InferenceEngine guards applied")
