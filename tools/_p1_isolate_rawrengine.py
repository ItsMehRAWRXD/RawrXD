from pathlib import Path

path = Path(r"F:\~dev\rawrxd\CMakeLists.txt")
text = path.read_text(encoding="utf-8", errors="replace")

text = text.replace(
    "RAWRXD_BUILD_RAWRENGINE=OFF) ? Win32IDE-only configure",
    "RAWRXD_BUILD_RAWRENGINE=OFF) — Win32IDE-only configure",
)

start = text.find("# RawrEngine needs specific ASM kernels for Deep2 and Sovereign Q4K")
end = text.find(
    "# =============================================================================\n# Standalone Gold Deployment: RawrXD_Gold.exe",
    start,
)
if start < 0 or end < 0:
    raise SystemExit(f"markers not found start={start} end={end}")

block = text[start:end]
if not block.lstrip().startswith("if(RAWRXD_BUILD_RAWRENGINE)"):
    wrapped = (
        "if(RAWRXD_BUILD_RAWRENGINE)\n"
        + block.rstrip()
        + "\nendif() # RAWRXD_BUILD_RAWRENGINE\n\n"
    )
    text = text[:start] + wrapped + text[end:]
    print("wrapped RawrEngine create block")
else:
    print("create block already wrapped")

guards = [
    (
        """if(RAWRXD_INCLUDE_STRESS_AND_REPLAY_SOURCES)
    target_include_directories(RawrEngine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/test_harness)
    target_include_directories(RawrXD_Gold PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/test_harness)
endif()""",
        """if(RAWRXD_INCLUDE_STRESS_AND_REPLAY_SOURCES)
    if(TARGET RawrEngine)
        target_include_directories(RawrEngine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/test_harness)
    endif()
    target_include_directories(RawrXD_Gold PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/test_harness)
endif()""",
    ),
    (
        """    # Link MASM objects into RawrEngine (disabled in Lane B headless minimal).
    if(NOT RAWR_ENGINE_LANE_B)
        target_link_libraries(RawrEngine PRIVATE ${MASM_OBJECTS})
        add_dependencies(RawrEngine masm_kernels)
    endif()""",
        """    # Link MASM objects into RawrEngine (disabled in Lane B headless minimal).
    if(TARGET RawrEngine AND NOT RAWR_ENGINE_LANE_B)
        target_link_libraries(RawrEngine PRIVATE ${MASM_OBJECTS})
        add_dependencies(RawrEngine masm_kernels)
    endif()""",
    ),
    (
        """    # Link NanoQuant into main targets
    target_link_libraries(RawrEngine PRIVATE RawrXD_NanoQuant)
    target_compile_definitions(RawrEngine PRIVATE RAWR_HAS_NANOQUANT=1)
    target_link_libraries(RawrXD_Gold PRIVATE RawrXD_NanoQuant)""",
        """    # Link NanoQuant into main targets
    if(TARGET RawrEngine)
        target_link_libraries(RawrEngine PRIVATE RawrXD_NanoQuant)
        target_compile_definitions(RawrEngine PRIVATE RAWR_HAS_NANOQUANT=1)
    endif()
    target_link_libraries(RawrXD_Gold PRIVATE RawrXD_NanoQuant)""",
    ),
]

for old, new in guards:
    if old not in text:
        print("WARN missing snippet:", repr(old[:80]))
    else:
        text = text.replace(old, new, 1)
        print("patched:", old.splitlines()[0][:60])

# Vulkan / link-options / compile-options / EnforceNoStubs — guard singles
lines = text.splitlines(keepends=True)
out = []
i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.lstrip()
    is_engine_cmd = (
        "RawrEngine" in line
        and not stripped.startswith("#")
        and (
            stripped.startswith("target_")
            or stripped.startswith("set_property(TARGET RawrEngine")
            or stripped.startswith("add_custom_command(TARGET RawrEngine")
            or stripped.startswith("add_dependencies(RawrEngine")
            or stripped.startswith("EnforceNoStubs(RawrEngine)")
        )
    )
    if is_engine_cmd:
        look = "".join(out[-12:])
        already = (
            "if(TARGET RawrEngine" in look
            or "if(RAWRXD_BUILD_RAWRENGINE)" in look
            or "TARGET RawrEngine AND" in look
        )
        # Also skip if this line itself is inside a same-indent if we just opened
        if not already:
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}if(TARGET RawrEngine)\n")
            out.append(line)
            buf = line
            bal = buf.count("(") - buf.count(")")
            while bal > 0 and i + 1 < len(lines):
                i += 1
                out.append(lines[i])
                bal += lines[i].count("(") - lines[i].count(")")
            out.append(f"{indent}endif()\n")
            print("guarded:", stripped[:70])
            i += 1
            continue
    out.append(line)
    i += 1

path.write_text("".join(out), encoding="utf-8")
print("DONE")
