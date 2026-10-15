cmake_minimum_required(VERSION 3.20)

# Standalone drop: also built as a subdirectory of the parent RawrXD project,
# where project() is a no-op and the parent's hardening flags already apply.
# Declared unconditionally so this file owns its own options either way.
project(rawr_run_dropin VERSION 1.0.0 LANGUAGES CXX)

add_executable(rawr_run rawr_run.cpp)
target_compile_features(rawr_run PRIVATE cxx_std_20)

# ---------------------------------------------------------------------------
# Security hardening (production-grade by default)
# ---------------------------------------------------------------------------
# Mirrors the parent project's RAWRXD_ENABLE_HARDENING defaults so a standalone
# build of this drop is production-grade: stack cookies, control flow guard,
# ASLR, DEP, high-entropy VA and elevated warnings.
#
# Two rules learned the hard way, both honoured here:
#  1. /DYNAMICBASE, /NXCOMPAT and /HIGHENTROPYVA are LINKER-only. MSVC rejects
#     them as compile arguments (D8021 "invalid numeric argument").
#  2. Each generator expression must be its OWN list element. Packing several
#     space-separated options into one $<> expression produces a single
#     mangled argument (e.g. "$<1:/O2(1,1)" -> "cannot open source file").
# ---------------------------------------------------------------------------
option(RAWRXD_ENABLE_HARDENING "Enable production security hardening (compiler/linker flags)" ON)

if(RAWRXD_ENABLE_HARDENING)
  if(MSVC)
    target_compile_options(rawr_run PRIVATE
      /GS /guard:cf /guard:ehcont /VOLATILE:ISO /permissive-
      /W4 /FC /Zc:strictStrings
    )
    target_link_options(rawr_run PRIVATE
      /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf /guard:ehcont
    )
    target_compile_definitions(rawr_run PRIVATE RAWRXD_HARDENING=1)
    message(STATUS "rawr_run: MSVC security hardening enabled")
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(rawr_run PRIVATE
      -fstack-protector-strong -fstack-clash-protection
      -fcf-protection=full -D_FORTIFY_SOURCE=2 -fPIE
      -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
      -Wnull-dereference -Warray-bounds -Wstringop-overflow
      -Wimplicit-fallthrough -Wshadow -Wformat=2
      -Werror=format-security
    )
    target_link_options(rawr_run PRIVATE
      -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    )
    target_compile_definitions(rawr_run PRIVATE RAWRXD_HARDENING=1)
    message(STATUS "rawr_run: GCC/Clang security hardening enabled")
  endif()
endif()

# ---------------------------------------------------------------------------
# Release optimisation (one generator expression per option)
# ---------------------------------------------------------------------------
if(MSVC)
  target_compile_options(rawr_run PRIVATE
    "$<$<CONFIG:Release>:/O2>"
    "$<$<CONFIG:Release>:/Ob2>"
    "$<$<CONFIG:Release>:/Ot>"
    "$<$<CONFIG:Release>:/GF>"
  )
  target_link_options(rawr_run PRIVATE
    "$<$<CONFIG:Release>:/OPT:REF>"
    "$<$<CONFIG:Release>:/OPT:ICF>"
  )
else()
  target_compile_options(rawr_run PRIVATE
    "$<$<CONFIG:Release>:-O2>"
    "$<$<CONFIG:Release>:-fomit-frame-pointer>"
  )
endif()

if(WIN32)
  target_link_libraries(rawr_run PRIVATE winhttp)
endif()

enable_testing()

# The runner's own contract test: JSON codec, framed-tool parsing, gash/unknown
# tool rejection, guarded file write/read/edit, and PATH_GUARD protection.
add_test(NAME rawr_run_self_test COMMAND rawr_run --self-test)

# ---------------------------------------------------------------------------
# Fuzz harness for the security-critical parsers and path guards
# ---------------------------------------------------------------------------
# Links the shipped implementation directly (RAWRXD_RUN_EMBEDDED suppresses the
# drop's main()) so it exercises the real code, not a copy. Deterministic by
# default (fixed seeds) so CI is reproducible; pass a larger iteration count to
# widen the search. Run the fuzz target with sanitizers enabled to turn "no
# crash" into "no memory error".
option(RAWRXD_BUILD_FUZZ "Build the fuzz harness for the security-critical parsers" ON)

if(RAWRXD_BUILD_FUZZ)
  add_executable(rawr_fuzz_parsers EXCLUDE_FROM_ALL rawr_fuzz_parsers.cpp)
  target_compile_features(rawr_fuzz_parsers PRIVATE cxx_std_20)

  # The harness #includes the drop, so it must inherit the same hardening flags
  # rather than relying on the parent directory options.
  if(RAWRXD_ENABLE_HARDENING)
    if(MSVC)
      target_compile_options(rawr_fuzz_parsers PRIVATE
        /GS /guard:cf /guard:ehcont /VOLATILE:ISO /permissive-
        /W4 /FC /Zc:strictStrings
      )
      target_link_options(rawr_fuzz_parsers PRIVATE
        /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf /guard:ehcont
      )
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
      target_compile_options(rawr_fuzz_parsers PRIVATE
        -fstack-protector-strong -fstack-clash-protection -fPIE
        -Wall -Wextra -Wpedantic
      )
      target_link_options(rawr_fuzz_parsers PRIVATE -fPIE -pie)
    endif()
  endif()

  if(MSVC)
    target_compile_options(rawr_fuzz_parsers PRIVATE
      "$<$<CONFIG:Release>:/O2>"
      "$<$<CONFIG:Debug>:/fsanitize=address>"
    )
    target_link_options(rawr_fuzz_parsers PRIVATE
      "$<$<CONFIG:Debug>:/fsanitize=address>"
    )
  else()
    target_compile_options(rawr_fuzz_parsers PRIVATE
      "$<$<CONFIG:Release>:-O2>"
      "$<$<CONFIG:Debug>:-fsanitize=address;-fsanitize=undefined>"
    )
    target_link_options(rawr_fuzz_parsers PRIVATE
      "$<$<CONFIG:Debug>:-fsanitize=address;-fsanitize=undefined>"
    )
  endif()

  if(WIN32)
    target_link_libraries(rawr_fuzz_parsers PRIVATE winhttp)
  endif()

  # Registered so a plain `cmake --build .` / ctest run covers the parsers.
  add_test(NAME rawr_fuzz_parsers COMMAND rawr_fuzz_parsers 20000)
  set_tests_properties(rawr_fuzz_parsers PROPERTIES TIMEOUT 120)
  message(STATUS "rawr_fuzz_parsers: fuzz harness enabled (build with RAWRXD_BUILD_FUZZ=ON)")
endif()