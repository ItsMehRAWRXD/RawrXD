# =============================================================================
# RAWRXD_REMOTE64_PRODUCT_INTEGRATION_001
#
# Build authority for the 64 native MASM64 translation units in src/remote64.
#
# Prior state: the 64 TUs were source-complete (64/64 assemble cleanly under
# ml64) but had no build authority at all -- no CMake target, no production
# C++ consumer, and no product binary linked them. The only consumers were the
# certification/probe programs. This module supplies the missing authority.
#
# This is a STATIC library. It deliberately has no main(). Linking one of these
# objects directly into an exe produces LNK1561 (no entry point); that is the
# expected result for a library object and is not a defect. The entry point
# comes from the product target that links this library.
# =============================================================================

set(RAWRXD_REMOTE64_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/remote64")

file(GLOB RAWRXD_REMOTE64_ASM_SOURCES CONFIGURE_DEPENDS "${RAWRXD_REMOTE64_DIR}/*.asm")
list(SORT RAWRXD_REMOTE64_ASM_SOURCES)
list(LENGTH RAWRXD_REMOTE64_ASM_SOURCES RAWRXD_REMOTE64_TU_COUNT)

# The closure receipt for this subsystem asserts 64 TUs. If the count moves, the
# receipt is stale and must be regenerated rather than silently reinterpreted.
if(NOT RAWRXD_REMOTE64_TU_COUNT EQUAL 64)
    message(WARNING
        "[remote64] TU count is ${RAWRXD_REMOTE64_TU_COUNT}, not the 64 recorded in "
        "RAWRXD_NATIVE_REMOTE_SOURCE_CLOSURE. Re-verify the closure before promoting.")
endif()
message(STATUS "[remote64] ${RAWRXD_REMOTE64_TU_COUNT} MASM64 translation units")

add_library(rawrxd_remote64 STATIC
    ${RAWRXD_REMOTE64_ASM_SOURCES}
    "${RAWRXD_REMOTE64_DIR}/remote64_bridge.cpp"
)

set_source_files_properties(${RAWRXD_REMOTE64_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)

# remote.inc is included by name from every TU; make that resolution explicit
# rather than relying on ml64's implicit current-directory behaviour.
target_include_directories(rawrxd_remote64
    PUBLIC  "${RAWRXD_REMOTE64_DIR}"
    PRIVATE "${RAWRXD_REMOTE64_DIR}"
)

target_compile_features(rawrxd_remote64 PUBLIC cxx_std_17)

# Win32 import libraries actually referenced by the 64 TUs:
#   bcrypt  -- aead.asm, crypto.asm, hashfile.asm        (BCrypt*)
#   ws2_32  -- transport.asm, shutdown.asm              (WSA*, socket/recv/send)
#   gdi32   -- capture.asm, viewer.asm                  (BitBlt/StretchDIBits)
#   user32  -- b37/b38/cursor/input/consent              (GetWindowRect/SendInput)
#   kernel32-- file IO, heap, VirtualAlloc, Sleep, QPC
#   ntdll   -- clipboard.asm                            (RtlMoveMemory)
target_link_libraries(rawrxd_remote64 PUBLIC
    kernel32 user32 gdi32 ws2_32 bcrypt ntdll
)

set(RAWRXD_REMOTE64_LINKED TRUE)
message(STATUS "[remote64] rawrxd_remote64 target defined")

# Expose the assembled TU count to consumers so a cert can assert 64/64 from the
# build graph instead of trusting the source list. RAWRXD_REMOTE64_TU_COUNT is
# computed above from the glob, so it cannot drift from what was actually built.
target_compile_definitions(rawrxd_remote64 PUBLIC
    RAWRXD_REMOTE64_TU_COUNT=${RAWRXD_REMOTE64_TU_COUNT}
)

# -----------------------------------------------------------------------------
# Product integration cert
# -----------------------------------------------------------------------------
# deep2_bridge.asm exports Deep2RemoteObserveGate / Deep2RemoteControlGate,
# wrapping remote64's authority predicates. Until this target existed nothing
# proved Deep2 and remote64 could coexist in one link: remote64 was only ever
# linked into its own probe drivers, so "both subsystems link together" was an
# assumption rather than a measurement.
#
# This cert links InferenceEngine (the Deep2 product library) AND rawrxd_remote64
# in a single image, then asserts:
#   * the bridge is a pass-through over RemoteAuthorityCanObserve/Control
#   * both gates DENY (R_AUTH, -3) at process start, before any session exists
#   * the deny constant in C++ still equals remote.inc's R_AUTH
#   * RemoteSelfTest and RemoteFinalSelfTest pass inside a Deep2 co-linked
#     binary, which is the load-order check: C++ objects shadowing the MASM
#     definitions, or a double-linked archive, would fail here
#   * the assembled TU count is 64
#
# It proves nothing about transport, capture, input, or throughput. TPS authority
# is Deep2Engine::GenerationStats and is measured by the existing benchmarks.
# -----------------------------------------------------------------------------
option(BUILD_DEEP2_REMOTE64_INTEGRATION_CERT
       "Build RAWRXD_REMOTE64_PRODUCT_INTEGRATION_001 cert" OFF)
# NOTE: no `AND TARGET InferenceEngine` guard. This module is included at
# CMakeLists.txt:2099, well before InferenceEngine is declared, so a TARGET
# guard evaluated here is always false and the cert would silently never be
# created -- exactly what happened on the first attempt. CMake resolves
# target_link_libraries names at generate time, so linking a target declared
# later in the same directory scope is legal.
if(BUILD_DEEP2_REMOTE64_INTEGRATION_CERT)
    add_executable(deep2_remote64_integration_cert
        src/deep2/deep2_remote64_integration_cert.cpp
    )
    target_link_libraries(deep2_remote64_integration_cert PRIVATE
        rawrxd_remote64
        InferenceEngine
    )
    target_include_directories(deep2_remote64_integration_cert PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/deep2"
    )
    target_compile_features(deep2_remote64_integration_cert PRIVATE cxx_std_17)
    set_target_properties(deep2_remote64_integration_cert PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    message(STATUS "[remote64] product integration cert: deep2_remote64_integration_cert")
endif()