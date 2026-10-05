# rawr_build_identity.cmake
# RAWRXD_CERT_BINARY_BUILD_IDENTITY_001
#
# WHY THIS EXISTS
# ---------------
# Four times in one session MSBuild produced a binary that ran, printed a
# plausible receipt, and did not contain the source it was supposedly built from.
# The concrete chain:
#
#     Deep2Engine.cpp edited to reference lw.ffnGate / lw.ffnUp / lw.ffnDown
#     -> Deep2Engine.obj left stale
#     -> link SUCCEEDED against the stale object
#     -> every gate in the chain certified a binary the current source does not
#        describe, and the source did not even compile
#
# mtime cannot see this. Those sources carried timestamps OLDER than their
# objects, so the incremental build correctly reported "up to date" for content
# that had changed. A timestamp is not an identity.
#
# WHAT THIS GENERATES
# -------------------
# For each certification target, a generated header carrying git HEAD, tree
# dirty state, a SHA256 manifest over the EXACT source files that target
# compiles, a build id derived from both, the compile timestamp, and
# human-readable feature markers emitted as literal strings.
#
# The manifest is content-based. Edit any participating source and the manifest
# changes, the header changes, the translation unit recompiles, and the identity
# embedded in the binary changes with it. A runner that recomputes the manifest
# from the tree can then detect a binary that does not match its source.
#
# CMAKE_CONFIGURE_DEPENDS closes the loop the other way: editing a participating
# source re-triggers configure, so the header cannot go stale relative to the
# sources it describes.
#
# Feature markers are the human-readable half. Hashes prove identity but are
# opaque; a marker literal found inside the finished executable proves the code
# implementing that feature was actually linked in. A marker present in source
# but absent from the binary is precisely the stale-object signature.

include_guard(GLOBAL)

# rawr_sha256_string(<outvar> <text>)
#
# string(SHA256) is NOT usable here: on this CMake it returns an empty string
# and no diagnostic, which would have produced a manifest of "" and a build id
# of "" -- both of which compare EQUAL for every input, so every binary would
# have certified itself against every other. file(SHA256) works, so the text is
# staged to a file and hashed there.
function(rawr_sha256_string OUT_VAR TEXT)
    set(_tmp "${CMAKE_CURRENT_BINARY_DIR}/.rawr_sha_${OUT_VAR}.tmp")
    file(WRITE "${_tmp}" "${TEXT}")
    file(SHA256 "${_tmp}" _h)
    file(REMOVE "${_tmp}")
    set(${OUT_VAR} "${_h}" PARENT_SCOPE)
endfunction()

# rawr_sha256_manifest(<outvar> <files...>)
#
# One SHA256 over "<path>:<sha256>" for every file, in the order given. Callers
# pass a sorted list so the result does not depend on list plumbing. A missing
# file is fatal: a manifest that silently skipped a source would certify a binary
# built from less code than it claims.
function(rawr_sha256_manifest OUT_VAR)
    set(_entries "")
    foreach(_f IN LISTS ARGN)
        if(NOT EXISTS "${_f}")
            message(FATAL_ERROR
                "RAWRXD_CERT_BINARY_BUILD_IDENTITY_001: cannot build a source "
                "manifest, '${_f}' does not exist. Refusing to certify a binary "
                "whose provenance cannot be named.")
        endif()
        file(SHA256 "${_f}" _h)
        list(APPEND _entries "${_f}:${_h}")
    endforeach()
    string(REPLACE ";" "\n" _blob "${_entries}")
    rawr_sha256_string(_m "${_blob}")
    set(${OUT_VAR} "${_m}" PARENT_SCOPE)
endfunction()

function(rawr_git_head OUT_VAR)
    set(_head "unknown")
    find_program(_git git)
    if(_git)
        # No .git existence test here: the repository root is not necessarily
        # the CMake source dir (this tree is a subdirectory of a larger repo),
        # and git resolves the root itself from the working directory.
        execute_process(COMMAND "${_git}" rev-parse HEAD
                        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                        OUTPUT_VARIABLE _o ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(_o)
            set(_head "${_o}")
        endif()
    endif()
    set(${OUT_VAR} "${_head}" PARENT_SCOPE)
endfunction()

# "dirty" means the tree differs from HEAD. A dirty tree is not disqualifying --
# most of this work is uncommitted by design -- but it must be recorded, because
# two builds from two different dirty states are two different builds even when
# both are called master.
function(rawr_tree_dirty OUT_VAR)
    set(_dirty "unknown")
    find_program(_git git)
    if(_git)
        execute_process(COMMAND "${_git}" status --porcelain
                        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                        OUTPUT_VARIABLE _o ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(STRIP "${_o}" _o)
        if(_o STREQUAL "")
            set(_dirty "clean")
        else()
            set(_dirty "dirty")
        endif()
    endif()
    set(${OUT_VAR} "${_dirty}" PARENT_SCOPE)
endfunction()

# rawr_generate_build_identity(<target> <cert_name> FEATURE_MARKERS <m...> SOURCES <f...>)
#
# Generates ${CMAKE_BINARY_DIR}/gen/rawr_build_identity_<target>.hpp and adds it
# to the target. Call AFTER the target's sources are known.
function(rawr_generate_build_identity TARGET CERT_NAME)
    cmake_parse_arguments(ABI "" "" "FEATURE_MARKERS;SOURCES" ${ARGN})

    if(NOT ABI_SOURCES)
        message(FATAL_ERROR "rawr_generate_build_identity(${TARGET}): no SOURCES given")
    endif()

    set(_sorted ${ABI_SOURCES})
    list(REMOVE_DUPLICATES _sorted)
    list(SORT _sorted)
    list(LENGTH _sorted _count)

    rawr_sha256_manifest(_manifest ${_sorted})
    rawr_git_head(_head)
    rawr_tree_dirty(_dirty)

    string(REPLACE ";" "\n" _srcblob "${_sorted}")
    rawr_sha256_string(_cmd_hash "${TARGET}\n${_srcblob}")
    rawr_sha256_string(_build_id "${_manifest}:${_head}:${_dirty}")
    string(TIMESTAMP _now "%Y-%m-%dT%H:%M:%SZ" UTC)

    set(_marker_entries "")
    foreach(_m IN LISTS ABI_FEATURE_MARKERS)
        string(APPEND _marker_entries "    \"${_m}\",\n")
    endforeach()

    set(_dir "${CMAKE_BINARY_DIR}/gen")
    file(MAKE_DIRECTORY "${_dir}")
    set(_hdr "${_dir}/rawr_build_identity_${TARGET}.hpp")

    file(WRITE "${_hdr}"
"// GENERATED -- DO NOT EDIT.
// Produced by cmake/rawr_build_identity.cmake for target ${TARGET}.
// RAWRXD_CERT_BINARY_BUILD_IDENTITY_001
//
// A receipt that cannot name the source that produced the binary it came from
// is not a receipt. Everything below is derived from the CONTENT of the sources
// this target compiles, so the identity changes whenever any of them changes.
#pragma once
#include <cstddef>
#include <cstring>
#include <cstdio>

namespace rawrxd_cert {

struct BuildIdentity {
    char certName[48];
    char gitHead[41];
    char treeDirty[16];
    char sourceManifestSha256[65];
    char buildCommandSha256[65];
    char buildId[65];
    char compileTimestamp[24];
    char sourceCount[12];
};

// Marker literals. Scanning the finished EXECUTABLE for these proves the code
// that implements the feature was linked in; a marker present in source but
// absent from the binary is the stale-object signature.
inline constexpr const char* const kFeatureMarkers[] = {
${_marker_entries}};

inline constexpr int kFeatureMarkerCount =
    static_cast<int>(sizeof(kFeatureMarkers) / sizeof(kFeatureMarkers[0]));

inline BuildIdentity identity() {
    BuildIdentity id{};
    std::memset(&id, 0, sizeof(id));
    std::strncpy(id.certName,             \"${CERT_NAME}\",  sizeof(id.certName) - 1);
    std::strncpy(id.gitHead,              \"${_head}\",      sizeof(id.gitHead) - 1);
    std::strncpy(id.treeDirty,            \"${_dirty}\",     sizeof(id.treeDirty) - 1);
    std::strncpy(id.sourceManifestSha256, \"${_manifest}\",  sizeof(id.sourceManifestSha256) - 1);
    std::strncpy(id.buildCommandSha256,   \"${_cmd_hash}\",  sizeof(id.buildCommandSha256) - 1);
    std::strncpy(id.buildId,              \"${_build_id}\",  sizeof(id.buildId) - 1);
    std::strncpy(id.compileTimestamp,     \"${_now}\",       sizeof(id.compileTimestamp) - 1);
    std::snprintf(id.sourceCount, sizeof(id.sourceCount), \"%d\", ${_count});
    return id;
}

inline void print() {
    const BuildIdentity id = identity();
    std::fprintf(stderr, \"CERT_NAME=%s\\n\", id.certName);
    std::fprintf(stderr, \"GIT_HEAD=%s\\n\", id.gitHead);
    std::fprintf(stderr, \"TREE_DIRTY=%s\\n\", id.treeDirty);
    std::fprintf(stderr, \"SOURCE_COUNT=%s\\n\", id.sourceCount);
    std::fprintf(stderr, \"SOURCE_MANIFEST_SHA256=%s\\n\", id.sourceManifestSha256);
    std::fprintf(stderr, \"BUILD_COMMAND_SHA256=%s\\n\", id.buildCommandSha256);
    std::fprintf(stderr, \"BUILD_ID=%s\\n\", id.buildId);
    std::fprintf(stderr, \"COMPILE_TIMESTAMP=%s\\n\", id.compileTimestamp);
    std::fprintf(stderr, \"FEATURE_MARKER_COUNT=%d\\n\", kFeatureMarkerCount);
    for (int i = 0; i < kFeatureMarkerCount; ++i) {
        std::fprintf(stderr, \"FEATURE_MARKER=%s\\n\", kFeatureMarkers[i]);
    }
    std::fflush(stderr);
}

} // namespace rawrxd_cert

#define RAWRXD_PRINT_BUILD_IDENTITY() ::rawrxd_cert::print()
")

    # Editing any participating source must re-run configure, or this header
    # could describe sources that have since changed.
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${_sorted} "${_hdr}")

    # A .hpp added as a source does NOT put its directory on the include path,
    # so the target would fail with "cannot open include file". Add it.
    target_include_directories(${TARGET} PRIVATE "${_dir}")
    target_sources(${TARGET} PRIVATE "${_hdr}")

    message(STATUS "[build-identity] ${TARGET}: sources=${_count} manifest=${_manifest} dirty=${_dirty}")
endfunction()
