# VAL-077: Certification Framework Test Suite CMake Configuration
# Tests for all 22 certification gates (VAL-050 to VAL-082)

cmake_minimum_required(VERSION 3.20)

# Certification test executable
add_executable(test_certification_framework
    test_certification_framework.cpp
    test_manifest_signer.cpp
    test_fault_injection.cpp
    test_supply_chain_provenance.cpp
    test_continuous_certification.cpp
)

# Include directories
target_include_directories(test_certification_framework PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/certification
    ${CMAKE_SOURCE_DIR}/include
)

# Link with certification sources (they're already in the main SOURCES list)
# But we need to ensure they're compiled
target_sources(test_certification_framework PRIVATE
    ${CMAKE_SOURCE_DIR}/src/certification/manifest_signer.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/supply_chain_provenance.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/fault_injection.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/continuous_certification_runner.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/external_verifier.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/artifact_compatibility.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/cross_platform_verification.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/reproducible_build_proof.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/certification_revocation.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/evidence_verifier.cpp
    ${CMAKE_SOURCE_DIR}/src/certification/threat_boundary_tests.cpp
)

# C++20 standard
target_compile_features(test_certification_framework PRIVATE cxx_std_20)

# Platform-specific settings
if(MSVC)
    target_compile_options(test_certification_framework PRIVATE /W4 /WX-)
else()
    target_compile_options(test_certification_framework PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# Add to CTest
add_test(NAME CertificationFramework COMMAND test_certification_framework)

# Set test properties
set_tests_properties(CertificationFramework PROPERTIES
    TIMEOUT 300  # 5 minute timeout
    LABELS "certification;production"
)

message(STATUS "VAL-077: Certification framework test suite configured")
