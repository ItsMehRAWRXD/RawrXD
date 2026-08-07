# ═════════════════════════════════════════════════════════════════════════════
# RawrXD OMEGA-1 Autonomous Engine CMake Configuration
# ═════════════════════════════════════════════════════════════════════════════

cmake_minimum_required(VERSION 3.20)

# Omega-1 PowerShell Module Installation
set(OMEGA1_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/omega1_modules" CACHE PATH "Omega-1 module directory")
set(OMEGA1_ROOT "D:/lazy init ide/auto_generated_methods" CACHE PATH "Omega-1 runtime root")

# PowerShell module files
set(OMEGA1_MODULES
    RawrXD.Core.psm1
    RawrXD.Deployment.psm1
    RawrXD.Agentic.psm1
    RawrXD.Observability.psm1
    RawrXD.Win32.psm1
    RawrXD.ModelLoader.psm1
    RawrXD.Swarm.psm1
    RawrXD.Production.psm1
    RawrXD.ReverseEngineering.psm1
    RawrXD.Testing.psm1
    RawrXD.Security.psm1
    RawrXD.Performance.psm1
    RawrXD.AutonomousEnhancement.psm1
    RawrXD.DeploymentOrchestrator.psm1
    RawrXD.UltimateProduction.psm1
    RawrXD.CustomModelLoaders.psm1
)

# C++ Bridge source
set(OMEGA1_SOURCES
    OmegaPowerShellBridge.cpp
)

# Install PowerShell modules
foreach(module ${OMEGA1_MODULES})
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/${module}
        ${OMEGA1_ROOT}/${module}
        COPYONLY
    )
endforeach()

# Install genesis script
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/genesis.ps1
    ${OMEGA1_ROOT}/genesis.ps1
    COPYONLY
)

# Install manifest generator
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/Generate-Manifest.ps1
    ${OMEGA1_ROOT}/Generate-Manifest.ps1
    COPYONLY
)

# Add Omega-1 bridge to main library
target_sources(RawrXDBridge PRIVATE ${OMEGA1_SOURCES})

# Define RAWRXD_OMEGA_ROOT for runtime
target_compile_definitions(RawrXDBridge PRIVATE
    RAWRXD_OMEGA_ROOT="${OMEGA1_ROOT}"
)

# Post-build: Bootstrap Omega-1
add_custom_command(TARGET RawrXDBridge POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Bootstrapping OMEGA-1..."
    COMMAND powershell -ExecutionPolicy Bypass -File "${OMEGA1_ROOT}/genesis.ps1" -RootPath "${OMEGA1_ROOT}"
    COMMENT "Initializing OMEGA-1 Autonomous Engine"
)
