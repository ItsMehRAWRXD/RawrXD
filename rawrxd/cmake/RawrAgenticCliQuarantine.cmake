# RAWRXD_AGENTIC_CLI_QUARANTINE_001
#
# Q2 tombstone. Replaces cmake/RawrAgenticCli.fragment.cmake, which declared a
# second, complete agentic CLI/runtime authority (agent loop, tools, permission
# gate, command guard, patch engine, session store, evidence writer, context
# window, history compactor, resume) plus 25 certificate executables.
#
# MEASURED AT QUARANTINE (2026-10-01):
#   * 63 declared sources in RAWR_AGENTIC_SOURCES: 0 exist on disk.
#   * src/platform/                            : does not exist.
#   * src/cli/rawr_main.cpp                    : does not exist.
#   * 25 rawr_agent_cert/rawr_ie_cert targets : point at certs/*.cpp that do
#                                                not exist.
#   * The fragment's own guard was `if(EXISTS src/cli/rawr_main.cpp)`, which is
#     false, so target_sources() never ran and configure still reported
#     success. That is the defect Q2 exists to remove: architectural absence
#     was converted into a successful configure.
#
# CANONICAL AUTHORITY (do not duplicate):
#   src/rawr_agent.cpp  ->  rawr_monolith
#   F:\~dev\CMakeLists.txt:9-54
#
# The preserved fragment is kept for provenance only, at
#   rawrxd/cmake/quarantine/RawrAgenticCli.fragment.cmake.QUARANTINED
# It is deliberately NOT included by any active build file.

option(BUILD_RAWRXD_AGENTIC_CLI
       "QUARANTINED: phantom second agent stack. See RAWRXD_AGENTIC_CLI_QUARANTINE_001."
       OFF)

if(BUILD_RAWRXD_AGENTIC_CLI)
  message(FATAL_ERROR
    "BUILD_RAWRXD_AGENTIC_CLI references a QUARANTINED phantom source set.\n"
    "  63 declared sources: 0 exist. 25 declared cert targets: 0 exist.\n"
    "  src/platform/ does not exist.\n"
    "  Canonical agent authority is src/rawr_agent.cpp -> rawr_monolith.\n"
    "  Preserved fragment: rawrxd/cmake/quarantine/"
    "RawrAgenticCli.fragment.cmake.QUARANTINED\n"
    "  See RAWRXD_AGENTIC_CLI_QUARANTINE_001 in AGENTS.md.")
endif()

message(STATUS
  "[Agentic] Second agent stack QUARANTINED "
  "(RAWRXD_AGENTIC_CLI_QUARANTINE_001); canonical authority is "
  "src/rawr_agent.cpp -> rawr_monolith")
