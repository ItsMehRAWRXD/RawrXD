//==============================================================================
// AgentCLICommands.cpp - CLI integration for Agent subsystem
//
// Registers the agent subsystem with the unified CLI
//==============================================================================

#include "../core/AgentSubsystem.h"
#include <cstdio>
#include <cstring>

// Forward declaration from SovereignCLI_Unified.cpp
extern "C" {
    typedef struct {
        const char* name;
        const char* version;
        int type;
        unsigned int capabilities;
        int state;
        int (*handler)(int argc, char** argv, char* output, size_t output_size);
        int (*init)(void);
        int (*shutdown)(void);
        int (*get_status)(char* status, size_t status_size);
    } SovereignSubsystem;
    
    int Sovereign_RegisterSubsystem(const SovereignSubsystem* subsystem);
}

//==============================================================================
// Agent Subsystem Registration
//==============================================================================

static int Agent_Init_Wrapper(void) {
    return AgentSubsystem_Init();
}

static int Agent_Shutdown_Wrapper(void) {
    return AgentSubsystem_Shutdown();
}

static int Agent_GetStatus_Wrapper(char* status, size_t status_size) {
    return AgentSubsystem_GetStatus(status, status_size);
}

//==============================================================================
// Register Agent with CLI
//==============================================================================

extern "C" int RegisterAgentSubsystem(void) {
    SovereignSubsystem agent_subsystem;
    memset(&agent_subsystem, 0, sizeof(agent_subsystem));
    
    agent_subsystem.name = "agent";
    agent_subsystem.version = AGENT_VERSION;
    agent_subsystem.type = 52;  // Next after existing 52 subsystems
    agent_subsystem.capabilities = 0x04;  // CAP_ANALYZE
    agent_subsystem.state = 1;  // STATE_READY
    agent_subsystem.handler = AgentSubsystem_Handler;
    agent_subsystem.init = Agent_Init_Wrapper;
    agent_subsystem.shutdown = Agent_Shutdown_Wrapper;
    agent_subsystem.get_status = Agent_GetStatus_Wrapper;
    
    return Sovereign_RegisterSubsystem(&agent_subsystem);
}

//==============================================================================
// Quick Test Function
//==============================================================================

extern "C" int TestAgentConnection(void) {
    char status[256];
    int result = Agent_GetStatus(status, sizeof(status));
    
    if (result == 0) {
        printf("Agent Status: %s\n", status);
        return 0;
    } else {
        printf("Agent not initialized\n");
        return -1;
    }
}
