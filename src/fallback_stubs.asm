.CODE
PUBLIC XR_Emit_PE_Header
XR_Emit_PE_Header PROC
ret
XR_Emit_PE_Header ENDP

PUBLIC XR_JIT_Emit_Kernel
XR_JIT_Emit_Kernel PROC
ret
XR_JIT_Emit_Kernel ENDP

PUBLIC UpdateBallistics
UpdateBallistics PROC
ret
UpdateBallistics ENDP

PUBLIC CheckCollision
CheckCollision PROC
ret
CheckCollision ENDP

PUBLIC NetworkTick
NetworkTick PROC
ret
NetworkTick ENDP

PUBLIC RenderFrame
RenderFrame PROC
ret
RenderFrame ENDP

PUBLIC InitializeWantedSystem
InitializeWantedSystem PROC
ret
InitializeWantedSystem ENDP

PUBLIC InitializeEntropyEngine
InitializeEntropyEngine PROC
ret
InitializeEntropyEngine ENDP

PUBLIC ApplyDynamicTurbulence
ApplyDynamicTurbulence PROC
ret
ApplyDynamicTurbulence ENDP

PUBLIC ExtractSessionToken
ExtractSessionToken PROC
ret
ExtractSessionToken ENDP

PUBLIC DispatchPayload
DispatchPayload PROC
ret
DispatchPayload ENDP

PUBLIC ReadDataLayer
ReadDataLayer PROC
ret
ReadDataLayer ENDP

PUBLIC WriteDataLayer
WriteDataLayer PROC
ret
WriteDataLayer ENDP

PUBLIC InitializeDataLayer
InitializeDataLayer PROC
ret
InitializeDataLayer ENDP

PUBLIC XR_JIT_Emit_LoadImm64
XR_JIT_Emit_LoadImm64 PROC
ret
XR_JIT_Emit_LoadImm64 ENDP

PUBLIC XR_JIT_Emit_LoopEnd
XR_JIT_Emit_LoopEnd PROC
ret
XR_JIT_Emit_LoopEnd ENDP

PUBLIC XR_JIT_Emit_AddImm32
XR_JIT_Emit_AddImm32 PROC
ret
XR_JIT_Emit_AddImm32 ENDP

PUBLIC XR_Promote_To_Executable
XR_Promote_To_Executable PROC
ret
XR_Promote_To_Executable ENDP

PUBLIC UpdateWantedSystem
UpdateWantedSystem PROC
ret
UpdateWantedSystem ENDP

PUBLIC InitializeWorldNetwork
InitializeWorldNetwork PROC
ret
InitializeWorldNetwork ENDP

PUBLIC InitializeGeoMapper
InitializeGeoMapper PROC
ret
InitializeGeoMapper ENDP

PUBLIC InitializeVehiclePhysics
InitializeVehiclePhysics PROC
ret
InitializeVehiclePhysics ENDP

PUBLIC UpdateVehiclePhysics
UpdateVehiclePhysics PROC
ret
UpdateVehiclePhysics ENDP

PUBLIC RenderHudOverlay
RenderHudOverlay PROC
ret
RenderHudOverlay ENDP

PUBLIC LoadGameState
LoadGameState PROC
ret
LoadGameState ENDP

PUBLIC XR_JIT_Inject_Probe
XR_JIT_Inject_Probe PROC
ret
XR_JIT_Inject_Probe ENDP

PUBLIC XR_Registry_Pop_Telemetry
XR_Registry_Pop_Telemetry PROC
ret
XR_Registry_Pop_Telemetry ENDP

PUBLIC XR_Registry_Push_Telemetry
XR_Registry_Push_Telemetry PROC
ret
XR_Registry_Push_Telemetry ENDP

PUBLIC GenerateWorldTopology
GenerateWorldTopology PROC
ret
GenerateWorldTopology ENDP

PUBLIC InitializePlayerSessions
InitializePlayerSessions PROC
ret
InitializePlayerSessions ENDP

PUBLIC HandleNetworkTick
HandleNetworkTick PROC
ret
HandleNetworkTick ENDP

PUBLIC SwitchProtagonist
SwitchProtagonist PROC
ret
SwitchProtagonist ENDP

PUBLIC GetActiveProtagInfo
GetActiveProtagInfo PROC
ret
GetActiveProtagInfo ENDP

PUBLIC ProcessTacticalInput
ProcessTacticalInput PROC
ret
ProcessTacticalInput ENDP

PUBLIC TriggerMissionStep
TriggerMissionStep PROC
ret
TriggerMissionStep ENDP

PUBLIC GetNPCResponse
GetNPCResponse PROC
ret
GetNPCResponse ENDP

PUBLIC CommitCrime
CommitCrime PROC
ret
CommitCrime ENDP

PUBLIC AssignRPRole
AssignRPRole PROC
ret
AssignRPRole ENDP

PUBLIC ProcessMapTile
ProcessMapTile PROC
ret
ProcessMapTile ENDP

PUBLIC FireProjectile
FireProjectile PROC
ret
FireProjectile ENDP

PUBLIC UpdateProjectiles
UpdateProjectiles PROC
ret
UpdateProjectiles ENDP

PUBLIC SaveGameState
SaveGameState PROC
ret
SaveGameState ENDP

PUBLIC Sovereign_Engine_Bootstrap
Sovereign_Engine_Bootstrap PROC
ret
Sovereign_Engine_Bootstrap ENDP

PUBLIC Sovereign_Kernel_MainLoop
Sovereign_Kernel_MainLoop PROC
ret
Sovereign_Kernel_MainLoop ENDP

PUBLIC Sovereign_Pulse_L2
Sovereign_Pulse_L2 PROC
ret
Sovereign_Pulse_L2 ENDP

PUBLIC PlayMediaStream
PlayMediaStream PROC
ret
PlayMediaStream ENDP

PUBLIC SendPhoneMessage
SendPhoneMessage PROC
ret
SendPhoneMessage ENDP

.DATA
PUBLIC g_SovereignRegistry
g_SovereignRegistry DQ 0
PUBLIC g_SchedulerState
g_SchedulerState DQ 0
PUBLIC g_ExecutionTick
g_ExecutionTick DQ 0
PUBLIC g_ResidencyMask
g_ResidencyMask DQ 0
END

