; =========================================================================================
; FILE: Sovereign_Maps_Landscape_Bridge.asm
; SUBSYSTEM: GOOGLE MAPS GEODATA INTEGRATION BRIDGE
; Pure x64 MASM / No Dependencies / Lock-Free
; Purpose: Maps real-world Google Maps metadata (Geodata) into Sovereign POI types.
;          Allows for semi-procedural generation following real urban layouts.
; =========================================================================================

.CODE

; -----------------------------------------------------------------------------------------
; MAP METADATA STRUCTURE (Expected from Geodata Pre-Processor)
; -----------------------------------------------------------------------------------------
; Struct Map_Metadata:
; [0-3]   UINT32 AreaDensity (0:Wilderness, 1:Rural, 2:Suburban, 3:Urban, 4:Industrial)
; [4-7]   UINT32 FeatureFlags (Bitmask for specific real-world landmark detection)
; [8-11]  UINT32 ElevationData (Used for placement height)
; [12-15] UINT32 ZoningHash (Deterministic hash of Google Place ID)

; Feature Flags (Geodata detections)
MAP_FEAT_HOSPITAL   EQU 00000001h
MAP_FEAT_POLICE     EQU 00000002h
MAP_FEAT_MILITARY   EQU 00000004h
MAP_FEAT_WATERFRONT EQU 00000008h
MAP_FEAT_PARKING    EQU 00000010h

; POI Reference IDs (Must match World_Generator)
POI_CAMPER           EQU 1
POI_TRAILER          EQU 2
POI_BUILDING         EQU 3
POI_SUBURB           EQU 4
POI_NEIGHBORHOOD     EQU 5
POI_CAR_LOT          EQU 6
POI_DOCK             EQU 7
POI_MILITARY_BASE    EQU 8
POI_CIVILIAN         EQU 9
POI_POLICE_STATION   EQU 10
POI_HOSPITAL         EQU 11

; -----------------------------------------------------------------------------------------
; UINT64 Sovereign_Map_Resolve_POI(void* pMapMeta)
; RCX = Pointer to Map_Metadata structure
; Returns: RAX = Final POI ID to generate for this world location.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Map_Resolve_POI
Sovereign_Map_Resolve_POI PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog

    test rcx, rcx
    jz @@DefaultWilderness

    ; 1) Check Feature Flags first (Prioritize landmarks detected by Maps API)
    mov eax, dword ptr [rcx+4]     ; EAX = FeatureFlags
    
    test eax, MAP_FEAT_HOSPITAL
    jnz @@PoiHospital
    
    test eax, MAP_FEAT_POLICE
    jnz @@PoiPolice
    
    test eax, MAP_FEAT_MILITARY
    jnz @@PoiMilitary
    
    test eax, MAP_FEAT_WATERFRONT
    jnz @@PoiDock
    
    test eax, MAP_FEAT_PARKING
    jnz @@PoiCarLot

    ; 2) Fallback to Area Density if no specific landmark bits are set
    mov r8d, dword ptr [rcx+0]     ; R8D = AreaDensity
    
    cmp r8d, 3                     ; Urban
    je @@PoiBuilding
    
    cmp r8d, 2                     ; Suburban
    je @@PoiNeighborhood
    
    cmp r8d, 1                     ; Rural
    je @@PoiTrailer
    
    cmp r8d, 4                     ; Industrial
    je @@PoiBuilding

@@DefaultWilderness:
    ; Low density / Wilderness defaults to campers/wilderness explorers
    mov rax, POI_CAMPER
    pop rbx
    ret

; Jump targets for Return Values
@@PoiHospital:
    mov rax, POI_HOSPITAL
    pop rbx
    ret
@@PoiPolice:
    mov rax, POI_POLICE_STATION
    pop rbx
    ret
@@PoiMilitary:
    mov rax, POI_MILITARY_BASE
    pop rbx
    ret
@@PoiDock:
    mov rax, POI_DOCK
    pop rbx
    ret
@@PoiCarLot:
    mov rax, POI_CAR_LOT
    pop rbx
    ret
@@PoiBuilding:
    mov rax, POI_BUILDING
    pop rbx
    ret
@@PoiNeighborhood:
    mov rax, POI_NEIGHBORHOOD
    pop rbx
    ret
@@PoiTrailer:
    mov rax, POI_TRAILER
    pop rbx
    ret

Sovereign_Map_Resolve_POI ENDP

END