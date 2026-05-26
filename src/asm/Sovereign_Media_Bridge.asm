; =========================================================================================
; FILE: Sovereign_Media_Bridge.asm
; SUBSYSTEM: MULTIPLAYER/OFFLINE MEDIA DISPATCHER
; Pure x64 MASM / No Dependencies / Jitter-Free
; Purpose: Procedurally selects and dispatches media stream requests (Spotify, YouTube,
;          SoundCloud) based on world state and location triggers.
; =========================================================================================

.DATA
; -----------------------------------------------------------------------------------------
; DETERMINISTIC PRNG STATE FOR MEDIA
; -----------------------------------------------------------------------------------------
align 8
g_Media_PRNG_State dq 3322114455667788h

.CODE

; -----------------------------------------------------------------------------------------
; MEDIA SOURCE IDENTIFIERS
; -----------------------------------------------------------------------------------------
SOURCE_SPOTIFY      EQU 1
SOURCE_YOUTUBE      EQU 2
SOURCE_SOUNDCLOUD   EQU 3
SOURCE_OFFLINE_WAV  EQU 4

; GENRE MASKS (Affects selection probability)
GENRE_CHILL         EQU 1
GENRE_HYPE          EQU 2
GENRE_GRITTY        EQU 3
GENRE_SYNTHWAVE     EQU 4
GENRE_AMIGAJAZZ     EQU 5

; -----------------------------------------------------------------------------------------
; UINT64 Fast_Rand_Media()
; Isolated XorShift64* PRNG for Media consistency.
; -----------------------------------------------------------------------------------------
Fast_Rand_Media PROC
    mov rax, qword ptr [g_Media_PRNG_State]
    mov rdx, rax
    shl rdx, 12
    xor rax, rdx
    
    mov rdx, rax
    shr rdx, 25
    xor rax, rdx
    
    mov rdx, rax
    shl rdx, 27
    xor rax, rdx
    
    mov qword ptr [g_Media_PRNG_State], rax
    
    mov rdx, 2685821657736338717
    imul rax, rdx
    ret
Fast_Rand_Media ENDP

; -----------------------------------------------------------------------------------------
; UINT64 Sovereign_Media_Select_Station(UINT32 locationType)
; RCX = locationType (Reference POI_IDs from World_Generator)
; Returns packed media request in RAX.
; Bit Layout:
; [0-7]   Media Source (1=Spotify, 2=YouTube, 3=SoundCloud, 4=Offline)
; [8-15]  Genre Recommendation
; [16-63] Procedural Track Variant ID (Used by higher level to fetch actual URI/File)
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Media_Select_Station
Sovereign_Media_Select_Station PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog

    mov ebx, ecx                   ; rbx = locationType
    xor rsi, rsi                   ; rsi = result accumulator

    ; 1) Determine Primary Source based on "Online/Offline" probability roll
    call Fast_Rand_Media
    mov rcx, rax                   ; Save random bits
    and rcx, 3                     ; Modulo 4 for source
    inc rcx                        ; Source is 1-4
    or rsi, rcx

    ; 2) Select Genre based on location context
    ; Logic: Map Hospital -> Chill, Car Lot -> Hype, Military -> Gritty
    mov rdx, GENRE_CHILL           ; Default
    cmp ebx, 8                     ; POI_MILITARY_BASE (Reference)
    je @@SetGritty
    cmp ebx, 6                     ; POI_CAR_LOT
    je @@SetHype
    cmp ebx, 10                    ; POI_POLICE_STATION
    je @@SetGritty
    jmp @@WriteGenre

@@SetGritty:
    mov rdx, GENRE_GRITTY
    jmp @@WriteGenre
@@SetHype:
    mov rdx, GENRE_HYPE

@@WriteGenre:
    shl rdx, 8
    or rsi, rdx

    ; 3) Generate Track Variant ID (Procedural)
    call Fast_Rand_Media
    shl rax, 16                    ; Move bit-mask to start at bit 16
    and rax, 0FFFFFFFFFFFF0000h    ; Mask just in case
    or rsi, rax

    mov rax, rsi                   ; Return packed media request
    pop rsi
    pop rbx
    ret
Sovereign_Media_Select_Station ENDP

; -----------------------------------------------------------------------------------------
; VOID Sovereign_Sync_Multiplayer_Music(UINT64 masterTrackID)
; RCX = Incoming TrackID from Host
; Forces local PRNG state to sync for synchronized radio play.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_Sync_Multiplayer_Music
Sovereign_Sync_Multiplayer_Music PROC
    test rcx, rcx
    jz @@Skip
    mov qword ptr [g_Media_PRNG_State], rcx
@@Skip:
    ret
Sovereign_Sync_Multiplayer_Music ENDP

END