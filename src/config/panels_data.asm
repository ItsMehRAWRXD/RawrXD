; =============================================================================
; panels_data.asm - Zero-Dependency MASM x64 Panel Manifest
; Pure data declarations matching panels.json schema
; =============================================================================

.DATA

; ---------------------------------------------------------------------------
; 1. STRUCT DEFINITIONS
; ---------------------------------------------------------------------------
PanelLayout STRUCT
    IdPtr           QWORD ?   ; Pointer to null-terminated ASCII string
    TitlePtr        QWORD ?   ; Pointer to null-terminated ASCII string
    IconPtr         QWORD ?   ; Pointer to null-terminated ASCII string
    ScriptsArrayPtr QWORD ?   ; Pointer to null-terminated QWORD array
    CssArrayPtr     QWORD ?   ; Pointer to null-terminated QWORD array
    DepsArrayPtr    QWORD ?   ; Pointer to null-terminated QWORD array
    PermsArrayPtr   QWORD ?   ; Pointer to null-terminated QWORD array
PanelLayout ENDS

; ---------------------------------------------------------------------------
; 2. STRING LITERALS
; ---------------------------------------------------------------------------
; Panel 1: Crypto Performance
id_crypto       DB "crypto-performance", 0
title_crypto    DB "Cryptocurrency Analytics Engine", 0
icon_crypto     DB "trending-up", 0
script_crypto_1 DB "/src/panels/crypto/analytics.js", 0
css_crypto_1    DB "/src/panels/crypto/layout.css", 0
dep_crypto_1    DB "RawrRuntime", 0
dep_crypto_2    DB "DataVisualizerCore", 0
perm_crypto_1   DB "ipc:telemetry", 0

; Panel 2: System Diagnostics
id_diag         DB "system-diagnostics", 0
title_diag      DB "Core System Monitor", 0
icon_diag       DB "activity", 0
script_diag_1   DB "/src/panels/diag/monitor.js", 0
css_diag_1      DB "/src/panels/diag/style.css", 0
dep_diag_1      DB "RawrRuntime", 0
perm_diag_1     DB "ipc:telemetry", 0
perm_diag_2     DB "ipc:engine", 0

; Panel 3: Engine Manager
id_engine       DB "engine-manager", 0
title_engine    DB "Engine Manager", 0
icon_engine     DB "cpu", 0
script_engine_1 DB "/src/panels/engine/manager.js", 0
css_engine_1    DB "/src/panels/engine/style.css", 0
dep_engine_1    DB "RawrRuntime", 0
dep_engine_2    DB "RawrIpcSynchronizer", 0
perm_engine_1   DB "ipc:engine", 0
perm_engine_2   DB "ipc:telemetry", 0

; Panel 4: Telemetry Dashboard
id_tele         DB "telemetry-dashboard", 0
title_tele      DB "Telemetry Dashboard", 0
icon_tele       DB "bar-chart", 0
script_tele_1   DB "/src/panels/telemetry/dashboard.js", 0
css_tele_1      DB "/src/panels/telemetry/style.css", 0
dep_tele_1      DB "RawrRuntime", 0
dep_tele_2      DB "DataVisualizerCore", 0
perm_tele_1     DB "ipc:telemetry", 0

; Panel 5: Session Manager
id_sess         DB "session-manager-panel", 0
title_sess      DB "Session Manager", 0
icon_sess       DB "lock", 0
script_sess_1   DB "/src/panels/session/manager.js", 0
css_sess_1      DB "/src/panels/session/style.css", 0
dep_sess_1      DB "RawrRuntime", 0
dep_sess_2      DB "RawrSessionManager", 0
perm_sess_1     DB "ipc:telemetry", 0

; ---------------------------------------------------------------------------
; 3. ARRAY LISTS (null-terminated QWORD arrays)
; ---------------------------------------------------------------------------
ALIGN 8

; Panel 1 arrays
CryptoScripts   QWORD OFFSET script_crypto_1, 0
CryptoCSS       QWORD OFFSET css_crypto_1, 0
CryptoDeps      QWORD OFFSET dep_crypto_1, OFFSET dep_crypto_2, 0
CryptoPerms     QWORD OFFSET perm_crypto_1, 0

; Panel 2 arrays
DiagScripts     QWORD OFFSET script_diag_1, 0
DiagCSS         QWORD OFFSET css_diag_1, 0
DiagDeps        QWORD OFFSET dep_diag_1, 0
DiagPerms       QWORD OFFSET perm_diag_1, OFFSET perm_diag_2, 0

; Panel 3 arrays
EngineScripts   QWORD OFFSET script_engine_1, 0
EngineCSS       QWORD OFFSET css_engine_1, 0
EngineDeps      QWORD OFFSET dep_engine_1, OFFSET dep_engine_2, 0
EnginePerms     QWORD OFFSET perm_engine_1, OFFSET perm_engine_2, 0

; Panel 4 arrays
TeleScripts     QWORD OFFSET script_tele_1, 0
TeleCSS         QWORD OFFSET css_tele_1, 0
TeleDeps        QWORD OFFSET dep_tele_1, OFFSET dep_tele_2, 0
TelePerms       QWORD OFFSET perm_tele_1, 0

; Panel 5 arrays
SessScripts     QWORD OFFSET script_sess_1, 0
SessCSS         QWORD OFFSET css_sess_1, 0
SessDeps        QWORD OFFSET dep_sess_1, OFFSET dep_sess_2, 0
SessPerms       QWORD OFFSET perm_sess_1, 0

; ---------------------------------------------------------------------------
; 4. CENTRAL MANIFEST REGISTRY
; ---------------------------------------------------------------------------
ALIGN 8
PUBLIC PANEL_MANIFEST_REGISTRY
PUBLIC PANEL_MANIFEST_COUNT

PANEL_MANIFEST_REGISTRY \
    PanelLayout <OFFSET id_crypto, OFFSET title_crypto, OFFSET icon_crypto, OFFSET CryptoScripts, OFFSET CryptoCSS, OFFSET CryptoDeps, OFFSET CryptoPerms> \
    PanelLayout <OFFSET id_diag,   OFFSET title_diag,   OFFSET icon_diag,   OFFSET DiagScripts,   OFFSET DiagCSS,   OFFSET DiagDeps,   OFFSET DiagPerms> \
    PanelLayout <OFFSET id_engine, OFFSET title_engine, OFFSET icon_engine, OFFSET EngineScripts, OFFSET EngineCSS, OFFSET EngineDeps, OFFSET EnginePerms> \
    PanelLayout <OFFSET id_tele,   OFFSET title_tele,   OFFSET icon_tele,   OFFSET TeleScripts,   OFFSET TeleCSS,   OFFSET TeleDeps,   OFFSET TelePerms> \
    PanelLayout <OFFSET id_sess,   OFFSET title_sess,   OFFSET icon_sess,   OFFSET SessScripts,   OFFSET SessCSS,   OFFSET SessDeps,   OFFSET SessPerms>

PANEL_MANIFEST_COUNT QWORD 5

; ---------------------------------------------------------------------------
; 5. CODE SECTION (required for valid COFF)
; ---------------------------------------------------------------------------
.CODE
END
