; Sovereign_Link.inc — Hardware/Logic Bridge
; v24.0.0-PRODUCTION
ifndef SOVEREIGN_LINK_INC
SOVEREIGN_LINK_INC equ 1

; Titan Hardware Slot Mapping
; These offsets translate Logic Signals to Titan DMA Registers
LINK_OFFSET_TITAN_SLOT_0    equ 0x1000
LINK_OFFSET_TITAN_SLOT_N    equ 0x2000

; Sovereign Global Logic State
; Access the Sovereign Core state without dynamic lookup
LINK_STATE_ACTIVE           equ 1
LINK_STATE_DRAIN            equ 2

endif
