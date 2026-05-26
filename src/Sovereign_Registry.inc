; ==============================================================================
; Sovereign_Registry.inc - Minimalist Registry Hub
; ==============================================================================

SovereignEntry STRUCT
    EntryID     DQ 0
    pBase       DQ 0
    EntrySize   DQ 0
    EntryFlags  DQ 0
SovereignEntry ENDS

SovereignHub STRUCT
    Entries     SovereignEntry 1024 DUP ({})
    Count       DQ 0
SovereignHub ENDS
