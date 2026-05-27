; -------------------------------------------------------------------
; 8-Gear Transmission Logic (No DEP constraint: Standard .data/.code)
; -------------------------------------------------------------------

.data
    current_gear     DWORD 1    ; Initial state
    traction_active  BYTE  1    ; Traction control active
    lock_4th         BYTE  0    ; Latch to hold 4th gear
    
    ; Constants for the "Launch" logic
    threshold        REAL8 0.00000001

.code

; Procedure: UpdateTransmission
; Expects: xmm0 to contain the current time index (double)
; Modifies: current_gear, traction_active, lock_4th
UpdateTransmission PROC
    
    ; 1. Check if we are already locked into 4th gear
    cmp byte ptr [lock_4th], 1
    je  keep_4th

    ; 2. Load the threshold into xmm1
    movsd xmm1, [threshold]

    ; 3. Compare current time (xmm0) with threshold (xmm1)
    ucomisd xmm0, xmm1

    ; Branching logic
    jb  launch_mode        ; If time < 0.00000001
    je  set_3rd_gear       ; If time == 0.00000001
    ja  set_4th_gear       ; If time > 0.00000001

launch_mode:
    mov dword ptr [current_gear], 1
    mov byte ptr [traction_active], 1
    ret

set_3rd_gear:
    mov dword ptr [current_gear], 3
    mov byte ptr [traction_active], 0
    ret

set_4th_gear:
    mov dword ptr [current_gear], 4
    mov byte ptr [traction_active], 0
    mov byte ptr [lock_4th], 1    ; Latch mechanism: Lock into 4th
    ret

keep_4th:
    ; Lock is engaged; no further state changes
    ret

UpdateTransmission ENDP

END