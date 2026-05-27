; ==============================================================================
; SOVEREIGN_COMPUTE_KERNEL (Ray-Marching Lambertian Shading)
; Inputs: R15 = Fabric Context, RCX = Lane ID
; ==============================================================================
INCLUDE Sovereign_Types.inc

_DATA SEGMENT
    ALIGN 16
    float_radius       REAL4 0.5
    float_one          REAL4 1.0
    float_width_inv    REAL4 0.00625
    float_height_inv   REAL4 0.0078125
    float_aspect_ratio REAL4 1.25
    float_distortion   REAL4 0.35   ; Fisheye distortion strength
    float_255          REAL4 255.0
    light_dir          REAL4 0.5, 0.5, -0.707
    
    march_epsilon      REAL4 0.001
    march_max_dist     REAL4 100.0
    march_max_steps    DWORD 64
    
    depth_scalar       REAL4 40.0   ; To scale 't' to visible brightness
    depth_base         REAL4 255.0  ; Used to invert 't'

    ; Camera Setup
    camera_pos      REAL4 0.0, 0.0, -3.0 ; Ray Origin (O)
    camera_forward  REAL4 0.0, 0.0, 1.0  ; Forward vector (F)
    camera_right    REAL4 1.0, 0.0, 0.0  ; Right vector (R)
    camera_up       REAL4 0.0, 1.0, 0.0  ; Up vector (U)
    camera_zoom     REAL4 1.0            ; Perspective strength

    K1_Factor       REAL4 0.35           ; Mild-to-heavy barrel wrap
    K2_Factor       REAL4 0.12           ; Exponential edge stretching for ultra-wide look
    CA_Strength     REAL4 8.0            ; Chromatic aberration offset multiplier
_DATA ENDS

_TEXT SEGMENT 'CODE'
PUBLIC Sovereign_Compute_Kernel

SDF_EVAL MACRO
    ; 1. Sphere SDF (centered at 0,0,0)
    movaps xmm4, xmm0
    mulss xmm4, xmm4          ; x^2
    movaps xmm5, xmm1
    mulss xmm5, xmm5          ; y^2
    addss xmm4, xmm5
    movaps xmm5, xmm2
    mulss xmm5, xmm5          ; z^2
    addss xmm4, xmm5          ; sum
    sqrtss xmm4, xmm4         ; len
    subss xmm4, [float_radius]; d_sphere = len - radius
    
    ; 2. Floor SDF (y = -0.5)
    movaps xmm5, xmm1         ; P.y
    addss xmm5, [float_radius]; d_floor = P.y + radius (so it sits exactly on the floor)
    
    ; 3. Smooth / Union (Min)
    minss xmm4, xmm5          ; Get closest distance
    movss xmm3, xmm4          ; Output distance in xmm3
ENDM

Sovereign_Compute_Kernel PROC
    ; 1. Setup Lane-Specific Bounds
    ; Rows = 128, Lanes = 16 => 8 rows per lane
    mov r9, rcx
    shl r9, 3              ; Start_Y = Lane_ID * 8
    mov rdx, r9            ; RDX = Current_Y
    mov r10, r9
    add r10, 8             ; End_Y = Start_Y + 8
    
    ; 2. Initialize Framebuffer Pointer
    mov r8, [r15 + SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base]
    
@@Y_Loop:
    xor rbx, rbx           ; X = 0 (Column)
    
@@X_Loop:
    ; ==============================================================================
    ; COORDINATE NORMALIZATION
    ; ==============================================================================
    
    vcvtsi2ss xmm0, xmm0, rbx  ; X_float
    vcvtsi2ss xmm1, xmm1, rdx  ; Y_float
    
    movss xmm2, [float_width_inv]
    mulss xmm0, xmm2
    addss xmm0, xmm0              ; * 2.0
    subss xmm0, [float_one]       ; - 1.0
    
    movss xmm2, [float_height_inv]
    mulss xmm1, xmm2
    addss xmm1, xmm1              ; * 2.0
    subss xmm1, [float_one]       ; - 1.0
    
    mulss xmm0, [float_aspect_ratio] 
    ; --- FISHEYE DISTORTION ---
    movaps xmm2, xmm0
    mulss xmm2, xmm2               ; x^2
    movaps xmm3, xmm1
    mulss xmm3, xmm3               ; y^2
    addss xmm2, xmm3               ; r^2 = x^2 + y^2

    mulss xmm2, [float_distortion] ; d * r^2
    addss xmm2, [float_one]        ; 1.0 + (d * r^2)

    mulss xmm0, xmm2               ; x' = x * (1.0 + d * r^2)
    mulss xmm1, xmm2               ; y' = y * (1.0 + d * r^2)
    ; --------------------------
    ; ==============================================================================
    ; CAMERA VIEW MATRIX INTEGRATION
    ; ==============================================================================
    
    ; 1. Load Host Uniforms
    movss xmm6, dword ptr [r15 + SOVEREIGN_FABRIC_CONTEXT.Beacon_Registers + 0]    ; cos_t
    movss xmm7, dword ptr [r15 + SOVEREIGN_FABRIC_CONTEXT.Beacon_Registers + 8]    ; sin_t

    ; 2. Setup Ray Origin (O) and Rotate
    movss xmm13, [camera_pos]    ; X
    movss xmm14, [camera_pos+4]  ; Y
    movss xmm15, [camera_pos+8]  ; Z

    movss xmm0, xmm13            ; X
    mulss xmm0, xmm6             ; X * cos
    movss xmm1, xmm15            ; Z
    mulss xmm1, xmm7             ; Z * sin
    addss xmm0, xmm1             ; xmm0 = X_new
    
    movss xmm2, xmm13            ; X
    mulss xmm2, xmm7             ; X * sin
    movss xmm3, xmm15            ; Z
    mulss xmm3, xmm6             ; Z * cos
    subss xmm3, xmm2             ; xmm3 = Z_new

    movss xmm13, xmm0            ; Updated X
    movss xmm15, xmm3            ; Updated Z

    ; 3. Calculate Ray Direction (D)
    ; Restore normalized coordinates for D
    vcvtsi2ss xmm0, xmm0, rbx  ; X_float
    vcvtsi2ss xmm1, xmm1, rdx  ; Y_float
    
    movss xmm2, [float_width_inv]
    mulss xmm0, xmm2
    addss xmm0, xmm0              ; * 2.0
    subss xmm0, [float_one]       ; - 1.0
    
    movss xmm2, [float_height_inv]
    mulss xmm1, xmm2
    addss xmm1, xmm1              ; * 2.0
    subss xmm1, [float_one]       ; - 1.0
    
    mulss xmm0, [float_aspect_ratio] 

    ; ==============================================================================
    ; FISHEYE LENS DISTORTION BLOCK
    ; ==============================================================================
    ; 1. Calculate r^2 = (X*X) + (Y*Y)
    movaps  xmm11, xmm0         ; xmm11 = X
    mulss   xmm11, xmm11        ; xmm11 = X^2
    movaps  xmm12, xmm1         ; xmm12 = Y
    mulss   xmm12, xmm12        ; xmm12 = Y^2
    addss   xmm11, xmm12        ; xmm11 = r^2 = X^2 + Y^2

    ; 2. Calculate Secondary Term (K2 * r^4)
    movaps  xmm12, xmm11        ; xmm12 = r^2
    mulss   xmm12, xmm12        ; xmm12 = r^4
    mulss   xmm12, [K2_Factor]  ; xmm12 = K2 * r^4

    ; 3. Calculate Primary Term (K1 * r^2)
    movaps  xmm5, xmm11         ; xmm5 = r^2
    mulss   xmm5, [K1_Factor]   ; xmm5 = K1 * r^2

    ; 4. Accumulate Scaling Factor: (1.0 + K1*r^2 + K2*r^4)
    addss   xmm5, xmm12         ; xmm5 = (K1 * r^2) + (K2 * r^4)
    addss   xmm5, [float_one]   ; xmm5 = 1.0 + K1*r^2 + K2*r^4 (Scale Factor)

    ; 5. Inject / Apply distortion to original coordinates
    mulss   xmm0, xmm5          ; Distorted_X = X * Scale Factor
    mulss   xmm1, xmm5          ; Distorted_Y = Y * Scale Factor
    ; ==============================================================================

    movss xmm2, xmm0
    mulss xmm2, [camera_right]    
    movss xmm3, xmm1
    mulss xmm3, [camera_up+4]     
    movss xmm4, [camera_zoom]
    mulss xmm4, [camera_forward+8]

    ; Normalize Direction (D)
    movaps xmm8, xmm2
    movaps xmm9, xmm3
    movaps xmm10, xmm4
    
    movaps xmm5, xmm8
    mulss xmm5, xmm5             
    movaps xmm6, xmm9
    mulss xmm6, xmm6             
    addss xmm5, xmm6
    movaps xmm6, xmm10
    mulss xmm6, xmm6             
    addss xmm5, xmm6             
    sqrtss xmm5, xmm5            
    
    divss xmm8, xmm5             ; D_x / len
    divss xmm9, xmm5             ; D_y / len
    divss xmm10, xmm5            ; D_z / len

    ; ==============================================================================
    ; ROTATE RAY DIRECTION (D) BY CAMERA Y-YAW MATRIX
    ; ==============================================================================
    ; We must apply the same rotation to the Local Ray Direction that we applied to O
    ; xmm8 = Dx, xmm9 = Dy, xmm10 = Dz
    ; xmm6 = cos(t), xmm7 = sin(t)

    movaps xmm2, xmm8            ; Dx
    mulss xmm2, xmm6             ; Dx * cos
    movaps xmm3, xmm10           ; Dz
    mulss xmm3, xmm7             ; Dz * sin
    addss xmm2, xmm3             ; xmm2 = Dx_new

    movaps xmm4, xmm8            ; Dx
    mulss xmm4, xmm7             ; Dx * sin
    movaps xmm5, xmm10           ; Dz
    mulss xmm5, xmm6             ; Dz * cos
    subss xmm5, xmm4             ; xmm5 = Dz_new

    movaps xmm8, xmm2            ; Updated Dx
    movaps xmm10, xmm5           ; Updated Dz

    ; ==============================================================================
    ; RAY-MARCHING LOOP (Sphere Tracing)
    ; Accumulates total distance (t) until hit or max_dist
    ; ==============================================================================
    
    ; 1. Reset Marching Accumulator (t = 0.0)
    xorps xmm7, xmm7            ; t = 0.0
    mov r14, 0                  ; Step_Counter = 0

@@March_Loop:
    ; 2. P = O + D * t
    movaps xmm0, xmm8           ; Direction D_x
    mulss xmm0, xmm7            ; D_x * t
    addss xmm0, xmm13           ; P_x = O_x + (D_x * t)
    
    movaps xmm1, xmm9           ; Direction D_y
    mulss xmm1, xmm7            ; D_y * t
    addss xmm1, xmm14           ; P_y = O_y + (D_y * t)
    
    movaps xmm2, xmm10          ; Direction D_z
    mulss xmm2, xmm7            ; D_z * t
    addss xmm2, xmm15           ; P_z = O_z + (D_z * t)
    
    ; 3. SDF(P) Calculation
    movaps xmm3, xmm0
    mulss xmm3, xmm3            ; Px^2
    movaps xmm4, xmm1
    mulss xmm4, xmm4            ; Py^2
    addss xmm3, xmm4
    movaps xmm4, xmm2
    mulss xmm4, xmm4            ; Pz^2
    addss xmm3, xmm4            
    
    sqrtss xmm3, xmm3           ; len
    subss xmm3, [float_radius]  ; d = len - radius
    
    ; 4. Advance t
    addss xmm7, xmm3            ; t += d
    
    ; 5. Termination Checks
    comiss xmm3, [march_epsilon]
    jb @March_Hit
    
    comiss xmm7, [march_max_dist]
    ja @March_Miss
    
    ; Loop Iteration
    inc r14
    cmp r14d, [march_max_steps]
    jl @@March_Loop

@March_Miss:
    mov eax, 0FF000000h         ; Background: Black
    jmp @Write_Pixel

@March_Hit:
    ; ==============================================================================
    ; GRADIENT ESTIMATION (Finite Differences)
    ; Requires: xmm0, xmm1, xmm2 (Point P)
    ; ==============================================================================
    movss xmm11, [march_epsilon] ; Load epsilon
    
    ; --- X-Axis Gradient ---
    addss xmm0, xmm11            ; P.x + eps
    SDF_EVAL
    movss xmm8, xmm3            ; xmm8 = f(x+eps)
    subss xmm0, xmm11            ; Reset P.x
    subss xmm0, xmm11            ; P.x - eps
    SDF_EVAL
    subss xmm8, xmm3            ; Nx = f(x+eps) - f(x-eps)
    addss xmm0, xmm11            ; Reset P.x

    ; --- Y-Axis Gradient ---
    addss xmm1, xmm11            ; P.y + eps
    SDF_EVAL
    movss xmm9, xmm3            ; xmm9 = f(y+eps)
    subss xmm1, xmm11            ; Reset P.y
    subss xmm1, xmm11            ; P.y - eps
    SDF_EVAL
    subss xmm9, xmm3            ; Ny = f(y+eps) - f(y-eps)
    addss xmm1, xmm11            ; Reset P.y
    
    ; --- Z-Axis Gradient ---
    addss xmm2, xmm11            ; P.z + eps
    SDF_EVAL
    movss xmm10, xmm3           ; xmm10 = f(z+eps)
    subss xmm2, xmm11            ; Reset P.z
    subss xmm2, xmm11            ; P.z - eps
    SDF_EVAL
    subss xmm10, xmm3           ; Nz = f(z+eps) - f(z-eps)
    addss xmm2, xmm11            ; Reset P.z

    ; ==============================================================================
    ; LAMBERTIAN SHADING BLOCK (Normalization + Dot Product)
    ; Input: Normal (xmm8, xmm9, xmm10), light_dir (in _DATA)
    ; Output: Intensity packed into EAX
    ; ==============================================================================

    ; 1. Normalization of Gradient (N = grad / |grad|)
    movaps xmm4, xmm8
    mulss xmm4, xmm4          ; Nx^2
    movaps xmm5, xmm9
    mulss xmm5, xmm5          ; Ny^2
    addss xmm4, xmm5
    movaps xmm5, xmm10
    mulss xmm5, xmm5          ; Nz^2
    addss xmm4, xmm5          ; len^2
    sqrtss xmm4, xmm4         ; len

    divss xmm8, xmm4          ; Nx = Nx / len
    divss xmm9, xmm4          ; Ny = Ny / len
    divss xmm10, xmm4         ; Nz = Nz / len

    ; 2. Lambertian Dot Product (N . L)
    ; L is your light_dir constant
    movss xmm4, [light_dir]      ; Lx
    mulss xmm4, xmm8             ; Lx * Nx
    movss xmm5, [light_dir+4]    ; Ly
    mulss xmm5, xmm9             ; Ly * Ny
    addss xmm4, xmm5
    movss xmm5, [light_dir+8]    ; Lz
    mulss xmm5, xmm10            ; Lz * Nz
    addss xmm4, xmm5             ; dot = (N.L)

    ; 3. Clamp and Intensity Mapping
    xorps xmm5, xmm5             ; Zero
    maxss xmm4, xmm5             ; Clamp negative values to 0
    
    movss xmm5, [float_255]
    mulss xmm4, xmm5             ; Scale to 0.0 - 255.0

    ; ==============================================================================
    ; CHROMATIC ABERRATION & PACKING (Replaces standard RGB Packing)
    ; Inputs: xmm4 = Base Intensity (0.0 - 255.0)
    ; ==============================================================================
    
    ; 1. Recalculate Normalized Screen Coords (X, Y) to get Falloff
    vcvtsi2ss xmm0, xmm0, rbx  ; X_float
    vcvtsi2ss xmm1, xmm1, rdx  ; Y_float
    
    movss xmm2, [float_width_inv]
    mulss xmm0, xmm2
    addss xmm0, xmm0              ; * 2.0
    subss xmm0, [float_one]       ; - 1.0
    
    movss xmm2, [float_height_inv]
    mulss xmm1, xmm2
    addss xmm1, xmm1              ; * 2.0
    subss xmm1, [float_one]       ; - 1.0

    ; Calculate Edge Falloff Strength (X^2 + Y^2) -> xmm6
    movaps xmm6, xmm0        ; X
    mulss  xmm6, xmm6        ; X^2
    movaps xmm7, xmm1        ; Y
    mulss  xmm7, xmm7        ; Y^2
    addss  xmm6, xmm7        ; Falloff = X^2 + Y^2
    mulss  xmm6, [CA_Strength] ; Scale the aberration

    ; 2. Branch Colors (Red = Base + CA, Green = Base, Blue = Base - CA)
    movaps xmm5, xmm4        ; Copy Base Intensity (Green)
    movaps xmm7, xmm4        ; Copy Base Intensity (Blue)
    
    addss  xmm4, xmm6        ; Red += Aberration
    subss  xmm7, xmm6        ; Blue -= Aberration

    ; 3. Clamp all colors (0.0 to 255.0)
    xorps  xmm6, xmm6        ; Zero for lower bound
    maxss  xmm4, xmm6
    maxss  xmm5, xmm6
    maxss  xmm7, xmm6
    
    movss  xmm6, [float_255]
    minss  xmm4, xmm6
    minss  xmm5, xmm6
    minss  xmm7, xmm6

    ; 4. Convert components to integers
    cvttss2si edi, xmm4      ; RED
    cvttss2si esi, xmm5      ; GREEN
    cvttss2si eax, xmm7      ; BLUE

    ; 5. Final Packing (ARGB Output)
    shl edi, 16              ; Shift Red
    shl esi, 8               ; Shift Green
    or  eax, edi
    or  eax, esi
    or  eax, 0FF000000h      ; Set Alpha to opaque
    
    jmp @Write_Pixel

@Write_Pixel:
    ; Write Pixel
    mov r11, rdx
    imul r11, 160
    add r11, rbx
    shl r11, 2             ; x4 bytes
    mov [r8 + r11], eax
    
    inc rbx
    cmp rbx, 160           ; SCREEN_WIDTH
    jl @@X_Loop
    
    inc rdx
    cmp rdx, r10           ; End_Y
    jl @@Y_Loop

    ; 5. Update Local Telemetry
    mov r11, rcx
    shl r11, 6
    lea r11, [r15 + SOVEREIGN_FABRIC_CONTEXT.Lanes + r11]
    lock inc QWORD PTR [r11 + SOVEREIGN_LANE.Cycle_Count]

    ret
Sovereign_Compute_Kernel ENDP

_TEXT ENDS
END
