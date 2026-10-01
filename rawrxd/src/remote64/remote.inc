OPTION CASEMAP:NONE

; RAWRXD_NATIVE_REMOTE_001 Win64 ABI header.
; Field names must not collide with MASM reserved words (TYPE, PTR, SIZE, WIDTH,
; HEIGHT, LENGTH, DEC, ...). All struct members below use ABI-neutral names.

RAWR_MAGIC EQU 52574152h
RAWR_VERSION EQU 1
RAWR_MAX_PAYLOAD EQU 16777216
RAWR_TILE EQU 64

R_OK EQU 0
R_ERR EQU -1
R_BOUNDS EQU -2
R_AUTH EQU -3
R_STATE EQU -4
R_IO EQU -5

S_DISCONNECTED EQU 0
S_CONNECTED EQU 1
S_PAIRING EQU 2
S_AUTHENTICATED EQU 3
S_VIEW_ONLY EQU 4
S_CONTROL EQU 5

MSG_HELLO EQU 1
MSG_CHALLENGE EQU 2
MSG_AUTH_PROOF EQU 3
MSG_AUTH_RESULT EQU 4
MSG_FRAME_BEGIN EQU 10h
MSG_TILE EQU 11h
MSG_FRAME_END EQU 12h
MSG_CURSOR EQU 20h
MSG_DISPLAY EQU 21h
MSG_MOUSE EQU 30h
MSG_KEYBOARD EQU 31h
MSG_PING EQU 40h
MSG_PONG EQU 41h
MSG_CLOSE EQU 0FFh

REMOTE_HEADER STRUCT
  magic      DWORD ?
  version    WORD ?
  msgType    WORD ?
  flags      DWORD ?
  sequence   QWORD ?
  payloadSize DWORD ?
  reserved   DWORD ?
REMOTE_HEADER ENDS

REMOTE_BUFFER STRUCT
  dataPtr     QWORD ?
  dataSize    QWORD ?
  dataCapacity QWORD ?
REMOTE_BUFFER ENDS

REMOTE_CAPTURE STRUCT
  screenDC    QWORD ?
  memoryDC    QWORD ?
  bitmap      QWORD ?
  oldBitmap   QWORD ?
  pixels      QWORD ?
  previous    QWORD ?
  bytes       QWORD ?
  frameW      DWORD ?
  frameH      DWORD ?
  stride      DWORD ?
  initialized DWORD ?
REMOTE_CAPTURE ENDS

REMOTE_SESSION STRUCT
  state          DWORD ?
  authenticated  DWORD ?
  controlAllowed DWORD ?
  reserved       DWORD ?
  txSequence     QWORD ?
  rxSequence     QWORD ?
  sessionKey     BYTE 32 DUP(?)
  challenge      BYTE 32 DUP(?)
REMOTE_SESSION ENDS

REMOTE_VIEWER STRUCT
  pixels      QWORD ?
  bytes       QWORD ?
  frameW      DWORD ?
  frameH      DWORD ?
  stride      DWORD ?
  initialized DWORD ?
REMOTE_VIEWER ENDS

REMOTE_TILE_HEADER STRUCT
  tileX     DWORD ?
  tileY     DWORD ?
  tileW     DWORD ?
  tileH     DWORD ?
  encoding  DWORD ?
  dataSize  DWORD ?
REMOTE_TILE_HEADER ENDS

REMOTE_CURSOR STRUCT
  cursorX   SDWORD ?
  cursorY   SDWORD ?
  visible   DWORD ?
  reserved  DWORD ?
REMOTE_CURSOR ENDS

; Layout-exact mirror of BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO (x64, sizeof 88).
; Field names match the Win32 declaration so the marshalling can be audited
; against bcrypt.h rather than against an invented shape.
BCRYPT_AEAD_INFO STRUCT
  cbSize       DWORD ?
  dwInfoVersion DWORD ?
  pbNonce      QWORD ?
  cbNonce      DWORD ?
  pad0         DWORD ?
  pbAuthData   QWORD ?
  cbAuthData   DWORD ?
  pad1         DWORD ?
  pbTag        QWORD ?
  cbTag        DWORD ?
  pad2         DWORD ?
  pbMacContext QWORD ?
  cbMacContext DWORD ?
  cbAAD        DWORD ?
  pbAAD        QWORD ?
  cbData       DWORD ?
  dwFlags      DWORD ?
BCRYPT_AEAD_INFO ENDS
