; Advanced Auth Header File
; Phase D Component 4: OAuth2, JWT, RBAC authentication

; Authentication error codes
AUTH_SUCCESS equ 0
AUTH_ERROR_INVALID equ 1
AUTH_ERROR_OOM equ 2
AUTH_ERROR_NOT_FOUND equ 3
AUTH_ERROR_EXISTS equ 4
AUTH_ERROR_FULL equ 5
AUTH_ERROR_INVALID_CREDENTIALS equ 6
AUTH_ERROR_EXPIRED equ 7
AUTH_ERROR_INSUFFICIENT_PERMISSIONS equ 8

; Authentication system structure
AUTH_SYSTEM STRUCT
    auth_mutex DWORD ?
    user_count DWORD ?
    max_users DWORD ?
    token_count DWORD ?
    max_tokens DWORD ?
    users_ptr DWORD ?
    tokens_ptr DWORD ?
    secret_key_ptr DWORD ?
    secret_key_len DWORD ?
    oauth_providers_ptr DWORD ?
    allocator_ptr DWORD ?
    deallocator_ptr DWORD ?
    stats_enabled DWORD ?
    reserved BYTE 12*4 dup(?)
AUTH_SYSTEM ENDS

; User structure
USER STRUCT
    user_id DWORD ?
    username_ptr DWORD ?
    username_len DWORD ?
    password_hash_ptr DWORD ?
    password_hash_len DWORD ?
    roles_ptr DWORD ?
    roles_count DWORD ?
    created_at DWORD ?
    last_login DWORD ?
    flags DWORD ?
    reserved BYTE 4*4 dup(?)
USER ENDS

; Token structure
TOKEN STRUCT
    token_id DWORD ?
    user_id DWORD ?
    token_ptr DWORD ?
    token_len DWORD ?
    token_type DWORD ?
    expires_at DWORD ?
    scopes_ptr DWORD ?
    scopes_count DWORD ?
    created_at DWORD ?
    flags DWORD ?
    reserved BYTE 2*4 dup(?)
TOKEN ENDS

; OAuth provider structure
OAUTH_PROVIDER STRUCT
    provider_id DWORD ?
    name_ptr DWORD ?
    name_len DWORD ?
    client_id_ptr DWORD ?
    client_id_len DWORD ?
    client_secret_ptr DWORD ?
    client_secret_len DWORD ?
    auth_url_ptr DWORD ?
    token_url_ptr DWORD ?
    reserved BYTE 4*4 dup(?)
OAUTH_PROVIDER ENDS

; Constants
USER_MAX_USERNAME_LEN equ 256
USER_MAX_PASSWORD_LEN equ 256
TOKEN_MAX_LEN equ 4096
OAUTH_MAX_NAME_LEN equ 256
OAUTH_MAX_CLIENT_ID_LEN equ 256
OAUTH_MAX_CLIENT_SECRET_LEN equ 256
OAUTH_MAX_URL_LEN equ 1024

; Function declarations
EXTERN auth_init:proc
EXTERN auth_shutdown:proc
EXTERN auth_authenticate:proc
EXTERN auth_authorize:proc




