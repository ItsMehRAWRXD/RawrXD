@echo off
setlocal
echo ═══════════════════════════════════════════════
echo   RawrXD Cloud Hosting — Deploy
echo ═══════════════════════════════════════════════

:: Check .env
if not exist ".env" (
    echo [!] .env not found. Copy .env.example to .env and fill in values.
    exit /b 1
)

:: Generate self-signed certs if missing
if not exist "nginx\ssl" mkdir "nginx\ssl"
if not exist "nginx\ssl\server.crt" (
    echo [*] Generating self-signed TLS certificate...
    where openssl >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo [!] openssl not found in PATH. Install OpenSSL or provide certs manually.
        echo     Place server.crt and server.key in nginx\ssl\
        exit /b 1
    )
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 ^
        -keyout nginx\ssl\server.key -out nginx\ssl\server.crt ^
        -subj "/CN=localhost/O=RawrXD/C=US" 2>nul
    echo [+] Self-signed cert generated.
)

:: Build and deploy
echo [*] Building containers...
docker compose build --no-cache
if %ERRORLEVEL% neq 0 (
    echo [!] Build failed.
    exit /b 1
)

echo [*] Starting stack...
docker compose up -d
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to start.
    exit /b 1
)

echo.
echo ═══════════════════════════════════════════════
echo   Stack is up.  https://localhost
echo   Health check: curl -k https://localhost/health
echo ═══════════════════════════════════════════════
endlocal
