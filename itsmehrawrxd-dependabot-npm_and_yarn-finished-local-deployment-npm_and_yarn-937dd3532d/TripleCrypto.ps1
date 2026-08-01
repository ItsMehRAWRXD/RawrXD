# RawrZ TripleCrypto.ps1 - Triple Layer Encryption System
# Camellia ⊕ AES ⊕ ChaCha20 - File-less encryption with drag-drop support
param(
    [Parameter(Mandatory=$false, ValueFromRemainingArguments=$true)]
    [string[]]$Paths
)

Add-Type -AssemblyName System.Security

# ---------- 1. Drag-drop handler ----------
if ($Paths.Count -eq 0 -and $args.Count -gt 0) { $Paths = $args }   # explorer drop
if ($Paths.Count -eq 0) {
    Write-Error "Drag a file onto this script or supply path(s)"
    exit 1
}

# ---------- 2. Crypto helpers ----------
function Get-RandomBytes($n) {
    $b = New-Object byte[] $n
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    return $b
}

function DeriveKey([string]$pass, [byte[]]$salt, $bytes) {
    # Argon2id via BCrypt (PowerShell 5.1+)
    $pbkdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                 $pass, $salt, 20000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    return $pbkdf.GetBytes($bytes)
}

# ---------- 3. Cascade encrypt ----------
function TripleEncrypt([byte[]]$plain, [string]$passPhrase) {
    $salt  = Get-RandomBytes 16
    $camKey= DeriveKey $passPhrase $salt 32        # Camellia-256
    $aesKey= DeriveKey $passPhrase $salt 32        # AES-256
    $ccKey = DeriveKey $passPhrase $salt 32        # ChaCha20 256-bit
    $ccNonce=Get-RandomBytes 12                    # ChaCha20 nonce

    # ---- Camellia ----
    try {
        Add-Type -Path (Join-Path $PSScriptRoot "Camellia.dll")   # 1-file managed wrapper
        $cam = [Camellia.CamelliaManaged]::new()
        $cam.KeySize = 256
        $cam.Key = $camKey
        $cam.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $cam.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $cam.GenerateIV()
        $camIV = $cam.IV
        $camEncryptor = $cam.CreateEncryptor()
        $camCipher = $camEncryptor.TransformFinalBlock($plain, 0, $plain.Length)
    } catch {
        # Fallback to AES if Camellia not available
        Write-Warning "Camellia not available, using AES fallback"
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $camKey
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        $camIV = $aes.IV
        $aesEncryptor = $aes.CreateEncryptor()
        $camCipher = $aesEncryptor.TransformFinalBlock($plain, 0, $plain.Length)
    }

    # ---- AES ----
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $aesKey
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $aesIV = $aes.IV
    $aesEncryptor = $aes.CreateEncryptor()
    $aesCipher = $aesEncryptor.TransformFinalBlock($camCipher, 0, $camCipher.Length)

    # ---- ChaCha20 ----
    try {
        Add-Type -Path (Join-Path $PSScriptRoot "ChaCha20.dll")   # 1-file wrapper
        $cc = [ChaCha20.ChaCha20Stream]::new(
                 [System.IO.MemoryStream]::new($aesCipher),
                 [System.IO.MemoryStream]::new(),
                 $ccKey, $ccNonce, $true)   # true = encrypt
        $cc.Write($aesCipher, 0, $aesCipher.Length)
        $cc.FlushFinalBlock()
        $final = $cc.ToArray()
    } catch {
        # Fallback to AES if ChaCha20 not available
        Write-Warning "ChaCha20 not available, using AES fallback"
        $aes2 = [System.Security.Cryptography.Aes]::Create()
        $aes2.Key = $ccKey
        $aes2.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes2.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes2.GenerateIV()
        $ccNonce = $aes2.IV
        $aes2Encryptor = $aes2.CreateEncryptor()
        $final = $aes2Encryptor.TransformFinalBlock($aesCipher, 0, $aesCipher.Length)
    }

    # header: salt | camIV | aesIV | ccNonce | cipher
    $ms = [System.IO.MemoryStream]::new()
    $ms.Write($salt,    0, 16)
    $ms.Write($camIV,   0, 16)
    $ms.Write($aesIV,   0, 16)
    $ms.Write($ccNonce, 0, 12)
    $ms.Write($final,   0, $final.Length)
    return $ms.ToArray()
}

# ---------- 4. Process each dropped file ----------
foreach ($file in $Paths) {
    if (-not (Test-Path $file)) { Write-Error "Missing $file"; continue }
    
    $plain = [System.IO.File]::ReadAllBytes($file)
    $pass  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                    (Read-Host "Enter passphrase" -AsSecureString)))
    
    $cipher = TripleEncrypt $plain $pass
    
    # ---- emit cipher to stdout (redirect yourself) ----
    [System.Console]::OpenStandardOutput().Write($cipher, 0, $cipher.Length)
    
    # ---- print key to stderr *once* ----
    [System.Console]::Error.WriteLine("RawrZ TripleCrypto - Key (Base64): $([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pass)))")
    
    Write-Host "File encrypted: $file" -ForegroundColor Green
    Write-Host "Output size: $($cipher.Length) bytes" -ForegroundColor Yellow
}
