#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignCryptoWrapper.ps1 - AES-256-GCM encryption for beacon payloads

.DESCRIPTION
    Wraps telemetry string elements inside AES-256-GCM encrypted handshake
    format before translating to hex. Provides authenticated encryption
    with associated data (AEAD) for covert channel signaling.

.NOTES
    Version: 1.0.0
    Requires: PowerShell 7.2+ (.NET 5+ for AesGcm)
#>

[CmdletBinding()]
param (
    [string]$KeyFilePath = "",
    [switch]$GenerateKey,
    [switch]$TestRoundtrip
)

$ErrorActionPreference = "SilentlyContinue"

# ============================================================================
# Key Management
# ============================================================================
function Get-SovereignCryptoKey {
    param ([string]$KeyFile)

    if ([string]::IsNullOrEmpty($KeyFile)) {
        $KeyFile = Join-Path $PSScriptRoot ".sovereign_key.bin"
    }

    if (Test-Path $KeyFile) {
        $KeyBytes = [System.IO.File]::ReadAllBytes($KeyFile)
        if ($KeyBytes.Length -eq 32) {
            return $KeyBytes
        }
        Write-Output "[CRYPTO] Invalid key length ($($KeyBytes.Length)), regenerating..."
    }

    # Generate new 256-bit key
    $NewKey = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($NewKey)
    [System.IO.File]::WriteAllBytes($KeyFile, $NewKey)
    Write-Output "[CRYPTO] New AES-256 key generated and saved to: $KeyFile"
    return $NewKey
}

function New-SovereignCryptoKey {
    param ([string]$KeyFile)

    if ([string]::IsNullOrEmpty($KeyFile)) {
        $KeyFile = Join-Path $PSScriptRoot ".sovereign_key.bin"
    }

    $NewKey = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($NewKey)
    [System.IO.File]::WriteAllBytes($KeyFile, $NewKey)
    Write-Output "[CRYPTO] New AES-256 key generated: $KeyFile"
    return $NewKey
}

# ============================================================================
# AES-256-GCM Encryption
# ============================================================================
function Protect-SovereignPayload {
    param (
        [Parameter(Mandatory=$true)]
        [byte[]]$PlaintextBytes,

        [Parameter(Mandatory=$true)]
        [byte[]]$Key,

        [byte[]]$AssociatedData = $null
    )

    # Generate random 96-bit nonce
    $Nonce = New-Object byte[] 12
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($Nonce)

    # Tag buffer for GCM authentication
    $Tag = New-Object byte[] 16

    # Ciphertext buffer
    $Ciphertext = New-Object byte[] $PlaintextBytes.Length

    try {
        $AesGcm = [System.Security.Cryptography.AesGcm]::new($Key)
        $AesGcm.Encrypt($Nonce, $PlaintextBytes, $Ciphertext, $Tag, $AssociatedData)
        $AesGcm.Dispose()

        # Output format: NONCE (12) + TAG (16) + CIPHERTEXT (N)
        $Output = New-Object byte[] ($Nonce.Length + $Tag.Length + $Ciphertext.Length)
        [Array]::Copy($Nonce, 0, $Output, 0, 12)
        [Array]::Copy($Tag, 0, $Output, 12, 16)
        [Array]::Copy($Ciphertext, 0, $Output, 28, $Ciphertext.Length)

        return $Output
    } catch {
        Write-Output "[CRYPTO] Encryption failed: $_"
        return $null
    }
}

# ============================================================================
# AES-256-GCM Decryption
# ============================================================================
function Unprotect-SovereignPayload {
    param (
        [Parameter(Mandatory=$true)]
        [byte[]]$EncryptedBytes,

        [Parameter(Mandatory=$true)]
        [byte[]]$Key,

        [byte[]]$AssociatedData = $null
    )

    if ($EncryptedBytes.Length -lt 28) {
        Write-Output "[CRYPTO] Encrypted data too short (need 28+ bytes)"
        return $null
    }

    # Extract components
    $Nonce = New-Object byte[] 12
    $Tag = New-Object byte[] 16
    $Ciphertext = New-Object byte[] ($EncryptedBytes.Length - 28)

    [Array]::Copy($EncryptedBytes, 0, $Nonce, 0, 12)
    [Array]::Copy($EncryptedBytes, 12, $Tag, 0, 16)
    [Array]::Copy($EncryptedBytes, 28, $Ciphertext, 0, $Ciphertext.Length)

    $Plaintext = New-Object byte[] $Ciphertext.Length

    try {
        $AesGcm = [System.Security.Cryptography.AesGcm]::new($Key)
        $AesGcm.Decrypt($Nonce, $Ciphertext, $Tag, $Plaintext, $AssociatedData)
        $AesGcm.Dispose()
        return $Plaintext
    } catch {
        Write-Output "[CRYPTO] Decryption failed (tampered or wrong key): $_"
        return $null
    }
}

# ============================================================================
# High-level string encrypt/decrypt helpers
# ============================================================================
function Protect-SovereignString {
    param (
        [string]$Plaintext,
        [byte[]]$Key,
        [string]$AssociatedDataString = ""
    )
    $PlainBytes = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
    $AadBytes = if ($AssociatedDataString) { [System.Text.Encoding]::UTF8.GetBytes($AssociatedDataString) } else { $null }
    $Encrypted = Protect-SovereignPayload -PlaintextBytes $PlainBytes -Key $Key -AssociatedData $AadBytes
    if ($Encrypted) {
        return [System.BitConverter]::ToString($Encrypted).Replace("-", "").ToLower()
    }
    return $null
}

function Unprotect-SovereignString {
    param (
        [string]$HexCiphertext,
        [byte[]]$Key,
        [string]$AssociatedDataString = ""
    )
    $EncryptedBytes = for ($i = 0; $i -lt $HexCiphertext.Length; $i += 2) {
        [Convert]::ToByte($HexCiphertext.Substring($i, 2), 16)
    }
    $AadBytes = if ($AssociatedDataString) { [System.Text.Encoding]::UTF8.GetBytes($AssociatedDataString) } else { $null }
    $Decrypted = Unprotect-SovereignPayload -EncryptedBytes $EncryptedBytes -Key $Key -AssociatedData $AadBytes
    if ($Decrypted) {
        return [System.Text.Encoding]::UTF8.GetString($Decrypted)
    }
    return $null
}

# ============================================================================
# Main / Test
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    if ($GenerateKey) {
        New-SovereignCryptoKey -KeyFile $KeyFilePath
        exit 0
    }

    if ($TestRoundtrip) {
        Write-Output "[CRYPTO] === AES-256-GCM Roundtrip Test ==="

        $Key = Get-SovereignCryptoKey -KeyFile $KeyFilePath
        $TestMessage = '{"status":"GREEN","cpu":"42","node":"test"}'
        $Aad = "sovereign-beacon-v1"

        Write-Output "[CRYPTO] Original: $TestMessage"

        $EncryptedHex = Protect-SovereignString -Plaintext $TestMessage -Key $Key -AssociatedDataString $Aad
        Write-Output "[CRYPTO] Encrypted hex: $EncryptedHex"

        $Decrypted = Unprotect-SovereignString -HexCiphertext $EncryptedHex -Key $Key -AssociatedDataString $Aad
        Write-Output "[CRYPTO] Decrypted: $Decrypted"

        if ($Decrypted -eq $TestMessage) {
            Write-Output "[CRYPTO] ROUNDTRIP PASSED"
        } else {
            Write-Output "[CRYPTO] ROUNDTRIP FAILED"
        }

        # Tamper test
        $Tampered = $EncryptedHex.Substring(0, $EncryptedHex.Length - 2) + "ff"
        $TamperResult = Unprotect-SovereignString -HexCiphertext $Tampered -Key $Key -AssociatedDataString $Aad
        if ($null -eq $TamperResult) {
            Write-Output "[CRYPTO] Tamper detection PASSED"
        }
    }
}
