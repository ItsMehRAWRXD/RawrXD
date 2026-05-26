# Sovereign_Padder.ps1 - Ensures tensor.bin is 2MB aligned
param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

$targetAlignment = 2MB

if (-Not (Test-Path $FilePath)) {
    Write-Host "[INFO] File $FilePath does not exist. Creating a dummy 2MB aligned file..."
    $dummySize = $targetAlignment * 352 # 704 MB
    $fs = [System.IO.File]::Create($FilePath)
    $buffer = [byte[]]::new($targetAlignment) # write 2MB at a time
    for ($i = 0; $i -lt 352; $i++) {
        $fs.Write($buffer, 0, $targetAlignment)
    }
    $fs.Close()
    Write-Host "[SUCCESS] Created dummy tensor file at $FilePath."
    exit 0
}

$file = Get-Item $FilePath
$currentSize = $file.Length
$remainder = $currentSize % $targetAlignment

if ($remainder -eq 0) {
    Write-Host "[SUCCESS] File is already 2MB aligned: ($currentSize / 1MB) MB."
} else {
    $paddingNeeded = $targetAlignment - $remainder
    Write-Host "[INFO] Alignment violation detected. Current: $currentSize bytes."
    Write-Host "[INFO] Applying $paddingNeeded bytes of zero-padding..."

    try {
        $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
        $paddingBuffer = [byte[]]::new($paddingNeeded)
        $fs.Write($paddingBuffer, 0, $paddingNeeded)
        $fs.Close()

        # Verification
        $newSize = (Get-Item $FilePath).Length
        if ($newSize % $targetAlignment -eq 0) {
            Write-Host "[SUCCESS] Padding applied. New size: ($newSize / 1MB) MB."
        } else {
            throw "[FATAL] Padding failed. Size remains non-compliant."
        }
    } catch {
        Write-Error "[FATAL] I/O Error: $($_.Exception.Message)"
        exit 1
    }
}
