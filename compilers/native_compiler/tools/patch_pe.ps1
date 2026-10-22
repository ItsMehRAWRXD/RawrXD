param([string]$Path, [string]$Patch)
# Patches a PE file in place to test loader-rejection hypotheses.
# Usage: patch_pe.ps1 <file> <patch>
#   nodiscard : clear IMAGE_SCN_MEM_DISCARDABLE on every section
#   gui       : set the subsystem to Windows GUI
#   noreloc   : clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
#   noexport  : zero the export data directory
#   dump      : print the relevant header fields
$bytes = [System.IO.File]::ReadAllBytes($Path)
$e_lfanew = [BitConverter]::ToUInt32($bytes, 60)
$coff = $e_lfanew + 4
$numSec = [BitConverter]::ToUInt16($bytes, $coff + 2)
$optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
$opt = $coff + 20
$secTab = $opt + $optSize

switch ($Patch) {
    "nodiscard" {
        for ($i = 0; $i -lt $numSec; $i++) {
            $s = $secTab + ($i * 40)
            $ch = [BitConverter]::ToUInt32($bytes, $s + 36)
            $ch = $ch -band (-bnot 0x02000000)
            [BitConverter]::GetBytes([uint32]$ch).CopyTo($bytes, $s + 36)
            $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
            Write-Host ("  {0}: chars 0x{1:X8}" -f $name, $ch)
        }
    }
    "gui" {
        [BitConverter]::GetBytes([uint16]2).CopyTo($bytes, $opt + 68)
        Write-Host "  subsystem = 2"
    }
    "noreloc" {
        $dc = [BitConverter]::ToUInt16($bytes, $opt + 70)
        $dc = $dc -band (-bnot 0x40)
        [BitConverter]::GetBytes([uint16]$dc).CopyTo($bytes, $opt + 70)
        Write-Host ("  dll characteristics = 0x{0:X4}" -f $dc)
    }
    "noexport" {
        [BitConverter]::GetBytes([uint32]0).CopyTo($bytes, $opt + 112)
        [BitConverter]::GetBytes([uint32]0).CopyTo($bytes, $opt + 116)
        Write-Host "  export data directory zeroed"
    }
    "dump" {
        Write-Host ("  subsystem={0} dllchars=0x{1:X4}" -f [BitConverter]::ToUInt16($bytes, $opt+68), [BitConverter]::ToUInt16($bytes, $opt+70))
        for ($i = 0; $i -lt $numSec; $i++) {
            $s = $secTab + ($i * 40)
            $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
            $ch = [BitConverter]::ToUInt32($bytes, $s + 36)
            Write-Host ("  {0,-10} VA=0x{1:X8} VS=0x{2:X8} RawPtr=0x{3:X8} RawSz=0x{4:X8} chars=0x{5:X8}" -f `
                $name, [BitConverter]::ToUInt32($bytes,$s+12), [BitConverter]::ToUInt32($bytes,$s+8), `
                [BitConverter]::ToUInt32($bytes,$s+20), [BitConverter]::ToUInt32($bytes,$s+16), $ch)
        }
    }
}
[System.IO.File]::WriteAllBytes($Path, $bytes)
