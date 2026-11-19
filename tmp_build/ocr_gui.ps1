param([string]$OutPath = "F:\rawrxd\build_ninja\gui_ocr.txt")

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WRect {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
    [StructLayout(LayoutKind.Sequential)] public struct R { public int L, T, Rr, B; }
}
"@

# find the GUI window
$gui = Get-Process -Name "RawrXD-Win32IDE-Native" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $gui) { Write-Output "GUI_NOT_RUNNING"; exit 1 }
$hwnd = $gui.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { Write-Output "NO_MAIN_WINDOW"; exit 1 }

[WRect]::ShowWindow($hwnd, 9) | Out-Null
[WRect]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 800

$r = New-Object WRect+R
[WRect]::GetWindowRect($hwnd, [ref]$r) | Out-Null
$w = $r.Rr - $r.L; $h = $r.B - $r.T
Write-Output "Window ${w}x${h} at $($r.L),$($r.T)"

$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
$png = "F:\rawrxd\build_ninja\gui_full.png"
$bmp.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()

# crop bottom dock (last 260 px)
$cookH = [Math]::Min(260, $h)
$crop = New-Object System.Drawing.Bitmap $w, $cookH
$g2 = [System.Drawing.Graphics]::FromImage($crop)
$g2.DrawImage($bmp, (New-Object System.Drawing.Rectangle 0,0,$w,$cookH), (New-Object System.Drawing.Rectangle 0,($h-$cookH),$w,$cookH), [System.Drawing.GraphicsUnit]::Pixel)
$pngBottom = "F:\rawrxd\build_ninja\gui_bottom.png"
$crop.Save($pngBottom, [System.Drawing.Imaging.ImageFormat]::Png)
$g2.Dispose(); $crop.Dispose(); $bmp.Dispose()

Write-Output "SAVED: $png"
Write-Output "SAVED: $pngBottom"

# OCR via Windows.Media.Ocr
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    function Await($op, $type) {
        $t = $asTaskGeneric.MakeGenericMethod($type).Invoke($null, @($op))
        $t.Wait(-1) | Out-Null
        $t.Result
    }
    [Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime] | Out-Null
    [Windows.Media.Ocr.OcrEngine,Windows.Media.Ocr,ContentType=WindowsRuntime] | Out-Null
    [Windows.Graphics.Imaging.BitmapDecoder,Windows.Graphics.Imaging,ContentType=WindowsRuntime] | Out-Null
    [Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime] | Out-Null

    $file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($pngBottom)) ([Windows.Storage.StorageFile])
    $stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    if ($null -eq $engine) { Write-Output "OCR_ENGINE_NULL" }
    else {
        $result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
        $lines = $result.Lines | ForEach-Object { $_.Text }
        $lines | ForEach-Object { Write-Output "OCR> $_" }
        $lines -join "`n" | Set-Content -Path $OutPath -Encoding UTF8
    }
} catch {
    Write-Output "OCR_FAILED: $($_.Exception.Message)"
}