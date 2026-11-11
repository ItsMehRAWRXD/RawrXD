[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Executable,
    [int] $DurationSeconds = 60,
    [string] $CaptureFile = $(Join-Path (Get-Location) 'native_ghosttext_capture.txt')
)

$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Executable).Path
$workDir = Split-Path -Parent $exe
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $hash = ([BitConverter]::ToString(
        $sha256.ComputeHash([System.IO.File]::ReadAllBytes($exe)))).Replace('-', '')
} finally {
    $sha256.Dispose()
}

Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class RawrXdCaptureNative {
    public delegate bool EnumWindowProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")] public static extern bool EnumChildWindows(
        IntPtr parent, EnumWindowProc callback, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int
        GetWindowText(IntPtr hwnd, StringBuilder text, int capacity);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Ansi)] public static extern int
        GetClassName(IntPtr hwnd, StringBuilder text, int capacity);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(
        IntPtr hwnd, out uint processId);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool CloseWindow(IntPtr hwnd);

    public static string Text(IntPtr hwnd) {
        int length = GetWindowTextLength(hwnd);
        var buffer = new StringBuilder(Math.Max(256, length + 1));
        GetWindowText(hwnd, buffer, buffer.Capacity);
        return buffer.ToString();
    }

    public static string ClassName(IntPtr hwnd) {
        var buffer = new StringBuilder(128);
        GetClassName(hwnd, buffer, buffer.Capacity);
        return buffer.ToString();
    }

    public static IntPtr FindChild(IntPtr root, int controlId, string className) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(root, (hwnd, ignored) => {
            if (GetDlgCtrlID(hwnd) == controlId &&
                (String.IsNullOrEmpty(className) || ClassName(hwnd) == className)) {
                found = hwnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@

function Write-Receipt([string] $line) {
    Add-Content -LiteralPath $CaptureFile -Value ("[{0}] {1}" -f (Get-Date).ToString('o'), $line)
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $CaptureFile) | Out-Null
Set-Content -LiteralPath $CaptureFile -Value @(
    '# RawrXD native GhostText debug capture'
    "EXECUTABLE=$exe"
    "SHA256=$hash"
    "DURATION_SECONDS=$DurationSeconds"
    'DEBUG_CONTROL_ID=1014'
    'EDITOR_CONTROL_ID=1001'
)

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.WorkingDirectory = $workDir
$psi.UseShellExecute = $false
$psi.EnvironmentVariables['RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS'] = '5000'
$psi.EnvironmentVariables['RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS'] = '50'
$process = [System.Diagnostics.Process]::Start($psi)
Write-Receipt ("PROCESS_STARTED PID={0}" -f $process.Id)

$debugHwnd = [IntPtr]::Zero
$editorHwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds([Math]::Max(1, $DurationSeconds))
try {
    while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
        $process.Refresh()
        $main = $process.MainWindowHandle
        if ($main -ne [IntPtr]::Zero) {
            if ($debugHwnd -eq [IntPtr]::Zero -or
                -not [RawrXdCaptureNative]::IsWindow($debugHwnd)) {
                $debugHwnd = [RawrXdCaptureNative]::FindChild($main, 1014, 'RICHEDIT50W')
                if ($debugHwnd -eq [IntPtr]::Zero) {
                    $debugHwnd = [RawrXdCaptureNative]::FindChild($main, 1014, 'RichEdit20A')
                }
                if ($debugHwnd -ne [IntPtr]::Zero) {
                    Write-Receipt ("DEBUG_HWND=0x{0} CLASS={1}" -f $debugHwnd.ToInt64().ToString('X'), [RawrXdCaptureNative]::ClassName($debugHwnd))
                }
            }
            if ($editorHwnd -eq [IntPtr]::Zero -or
                -not [RawrXdCaptureNative]::IsWindow($editorHwnd)) {
                $editorHwnd = [RawrXdCaptureNative]::FindChild($main, 1001, 'RichEdit20A')
                if ($editorHwnd -ne [IntPtr]::Zero) {
                    Write-Receipt ("EDITOR_HWND=0x{0} CLASS={1}" -f $editorHwnd.ToInt64().ToString('X'), [RawrXdCaptureNative]::ClassName($editorHwnd))
                }
            }
            if ($debugHwnd -ne [IntPtr]::Zero) {
                $text = [RawrXdCaptureNative]::Text($debugHwnd)
                if ($text -match 'GHOSTTEXT_') {
                    Set-Content -LiteralPath ($CaptureFile + '.debug.latest') -Value $text
                    Write-Receipt ("DEBUG_TEXT_BYTES={0}" -f $text.Length)
                }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    if ($process.HasExited) {
        Write-Receipt ("PROCESS_EXITED EXIT_CODE={0}" -f $process.ExitCode)
    } else {
        Write-Receipt 'CAPTURE_WINDOW_ENDED=1'
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) {
            $null = $process.CloseMainWindow()
            Write-Receipt 'NORMAL_CLOSE_REQUESTED=1'
            if ($process.WaitForExit(10000)) {
                Write-Receipt ("PROCESS_EXITED_AFTER_CLOSE EXIT_CODE={0}" -f $process.ExitCode)
            } else {
                Write-Receipt 'PROCESS_CLEANUP=HELD_NO_FORCE_TERMINATION'
            }
        } else {
            Write-Receipt 'PROCESS_CLEANUP=HELD_NO_MAIN_WINDOW'
        }
    }
} finally {
    if (-not $process.HasExited) {
        Write-Receipt 'PROCESS_REMAINS=1; no force termination performed'
    }
}
