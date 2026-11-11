$ErrorActionPreference = 'Stop'

$link = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe'
$vcLib = 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64'
$umLib = 'C:\PROGRA~2\WI3CF2~1\10\Lib\10.0.22621.0\um\x64'
$ucrtLib = 'C:\PROGRA~2\WI3CF2~1\10\Lib\10.0.22621.0\ucrt\x64'
$root = 'd:\rawrxd-ci-bootstrap'

$args = @(
	'/NOLOGO', '/DLL', '/MACHINE:X64',
	"/DEF:$root\Sovereign_SDK.def",
	"/OUT:$root\Sovereign_SDK.patched.dll",
	"/IMPLIB:$root\Sovereign_SDK.patched.lib",
	"/LIBPATH:$vcLib",
	"/LIBPATH:$umLib",
	"/LIBPATH:$ucrtLib",
	"$root\Sunshine_Compositor.obj",
	"$root\GhostHUD.obj",
	"$root\GhostBuffer_Wrappers.obj",
	"$root\Simulation_Thread.obj",
	"$root\InputBridge.obj",
	"$root\BattleCoreTape.obj",
	"$root\Lockstep_Tape.obj",
	"$root\LockstepNet.obj",
	"$root\NetLockstep.obj",
	"$root\CRC64_StateHash.obj",
	"$root\DesyncRecovery.obj",
	"$root\SnapshotBuilder.obj",
	"$root\Sovereign_GGUF_Loader.obj",
	"$root\Sovereign_Load_Safe.obj",
	"$root\Sovereign_LoaderThread.obj",
	"$root\Sovereign_Symbolic_Validator.obj",
	"$root\masm_solo_compiler_dual.obj",
	"$root\titan_clean.obj",
	'kernel32.lib', 'user32.lib', 'gdi32.lib', 'ws2_32.lib',
	'winmm.lib', 'advapi32.lib', 'shell32.lib', 'ole32.lib', 'uuid.lib'
)

& $link @args
if ($LASTEXITCODE -ne 0) {
	throw "link failed with exit code $LASTEXITCODE"
}
