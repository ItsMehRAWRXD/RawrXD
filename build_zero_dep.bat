; Build Script  
set ASM_BIN=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe  
set modules=RawrXD_Titan_Master_GodSource Sovereign_PEB_Loader Sovereign_IPC Sovereign_Wire Sovereign_Watchdog Sovereign_Log Sovereign_Alpha Sovereign_Ticker Sovereign_GGUF  
cd /d d:\rawrxd\src  
for %%%%m in (%%modules%%) do ( %%ASM_BIN%% /c /Fo..\obj\%%%%m.obj %%%%m.asm )  
link.exe /OUT:..\Titan_Sovereign_Engine.exe /ENTRY:main /SUBSYSTEM:CONSOLE ..\obj\*.obj /NODEFAULTLIB ntdll.lib kernel32.lib 
