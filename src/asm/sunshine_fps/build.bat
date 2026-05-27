@echo off
:: Ensure these paths point to your VS2022 VC bin
set _ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set _CL="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set _LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

set INCLUDES=/I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\include"

%_CL% /c /nologo /O2 /GS- /Zl %INCLUDES% Sovereign_Ghost_Renderer.cpp
%_ML64% /c /nologo Sovereign_Entry.asm Sovereign_Engine.asm Sovereign_Licensing.asm Sovereign_Fabric_Scheduler.asm Sovereign_Compute_Kernel.asm Sovereign_Monitor.asm Sovereign_Math_HUD.asm Sovereign_PEB_Walk.asm Sovereign_Transmission.asm Sovereign_Inflection_Detector.asm Sovereign_Transmission_Intercept.asm Sovereign_Scheduler_Harden.asm Sovereign_Tick_Master.asm Sovereign_Ghost_Buffer.asm Sovereign_Input_Quantizer.asm Sovereign_Lockstep_Tape.asm Sovereign_Tape_SelfTest.asm Sovereign_HID_RawInput.asm Sovereign_HID_Pump.asm Sovereign_Prediction_Core.asm Sunshine_Compositor.asm
%_LINK% /NODEFAULTLIB /ENTRY:_start /SUBSYSTEM:CONSOLE /IGNORE:4210 /OUT:SunshineFPS.exe /MAP /MAP /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64" Sovereign_Entry.obj Sovereign_Engine.obj Sovereign_Licensing.obj Sovereign_Fabric_Scheduler.obj Sovereign_Compute_Kernel.obj Sovereign_Monitor.obj Sovereign_Math_HUD.obj Sovereign_PEB_Walk.obj Sovereign_Transmission.obj Sovereign_Inflection_Detector.obj Sovereign_Transmission_Intercept.obj Sovereign_Scheduler_Harden.obj Sovereign_Tick_Master.obj Sovereign_Ghost_Buffer.obj Sovereign_Input_Quantizer.obj Sovereign_Lockstep_Tape.obj Sovereign_Tape_SelfTest.obj Sovereign_HID_RawInput.obj Sovereign_HID_Pump.obj Sovereign_Prediction_Core.obj Sunshine_Compositor.obj Sovereign_Ghost_Renderer.obj kernel32.lib user32.lib opengl32.lib gdi32.lib

echo [SUCCESS] SunshineFPS.exe Built.
