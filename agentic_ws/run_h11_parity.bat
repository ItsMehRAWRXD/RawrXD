@echo off
setlocal enabledelayedexpansion
set EXE=F:\rawrxd\_cert_clean3\bin\Release\deep2_prefill_parity.exe
set MODEL=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
set EV=F:\rawrxd\evidence
set FAILS=0

for %%K in (1 2 16 128) do (
    echo.
    echo ================= H11 PARITY k=%%K =================
    "%EXE%" --model "%MODEL%" --tokens %%K --role serial --dump "%EV%\serial_%%K.bin" > "%EV%\role_serial_%%K.log" 2>&1
    if errorlevel 1 (
        echo SERIAL_FAIL k=%%K
        type "%EV%\role_serial_%%K.log"
        set /a FAILS+=1
    ) else (
        "%EXE%" --model "%MODEL%" --tokens %%K --role batch --dump "%EV%\batch_%%K.bin" > "%EV%\role_batch_%%K.log" 2>&1
        if errorlevel 1 (
            echo BATCH_FAIL k=%%K
            type "%EV%\role_batch_%%K.log"
            set /a FAILS+=1
        ) else (
            "%EXE%" --compare "%EV%\serial_%%K.bin" "%EV%\batch_%%K.bin" --tokens %%K
            if errorlevel 1 set /a FAILS+=1
        )
    )
)

echo.
echo ================= H11 PARITY SUMMARY =================
echo FAILURES=!FAILS!
if "!FAILS!"=="0" (echo GATE_H11_P1_P4=PASS) else (echo GATE_H11_P1_P4=FAIL)
