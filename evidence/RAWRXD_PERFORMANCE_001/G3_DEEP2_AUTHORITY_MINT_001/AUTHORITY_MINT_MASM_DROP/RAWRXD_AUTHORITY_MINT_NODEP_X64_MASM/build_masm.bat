@echo off
setlocal

ml64 /nologo /c /FoAuthorityBootstrap.obj AuthorityBootstrap.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /FoAuthorityMint.obj AuthorityMint.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /FoAuthorityObserveRevoke.obj AuthorityObserveRevoke.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /FoAuthorityContractTest.obj AuthorityContractTest.asm
if errorlevel 1 exit /b %errorlevel%
ml64 /nologo /c /Foharness.obj harness.asm
if errorlevel 1 exit /b %errorlevel%

link /nologo /subsystem:console /entry:main ^
  harness.obj AuthorityBootstrap.obj AuthorityMint.obj AuthorityObserveRevoke.obj AuthorityContractTest.obj ^
  kernel32.lib /out:authority_mint_contract.exe
if errorlevel 1 exit /b %errorlevel%

authority_mint_contract.exe
set RC=%ERRORLEVEL%
echo AUTHORITY_CONTRACT_FAILMASK=%RC%
if not "%RC%"=="0" exit /b %RC%
echo AUTHORITY_MINT_NODEP_X64_MASM_TESTS=PASS
echo PROMOTE=0
exit /b 0
