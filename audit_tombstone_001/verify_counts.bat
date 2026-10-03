@echo off
echo === STUB marker count ===
rg -c "^// STUB:" "F:\~dev\rawrxd\src\deep2\Deep2Server_Sovereign.cpp"
echo STUB_EXIT=%errorlevel%
echo.
echo === Non-comment lines ===
rg -n -v "^\s*(//.*)?$" "F:\~dev\rawrxd\src\deep2\Deep2Server_Sovereign.cpp"
echo CODE_EXIT=%errorlevel%
echo.
echo === Deep2Server_Sovereign in CMakeLists (comments only check) ===
rg -n "Deep2Server_Sovereign" "F:\~dev\rawrxd\CMakeLists.txt" | findstr /R "^\d*:[^#]*Deep2Server_Sovereign"
echo NON_COMMENT_CMAKE_EXIT=%errorlevel%
echo.
echo === InferenceWire.cpp definition ===
rg -n "WireRecordDispatch" "F:\~dev\rawrxd\src\deep2\InferenceWire.cpp"
echo.
echo === InferenceWire.cpp in CMakeLists.txt? ===
rg -n "InferenceWire" "F:\~dev\rawrxd\CMakeLists.txt"
echo INFERENCE_WIRE_IN_CMAKE_EXIT=%errorlevel%
