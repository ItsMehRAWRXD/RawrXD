# RAWRXD_NILW15_X64_MASM_NODEP

Pure x64 MASM source drop for 15 independent NILW runtime witnesses.

Goals:
- no third-party dependencies;
- fail closed;
- NOT_RUN != PASS;
- no witness self-promotes another;
- witness 15 only reports conjunction;
- scheduler authority untouched.

Build on x64 Native Tools Command Prompt:
    build_masm.bat

The harness intentionally starts with a zero/NOT_RUN witness and must emit:
    AUTHORIZED_PASS=0
