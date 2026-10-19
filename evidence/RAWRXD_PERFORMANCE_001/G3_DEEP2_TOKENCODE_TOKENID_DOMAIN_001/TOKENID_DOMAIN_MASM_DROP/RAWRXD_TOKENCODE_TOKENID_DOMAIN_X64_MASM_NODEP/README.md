# RAWRXD_TOKENCODE_TOKENID_DOMAIN_X64_MASM_NODEP

Pure x64 MASM source drop replacing the old finite vocabulary-range assumption.

The token-ID domain is now explicit:

- `TOKEN_ID_MODE_BOUNDED` for a real finite vocabulary/range.
- `TOKEN_ID_MODE_U64_FULL` for the complete unsigned 64-bit token-ID storage
  domain without overflow-prone `UINT64_MAX + 1` arithmetic.

This does not turn validation off. Both modes require complete per-generation
ID checks, zero OOV evidence, zero signed-negative reinterpretation, and exact
encode/decode ID agreement.

Native Windows build:

    build_masm.bat

Expected:

    TOKENCODE_TOKENID_DOMAIN_X64_MASM_TESTS=PASS
