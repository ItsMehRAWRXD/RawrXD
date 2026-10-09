Acceptance certificates
=======================

Each certificate in this tree is a durable receipt from a *finished* process:
the harness writes it, flushes and closes the file before it exits, and the
fields are then re-validated independently.

Do not treat a process exit code, or text on stdout, as evidence. A truncated
or redirected stream must not be able to make a run look successful.

Run
---

    _build_parity.cmd            # builds RawrXDCore.dll + the parity harness

    set RAWRXD_CERTIFICATE_PATH=%CD%\CERT.cert
    tmp_build_mg\dll_parity.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf

Verify (after the producer has exited)
-------------------------------------

    py tools\verify_certificate.py CERT.cert

The verifier independently enforces:

  * the file exists and is non-empty
  * ``GATE`` matches the expected gate id
  * ``END_CERTIFICATE`` is present, so the producer was not killed mid-run
  * every required field is present and in an accepted state
  * ``CHECKS`` equals the number of field rows
  * ``PASSED`` / ``FAILED`` agree with the required fields
  * ``VERDICT`` is ``PASS`` and consistent with ``PASSED`` / ``FAILED``

Any violation exits non-zero.

Recorded gates
--------------

``RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001``
    ModelGenie promoted into the production runtime behind ``RawrXDCore.dll``:
    shared executor, bitwise standalone/DLL logit parity, 300/300 IR dispatch,
    persistent-KV autoregression, and the prompt-echo fallback removed.

    Note that this gate certifies *inference execution*, not output quality.
    Coherent text generation is **not** asserted here; see ``RAWRXD_ATTN_Q_
    PROJECTION_AUTHORITY_001`` and the tokenizer work before making that claim.
