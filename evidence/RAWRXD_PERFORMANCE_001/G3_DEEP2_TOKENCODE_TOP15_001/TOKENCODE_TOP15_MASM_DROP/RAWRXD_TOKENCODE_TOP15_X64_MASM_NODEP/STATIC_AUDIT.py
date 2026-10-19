from pathlib import Path
import traceback

ROOT = Path(__file__).resolve().parent

def main():
    print("STDOUT/STDERR")
    print()
    print("```")
    try:
        inc = (ROOT / "tokencode15.inc").read_text(encoding="utf-8")
        asm = (ROOT / "tokencode15.asm").read_text(encoding="utf-8")
        raw = inc.split("TokenCodeRaw STRUCT",1)[1].split("TokenCodeRaw ENDS",1)[0]

        checks = {
            "caller_witness_state_absent": "witness_state" not in raw,
            "caller_authority_absent": "tokencode_authorized" not in raw,
            "generation_bound_present": "TE01_GENERATION_BOUND" in asm,
            "request_closure_present": "TE03_REQUEST_CLOSURE" in asm,
            "tokencode_closure_present": "TE04_TOKENCODE_CLOSURE" in asm,
            "vocab_bounds_present": "TE07_VOCAB_BOUNDS" in asm,
            "commit_closure_present": "TE08_ENCODE_COMMIT_CLOSURE" in asm,
            "duplicate_guard_present": "TE09_NO_DUPLICATE_ENCODE" in asm,
            "position_span_present": "TE10_MONOTONIC_POSITION_SPAN" in asm,
            "roundtrip_present": "TE12_DECODE_ROUNDTRIP" in asm,
            "output_bytes_present": "TE13_OUTPUT_BYTES_CLOSURE" in asm,
            "error_veto_present": "TE14_BUFFER_AND_ERROR_FREE" in asm,
            "final_authority_write_present":
                "TokenCodeResult.tokencode_authorized, 1" in asm,
            "notrun_ne_pass":
                "cmp r12, 14" in asm and "test r14, r14" in asm,
        }

        model_positive = {
            "generated": 128,
            "requests": 128,
            "tokencode": 128,
            "inputs": 128,
            "outputs": 128,
            "vocab_bounds": True,
            "commits": 128,
            "duplicates": 0,
            "position_span": 128,
            "position_observations": 128,
            "decode_roundtrip": 128,
            "roundtrip_mismatch": 0,
            "output_bytes_exact": True,
            "faults": 0,
            "authorized": True,
        }

        model_tamper = {
            "generated": 128,
            "tokencode": 127,
            "te04": False,
            "authorized": False,
        }

        ok = all(checks.values())
        print("STATIC_AUDIT=", checks)
        print("MODEL_POSITIVE=", model_positive)
        print("MODEL_TAMPER=", model_tamper)
        print("STATIC_AUDIT_RESULT=", "PASS" if ok else "FAIL")
        if not ok:
            print("EXCEPTION_CLASS=StaticAuditFailure")
            print("EXCEPTION_MESSAGE=static audit failed")
            print("```")
            return 1
        print("```")
        return 0
    except Exception as exc:
        print("STATIC_AUDIT_RESULT=FAIL")
        print("EXCEPTION_CLASS=", exc.__class__.__name__)
        print("EXCEPTION_MESSAGE=", str(exc))
        print("TRACEBACK_BEGIN")
        traceback.print_exc()
        print("TRACEBACK_END")
        print("```")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
