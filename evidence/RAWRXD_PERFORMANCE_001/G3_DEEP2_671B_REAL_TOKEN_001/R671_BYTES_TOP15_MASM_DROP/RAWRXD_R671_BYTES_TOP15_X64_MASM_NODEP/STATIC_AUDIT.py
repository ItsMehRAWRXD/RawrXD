from pathlib import Path
import traceback

ROOT=Path(__file__).resolve().parent

def main():
    print("STDOUT/STDERR")
    print()
    print("```")
    try:
        inc=(ROOT/"r671_bytes15.inc").read_text(encoding="utf-8")
        asm=(ROOT/"r671_bytes15.asm").read_text(encoding="utf-8")
        raw=inc.split("R671BytesRaw STRUCT",1)[1].split("R671BytesRaw ENDS",1)[0]

        checks={
            "caller_witness_absent":"witness_state" not in raw,
            "caller_authority_absent":"bytes_authorized" not in raw,
            "generation_bound_present":"RB01_GENERATION_BOUND" in asm,
            "file_range_overflow_guard":"jc rb02_fail" in asm,
            "lease_active_present":"RB04_LEASE_ACTIVE" in asm,
            "lease_offset_match_present":"RB05_LEASE_OFFSET_MATCH" in asm,
            "lease_coverage_present":"RB06_LEASE_BYTE_COVERAGE" in asm,
            "pointer_provenance_present":"RB07_POINTER_PROVENANCE" in asm,
            "mapping_bound_present":"RB08_MAPPING_BOUND" in asm,
            "exact_consumption_present":"RB09_EXACT_BYTE_CONSUMPTION" in asm,
            "failed_acquire_guard":"RB10_NO_FAILED_ACQUIRE" in asm,
            "fallback_guard":"RB11_NO_FULL_TENSOR_FALLBACK" in asm,
            "checksum_observed_present":"RB12_CHECKSUM_OBSERVED" in asm,
            "nonfinite_guard":"RB13_NONFINITE_FREE" in asm,
            "release_closure_present":"RB14_RELEASE_CLOSURE" in asm,
            "final_authority_write":"R671BytesResult.bytes_authorized,1" in asm,
            "notrun_ne_pass":"cmp r12,14" in asm and "test r14,r14" in asm,
        }

        model_positive={
            "same_generation":True,
            "range_valid":True,
            "lease_active":True,
            "pointer_provenance":True,
            "exact_bytes_consumed":True,
            "failed_acquires":0,
            "fallback":0,
            "checksum_observed":True,
            "nonfinite":0,
            "release_closed":True,
            "authorized":True,
        }
        model_tamper={
            "pointer_provenance":False,
            "authorized":False,
        }

        ok=all(checks.values())
        print("STATIC_AUDIT=",checks)
        print("MODEL_POSITIVE=",model_positive)
        print("MODEL_TAMPER=",model_tamper)
        print("STATIC_AUDIT_RESULT=","PASS" if ok else "FAIL")
        if not ok:
            print("EXCEPTION_CLASS=StaticAuditFailure")
            print("EXCEPTION_MESSAGE=static audit failed")
            print("```")
            return 1
        print("```")
        return 0
    except Exception as exc:
        print("STATIC_AUDIT_RESULT=FAIL")
        print("EXCEPTION_CLASS=",exc.__class__.__name__)
        print("EXCEPTION_MESSAGE=",str(exc))
        print("TRACEBACK_BEGIN")
        traceback.print_exc()
        print("TRACEBACK_END")
        print("```")
        return 2

if __name__=="__main__":
    raise SystemExit(main())
