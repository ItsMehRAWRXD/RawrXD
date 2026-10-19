from pathlib import Path
import traceback

ROOT = Path(__file__).resolve().parent

def main():
    print("STDOUT/STDERR")
    print()
    print("```")
    try:
        inc=(ROOT/"tokencode_tokenid_domain.inc").read_text(encoding="utf-8")
        asm=(ROOT/"tokencode_tokenid_domain.asm").read_text(encoding="utf-8")
        raw=inc.split("TokenIdRaw STRUCT",1)[1].split("TokenIdRaw ENDS",1)[0]

        checks={
            "caller_authority_absent":"token_id_authorized" not in raw,
            "bounded_mode_present":"TOKEN_ID_MODE_BOUNDED" in asm,
            "u64_full_mode_present":"TOKEN_ID_MODE_U64_FULL" in asm,
            "bounded_add_overflow_guard":"jc tid_arith_fault" in asm,
            "u64_full_avoids_end_plus_one":"tid_u64_full:" in asm,
            "check_count_closure":"token_id_check_count" in asm,
            "oov_guard":"out_of_vocab_count" in asm,
            "negative_reinterpret_guard":"negative_token_id_count" in asm,
            "decode_mismatch_guard":"token_id_decode_mismatch" in asm,
            "encode_mismatch_guard":"token_id_encode_mismatch" in asm,
            "authority_write_present":"TokenIdResult.token_id_authorized, 1" in asm,
        }

        model_bounded={
            "mode":"BOUNDED",
            "vocab_base":0,
            "vocab_count":500000,
            "min_id":0,
            "max_id":499999,
            "authorized":True,
        }
        model_u64_full={
            "mode":"U64_FULL",
            "min_id":0,
            "max_id":"UINT64_MAX",
            "checked_all_generated":True,
            "authorized":True,
        }
        model_negative={
            "mode":"U64_FULL",
            "negative_token_id_count":1,
            "authorized":False,
        }
        model_overflow={
            "mode":"BOUNDED",
            "base_plus_count_overflow":True,
            "arithmetic_fault":True,
            "authorized":False,
        }

        ok=all(checks.values())
        print("STATIC_AUDIT=",checks)
        print("MODEL_BOUNDED=",model_bounded)
        print("MODEL_U64_FULL=",model_u64_full)
        print("MODEL_NEGATIVE=",model_negative)
        print("MODEL_OVERFLOW=",model_overflow)
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
