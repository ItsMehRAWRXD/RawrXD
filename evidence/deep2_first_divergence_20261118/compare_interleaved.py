import runpy, sys

source = open(r"F:\rawrxd\evidence\qwen38_27b_cpu_ref_20261118\compare_qwen38_v2.py",
              encoding="utf-8").read()
source = source.replace(
    r'DEEP2_DIR = os.path.join(EV, "deep2")',
    r'DEEP2_DIR = r"F:\rawrxd\evidence\deep2_first_divergence_20261118\deep2_after_interleaved"')
sys.argv = ["compare_qwen38_v2.py", sys.argv[1] if len(sys.argv) > 1 else "0"]
exec(compile(source, "compare_qwen38_v2_interleaved.py", "exec"),
     {"__name__": "__main__"})
