import subprocess, struct, os, sys

DIR = r"C:\Users\Garrett\AppData\Local\Temp\kilo\ds"
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DIR, "tok_parity.exe")
REF = r"F:\rawrxd\tmp_llama-cpp-cpu\llama-tokenize.exe"
MODEL = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"

prompts = [
    "Hello world",
    "The quick brown fox jumps over the lazy dog.",
    "def fibonacci(n): return n if n<2 else fibonacci(n-1)+fibonacci(n-2)",
    "Q: What is the capital of France? A: Paris",
    "translate to French: good morning",
    "In 2024, machine learning models grew to 70B parameters.",
    "I've been 'told he's there, 'RE you sure? 'M not sure I'll make it",
    "SELECT * FROM users WHERE id = 1;",
    "The temperature is -5 degrees Celsius.",
    "na\u00efve caf\u00e9 r\u00e9sum\u00e9",
    "emoji test \U0001F601 \U0001F680 done",
    "3.14159 and 2.71828",
    "C++ vs Python: which is faster?",
    "a b c d e f g",
    "don't stop believin'",
    "\u4f60\u597d\u4e16\u754c",
    "line1\nline2",
    "The meaning of life is",
]


def write_lp(path, items):
    with open(path, "wb") as o:
        o.write(struct.pack("<I", len(items)))
        for it in items:
            b = it.encode("utf-8")
            o.write(struct.pack("<I", len(b)))
            o.write(b)


def ref_ids(text):
    r = subprocess.run([REF, "-m", MODEL, "-p", text, "--ids", "--no-bos",
                        "--no-escape", "--log-disable"],
                       capture_output=True)
    out = r.stdout.decode("utf-8", "replace").strip()
    assert out.startswith("[") and out.endswith("]"), "ref parse %r" % out
    body = out[1:-1].strip()
    return [int(x) for x in body.split(",") if x.strip()]


def main():
    write_lp(os.path.join(DIR, "ds_prompts.bin"), prompts)
    # native ids
    r = subprocess.run([EXE, DIR + "\\"], capture_output=True)
    native = r.stdout.decode("utf-8", "replace")
    nat = {}
    for line in native.splitlines():
        if line.startswith("IDS "):
            parts = line.split()
            n = int(parts[1])
            ids = [int(x) for x in parts[2:]]
            nat[n] = ids

    match = 0
    diffs = []
    for i, p in enumerate(prompts):
        exp = ref_ids(p)
        got = nat.get(i, [])
        ok = exp == got
        if ok:
            match += 1
        else:
            diffs.append((p, exp, got))
        flag = "OK  " if ok else "DIFF"
        disp = p if (len(p) <= 40 and "\n" not in p) else p.encode("unicode_escape").decode()
        print("%s | %-42s ref=%s nat=%s" % (flag, disp, exp, got))

    print("\nSWEEP match=%d/%d" % (match, len(prompts)))
    if diffs:
        print("DIFFERENCES:")
        for p, e, g in diffs:
            print("  prompt=%r\n    ref=%s\n    nat=%s" %
                  (p.encode("unicode_escape").decode(), e, g))
    else:
        print("EXACT_REFERENCE_TOKEN_PARITY=PASS")


if __name__ == "__main__":
    main()
