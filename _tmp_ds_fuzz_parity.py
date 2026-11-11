import subprocess, os, struct, random, sys

DIR = r"C:\Users\Garrett\AppData\Local\Temp\kilo\ds"
REF = r"F:\rawrxd\tmp_llama-cpp-cpu\llama-tokenize.exe"
MODEL = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
MG = os.path.join(DIR, "tok_parity_mg.exe")

SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
N = int(sys.argv[2]) if len(sys.argv) > 2 else 120
random.seed(SEED)

alphabet = (
    list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    + list("0123456789")
    + list(" \t\n")
    + list("  \t\n   \n\n  ")
    + list("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
    + list(".,;:!?-_/\\|@#$%^&*()[]{}<>+=~`'\"")
    + ["你好世界", "こんにちは", "한국어", "café", "naïve", "résumé", "😀🚀🎉",
       "??!!!", "αβγ", "日本語テキスト", "русский", "العربية", "ไทย", "۱۲۰۳", "１２３"]
    + ["\n\n", "\t\t", "   ", "    ", "  \t  ", "x", " ", "  "]
)


def rand_text():
    n = random.randint(1, 14)
    return "".join(random.choice(alphabet) for _ in range(n))


cases = [rand_text() for _ in range(N)]

with open(os.path.join(DIR, "ds_prompts.bin"), "wb") as o:
    o.write(struct.pack("<I", len(cases)))
    for it in cases:
        b = it.encode("utf-8")
        o.write(struct.pack("<I", len(b)))
        o.write(b)

r = subprocess.run([MG, DIR], capture_output=True)
nat = {}
for line in r.stdout.decode("utf-8", "replace").splitlines():
    if line.startswith("IDS "):
        parts = line.split()
        nat[int(parts[1])] = [int(x) for x in parts[2:]]

ok = 0
bad = 0
for i, c in enumerate(cases):
    rr = subprocess.run([REF, "-m", MODEL, "-p", c, "--ids", "--no-bos",
                         "--no-escape", "--log-disable"], capture_output=True)
    out = rr.stdout.decode("utf-8", "replace").strip()
    body = out[1:-1].strip()
    exp = [int(x) for x in body.split(",") if x.strip()]
    got = nat.get(i, [])
    if exp == got:
        ok += 1
    else:
        bad += 1
        if bad <= 12:
            print("DIFF | %r\n     | ref=%s\n     | nat=%s" % (c, exp, got))
print("fuzz seed=%d n=%d match=%d bad=%d" % (SEED, N, ok, bad))
