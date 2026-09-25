param([string]$RepoRoot = "F:\~dev\rawrxd")
$ErrorActionPreference = "Stop"
$src = Join-Path $RepoRoot "src\deep2\Deep2Engine_GpuForward.cpp"
if (!(Test-Path $src)) { throw "Source not found: $src" }

$text = [IO.File]::ReadAllText($src)
$original = $text
$marker = "RAWRXD_GPU_FINITE_PREFIX_DIAG_001"
if ($text.Contains($marker)) {
    Write-Host "$marker already present"
    exit 0
}

$ns = [regex]::Match($text, 'namespace Deep2 \{\r?\nnamespace \{\r?\n')
if (!$ns.Success) { throw "Anonymous namespace anchor not found" }

$helper = @'

// RAWRXD_GPU_FINITE_PREFIX_DIAG_001
struct GpuFiniteWitness {
    size_t finite = 0, nan = 0, inf = 0;
    size_t firstBad = static_cast<size_t>(-1);
    float minFinite = 0.0f, maxFinite = 0.0f;
};

static bool GpuFiniteTraceEnabled() {
    const char* s = std::getenv("DEEP2_GPU_FINITE_TRACE");
    return s && *s && std::strcmp(s, "0") != 0;
}

static long GpuTracePrefixHi() {
    const char* s = std::getenv("DEEP2_GPU_TRACE_PREFIX_HI");
    if (!s || !*s) return -1;
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    return (end == s || (end && *end) || v < 0) ? -1 : v;
}

static GpuFiniteWitness ScanGpuFiniteWitness(const float* p, size_t n) {
    GpuFiniteWitness w{};
    bool haveFinite = false;
    if (!p) return w;
    for (size_t i = 0; i < n; ++i) {
        const float v = p[i];
        if (std::isnan(v)) {
            ++w.nan;
            if (w.firstBad == static_cast<size_t>(-1)) w.firstBad = i;
        } else if (std::isinf(v)) {
            ++w.inf;
            if (w.firstBad == static_cast<size_t>(-1)) w.firstBad = i;
        } else {
            ++w.finite;
            if (!haveFinite) {
                w.minFinite = w.maxFinite = v;
                haveFinite = true;
            } else {
                if (v < w.minFinite) w.minFinite = v;
                if (v > w.maxFinite) w.maxFinite = v;
            }
        }
    }
    return w;
}

'@

$text = $text.Insert($ns.Index + $ns.Length, $helper)

$sig = "bool Deep2Engine::forwardGpuContiguousRange(unsigned slot, uint32_t lo, uint32_t hi,"
$start = $text.IndexOf($sig)
$finish = $text.IndexOf("bool Deep2Engine::forwardGpuMultiMap(", $start)
if ($start -lt 0 -or $finish -lt 0) { throw "Contiguous range function bounds not found" }

$pre = $text.Substring(0,$start)
$fn = $text.Substring($start,$finish-$start)
$post = $text.Substring($finish)

$h = "    const uint32_t H = (uint32_t)config.hiddenDim;"
$hi = $fn.IndexOf($h)
if ($hi -lt 0) { throw "H anchor not found" }
$nl = if ($fn.Contains("`r`n")) { "`r`n" } else { "`n" }

$insert = @'
    uint32_t execHi = hi;
    const long tracePrefix = GpuTracePrefixHi();
    if (tracePrefix >= 0) {
        const uint64_t req = static_cast<uint64_t>(tracePrefix);
        if (req >= static_cast<uint64_t>(lo) &&
            req < static_cast<uint64_t>(execHi))
            execHi = static_cast<uint32_t>(req);
        std::fprintf(stderr,
            "GPU_PREFIX_LIMIT slot=%u requested=%ld lo=%u hi=%u exec_hi=%u\n",
            slot, tracePrefix, lo, hi, execHi);
        std::fflush(stderr);
    }
'@ -replace "`r?`n",$nl

$fn = $fn.Insert($hi + $h.Length, $nl + $insert)

$oldLoop = "for (uint32_t L = lo; L <= hi; ++L)"
if (([regex]::Matches($fn,[regex]::Escape($oldLoop))).Count -ne 1) {
    throw "Unexpected contiguous layer-loop count"
}
$fn = $fn.Replace($oldLoop,"for (uint32_t L = lo; L <= execHi; ++L)")

$oldDl = "        if (!vc->DownloadHidden(hostOut, H)) return false;"
if (([regex]::Matches($fn,[regex]::Escape($oldDl))).Count -ne 1) {
    throw "Unexpected DownloadHidden count"
}
$newDl = @'
        if (!vc->DownloadHidden(hostOut, H)) return false;
        if (GpuFiniteTraceEnabled()) {
            const GpuFiniteWitness fw = ScanGpuFiniteWitness(hostOut, H);
            const long long firstBad =
                fw.firstBad == static_cast<size_t>(-1)
                    ? -1LL : static_cast<long long>(fw.firstBad);
            const size_t seq = kvCache ? kvCache->currentLength() : 0;
            std::fprintf(stderr,
                "GPU_FINITE_WITNESS slot=%u lo=%u hi=%u exec_hi=%u seq=%zu "
                "count=%u finite=%zu nan=%zu inf=%zu first_bad=%lld min=%g max=%g\n",
                slot, lo, hi, execHi, seq, H,
                fw.finite, fw.nan, fw.inf, firstBad,
                fw.minFinite, fw.maxFinite);
            std::fflush(stderr);
        }
'@ -replace "`r?`n",$nl
$fn = $fn.Replace($oldDl,$newDl.TrimEnd("`r","`n"))

$text = $pre + $fn + $post
foreach ($needle in @($marker,"DEEP2_GPU_FINITE_TRACE","DEEP2_GPU_TRACE_PREFIX_HI","GPU_FINITE_WITNESS","L <= execHi")) {
    if (!$text.Contains($needle)) { throw "Post-edit assertion failed: $needle" }
}

$bak = "$src.pre_gpu_finite_prefix_diag.bak"
if (!(Test-Path $bak)) { [IO.File]::WriteAllText($bak,$original) }
[IO.File]::WriteAllText($src,$text)
Write-Host "RAWRXD_GPU_FINITE_PREFIX_DIAG_001=APPLIED"
Write-Host "NORMAL_PATH_CHANGED_WHEN_ENV_UNSET=0"
