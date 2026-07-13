# Phase F.5 Batch 3/5: Demo Video Script

## RawrXD Live Hotpatching Demo — 3 Minute Showcase

---

## Video Metadata

- **Title:** "RawrXD: Live Hotpatching in Action — 50% TPS Improvement Without Restarting"
- **Duration:** 3:00 (180 seconds)
- **Resolution:** 1920x1080 (1080p)
- **Format:** MP4 (H.264)
- **Target Platforms:** YouTube, Twitter/X, LinkedIn

---

## Scene Breakdown

### Scene 1: Introduction (0:00 - 0:20)

**Visual:**
- RawrXD logo animation
- Dark background with circuit traces
- Text overlay: "RawrXD"

**Audio (Voiceover):**
> "What if you could optimize your AI inference engine without stopping a single request?"

**On-screen text:**
- "Zero Downtime"
- "Live Hotpatching"
- "50% TPS Improvement"

---

### Scene 2: The Problem (0:20 - 0:45)

**Visual:**
- Split screen showing traditional deployment
- Terminal window with "service stopping..."
- Graph showing traffic drop to zero
- Timer counting: 30... 60... 90 seconds

**Audio (Voiceover):**
> "Traditional optimization means stopping your service, deploying new code, and restarting. That's 30 seconds to 5 minutes of downtime. And if something goes wrong? Another restart."

**On-screen text:**
- "Stop Service"
- "Deploy Code"
- "Restart"
- "Hope It Works"

**Visual transition:**
- Red X over each step
- "TOO RISKY" stamp

---

### Scene 3: The Solution (0:45 - 1:10)

**Visual:**
- RawrXD architecture diagram
- Animated arrows showing data flow
- Highlight: "Hotpatch Engine"
- Highlight: "Sovereign Governance"

**Audio (Voiceover):**
> "RawrXD takes a different approach. Our hotpatch engine compiles optimized kernels in milliseconds and applies them live — no restart required."

**On-screen text:**
- "2-5ms Deployment"
- "Atomic Switch"
- "Auto-Rollback"

**Animation:**
- Code compiling (progress bar: 2ms)
- Memory patch visualization
- Green checkmark

---

### Scene 4: Live Demo (1:10 - 2:20)

**Visual:**
- Terminal window (full screen)
- RawrXD starting up

**Terminal commands shown:**
```bash
$ ./RawrXD.exe --model phi-3-mini --enable-hotpatch
[RawrXD] Sovereign Runtime v1.0.0
[RawrXD] Loading model: phi-3-mini
[RawrXD] Hotpatch engine: ENABLED
[RawrXD] Telemetry: http://localhost:8081
[RawrXD] Ready. TPS: 40.2 tok/s
```

**Audio (Voiceover):**
> "Here's RawrXD running Phi-3 Mini. Baseline throughput: 40 tokens per second."

**Visual:**
- Dashboard appears (split screen)
- Real-time TPS graph (flat at 40)
- SIS score: 85.0

**Terminal (hotpatch trigger):**
```bash
[HOTPATCH] Opportunity detected: GEMM kernel optimization
[HOTPATCH] Compiling... 2.3ms
[HOTPATCH] Applying patch... 0.8ms
[HOTPATCH] Verifying... TPS: 58.7 ✓
[HOTPATCH] Patch committed. Rollback available.
```

**Visual:**
- TPS graph jumps: 40 → 58
- Animated arrow: +47%
- SIS score updates: 85 → 91
- Green pulse effect

**Audio (Voiceover):**
> "RawrXD detected an optimization opportunity, compiled a new kernel in 2.3 milliseconds, and hotpatched it live. Throughput jumped 47% — instantly."

**Visual:**
- Multiple hotpatches shown
- TPS graph climbing: 40 → 52 → 58 → 60
- Final TPS: 60.3
- Improvement badge: "+50%"

---

### Scene 5: Safety Features (2:20 - 2:45)

**Visual:**
- Split screen: Dashboard + Terminal
- Simulate degradation

**Terminal:**
```bash
[GOVERNANCE] TPS variance detected: 3.2σ
[GOVERNANCE] Triggering automatic rollback...
[HOTPATCH] Rolling back to v1.0.0... 1.2ms
[HOTPATCH] Rollback complete. TPS: 40.2
```

**Visual:**
- TPS graph dips then recovers
- Red warning icon → Green checkmark
- "Auto-Rollback" text appears

**Audio (Voiceover):**
> "What if a patch causes degradation? RawrXD's sovereign governance layer detects variance beyond three sigma and automatically rolls back — all in under 2 milliseconds."

**On-screen text:**
- "Welford-Adaptive 3-Sigma"
- "Automatic Rollback"
- "Zero Data Loss"

---

### Scene 6: Conclusion (2:45 - 3:00)

**Visual:**
- Summary screen with key metrics
- RawrXD logo
- GitHub URL

**On-screen text:**
```
RawrXD Results:
━━━━━━━━━━━━━━━━━━━━
Baseline:     40.2 TPS
Hotpatched:   60.3 TPS
Improvement:  +50%
Deployment:   2-5ms
Downtime:     0ms
━━━━━━━━━━━━━━━━━━━━
SIS Score:    89.4/100
SAI Index:    1.52x
━━━━━━━━━━━━━━━━━━━━
```

**Audio (Voiceover):**
> "RawrXD: The sovereign AI runtime that optimizes without stopping. Get started at github.com/ItsMehRAWRXD"

**Visual:**
- QR code appears
- Social media icons
- "Star us on GitHub" CTA

**Fade to black**

---

## Technical Requirements

### Recording Setup

**Software:**
- OBS Studio (screen recording)
- Audacity (audio editing)
- DaVinci Resolve (video editing)

**Hardware:**
- 1920x1080 display
- Microphone (voiceover)
- AMD RX 7800 XT (for demo)

### Terminal Styling

```bash
# Use Windows Terminal with:
# - Theme: Dark
# - Font: Cascadia Code Mono
# - Font size: 14
# - Background: #0d1117
# - Foreground: #c9d1d9
# - Accent: #58a6ff
```

### Dashboard Styling

- Use `telemetry/phase_g2/batch3_websocket_dashboard/dashboard_server.ps1`
- Dark theme (already configured)
- Refresh interval: 1 second for demo

---

## Recording Checklist

### Pre-Recording
- [ ] Close all unnecessary applications
- [ ] Set display resolution to 1920x1080
- [ ] Test microphone levels
- [ ] Prepare terminal commands (copy-paste ready)
- [ ] Start dashboard server
- [ ] Verify RawrXD binary works

### Recording
- [ ] Record intro sequence (logo animation)
- [ ] Record problem demonstration
- [ ] Record architecture diagram (static image OK)
- [ ] Record live demo (multiple takes allowed)
- [ ] Record safety features demo
- [ ] Record outro sequence

### Post-Production
- [ ] Sync audio with video
- [ ] Add background music (subtle)
- [ ] Add text overlays
- [ ] Add transitions between scenes
- [ ] Export at 1080p, 60fps
- [ ] Create thumbnail (1920x1080, text: "50% TPS + 0 Downtime")

---

## Alternative: Short Form (60 seconds)

For Twitter/X and TikTok, create a condensed version:

**0:00-0:10:** Hook — "40 TPS → 60 TPS in 3ms"
**0:10-0:30:** Demo — Show hotpatch happening
**0:30-0:50:** Results — Dashboard with metrics
**0:50-0:60:** CTA — GitHub URL

---

## Distribution Plan

### YouTube (Primary)
- Full 3-minute version
- SEO-optimized title and description
- Tags: AI, LLM, inference, optimization, hotpatching
- End screen with subscribe CTA

### Twitter/X
- 60-second condensed version
- GIF of TPS jump
- Link to full video

### LinkedIn
- 3-minute version with professional intro
- Focus on business value (uptime, cost savings)

### Reddit
- Link to YouTube
- r/MachineLearning, r/programming, r/rust

---

## Success Metrics

Track these after release:
- Views (target: 10,000 in first week)
- GitHub stars (target: +500 in first week)
- Comments/engagement
- Click-through rate to GitHub
