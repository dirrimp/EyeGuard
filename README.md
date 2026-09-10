# EyeGuard

A 24/7 accountability monitoring system for one person's **Mac and iPhone**, with
a private cloud layer that gives an accountability partner full, tamper-evident
visibility.

Unlike text- or URL-based accountability tools, EyeGuard analyzes the **actual
screen pixels** on the Mac and the **actual DNS traffic on the wire** from the
phone — so it sees content regardless of which app, browser, video, game, VPN, or
window it appears in. All detection runs **on-device / on-wire**; only flags, a
browsing trail, and small **encrypted** review images sync to the partner's
dashboard.

It is built around one specific situation: **the monitored person administers
their own devices** (full admin on the Mac, root SSH on the router) — so the
design goal is not to build an unbreakable cage, it's to make every possible
bypass *loud*.

> **Tamper-evident, not tamper-proof.** Anything that stops, blinds, or subverts
> monitoring — killing a process, revoking a permission, creating a second
> account, editing the deployed code, taking the phone off the tunnel — surfaces
> as an alert to the partner. Nothing in EyeGuard claims to be impossible to
> defeat; it claims that defeating it can't be done quietly.

---

## The trust model

Every serious weakness in a self-monitoring tool reduces to *the monitored user
also being the administrator*. EyeGuard resolves that by splitting the two roles:

| Role | Who | Holds |
|------|-----|-------|
| **Monitored** | the person being held accountable | admin on their own Mac, root SSH on the router — but **no backend logins** |
| **Partner / admin** | e.g. a parent or sponsor | the Supabase project, the Resend (email) account, and the GitHub repo that serves the dashboard and ships the code |

Consequences of that split, enforced (not conventional):

- **No secret key on the monitored Mac, ever.** The agent authenticates to the
  backend with the **public anon key** only, through Postgres RPCs that are
  individually safe to call (a server-stamped heartbeat has no timestamp
  parameter to forge, etc.). The `service_role` key lives only in the partner's
  Supabase console.
- **The deployed code is root-owned.** The monitored user can't edit
  `/Library/Application Support/EyeGuard` directly. To change anything they open
  a pull request; GitHub branch protection + a `CODEOWNERS` rule make the
  partner's review mandatory before it can merge.
- **Review images are end-to-end encrypted.** What lands in cloud storage is
  opaque ciphertext (AES-256-GCM under an RSA-OAEP-wrapped one-time key). The
  private key exists only on the partner's separate device — a Supabase breach or
  a leaked anon key exposes nothing viewable.

See `deploy/STATUS.md` for the as-built lockdown state and the accepted
residuals, and `deploy/WORKFLOW.md` for the propose → review → ship loop.

## Components

```
┌──────────────────────────── the Mac ────────────────────────────┐
│                                                                 │
│  ● main agent  (per-user menu-bar app / LaunchAgent)            │
│      screen capture (mss) → change filter                       │
│      NudeNet (fast NSFW)  +  CLIP zero-shot (head-to-head)      │  onnxruntime only —
│      context-risk grading (app / site / window → keep + grade)  │  no PyTorch, no
│      local log + live HTML report                               │  transformers at runtime
│      encrypted uploader (offline queue)  ·  heartbeat pulse     │
│                                                                 │
│  ● session_watcher  (root LaunchDaemon)                         │
│      cross-session checks a per-user process structurally can't:│
│      new local account · wrong console user · injected dylib ·  │
│      attached debugger  → same gone-dark-style alerts           │
│                                                                 │
│  ● deploy_watcher  (root LaunchDaemon)                          │
│      polls GitHub main, pulls + restarts on every merge         │
│      (the partner's PR approval is the only gate)               │
│                                                                 │
│  ● integrity check  (in the main agent)                         │
│      fetches a published file-hash manifest from Supabase and   │
│      flags any deployed *.py whose hash doesn't match           │
│                                                                 │
│  ● findmy_watcher  (cron)  — cross-checks the phone-dark signal │
│      against Apple Find My so ordinary iOS VPN suspension       │
│      doesn't false-fire                                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │  all HTTPS bound to the physical
                                │  interface (IP_BOUND_IF) so an
                                │  on-demand VPN tunnel can't sever
                                │  the accountability channel
┌──────────────────────── the router (GL.iNet Flint 2) ───────────┐
│  ● eyeguard-phone  — tcpdump on the phone's DNS off the wire →   │
│      green browsing trail / red explicit-domain hits;           │
│      phone-dark via WireGuard tunnel liveness (keepalive rx     │
│      counter), ARP reachability, and DNS activity OR-combined   │
│  ● router-watcher  (separate process) — router-config drift,    │
│      DoH / Tor bypass attempts, and eyeguard-phone's own hash   │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
┌──────────────────────────── Supabase ───────────────────────────┐
│  Postgres:  flags · device_status · phone_status ·              │
│             release_manifests                                   │
│  RLS → the two partner accounts can only READ                   │
│  private Storage bucket (encrypted review frames)               │
│  pg_cron: 7-day wipe · gone-dark / health cron checks           │
│  pg_net → Resend  ──  red / gone-dark / digest / context emails ─▶ 📧
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
                partner dashboard — static page on the partner's
                GitHub Pages · magic-link login · read-only
```

## Detection (the Mac)

- **NudeNet** (a trained nudity detector) runs first as a fast explicit-content
  pass — if it sees real exposure it flags 🔴 immediately, no second stage
  needed.
- **CLIP zero-shot** runs on everything else and scores each frame (and tiles)
  **head-to-head**: best explicit prompt vs. best suggestive prompt vs. best
  *safe* prompt, softmaxed against each other. A large set of "safe anchor"
  prompts (clothed people, animals, gameplay, UI, code, art, text posts) gives
  ordinary content a home so it isn't forced onto a body/nudity hub — this is
  what keeps false positives low.
- **Tiling** — each frame is also split into an overlapping grid so a small
  on-screen window isn't drowned out by the desktop around it. Tiles must clear a
  higher bar than the full frame since they're zoomed and noisier.
- **Context-risk layer** (rules, no AI) combines the score with *where* it
  happened: safe contexts (terminals, editors, EyeGuard's own report) are
  suppressed, risky ones (social media) are graded up.
- **OCR / signal layer** — explicit terms in a URL, search box, or window title
  are flagged even when there's no image to see.

Runs entirely on **onnxruntime**. The CLIP vision encoder is a pre-exported ONNX
model; image preprocessing is a vendored numpy reimplementation (validated
byte-for-byte against the reference) and the prompt embeddings are precomputed
into a committed asset — so `transformers` / `tokenizers` / PyTorch are **not in
the running process** at all. Resident footprint ≈ 560 MB.

## Detection (the iPhone)

The phone can't run a monitoring app (iOS sandbox + one-VPN limit, which the
WireGuard tunnel already uses), so the **router** does it by watching the phone's
DNS traffic directly off the wire with `tcpdump`. The router's firewall forces
plaintext DNS (DoT/DoH blocked), so every lookup — on home wifi or away on the
tunnel — crosses the router in the clear.

- 🟢 **browsing trail** — every meaningful domain, collapsed to app names,
  throttled to browsing-not-telemetry.
- 🔴 **explicit domain hit** — the phone querying a name on the explicit list.
- 📵 **phone went dark** — no phone traffic (home DNS, ARP reachability, *or*
  tunnel keepalive) for 60s. The WireGuard keepalive rx counter distinguishes
  "asleep" from "VPN off / phone off", and `findmy_watcher` on the Mac
  cross-checks against Apple Find My so an ordinary iOS background-suspension of
  the VPN doesn't fire a false alarm.
- 🚨 **router-config tamper-evidence** — AdGuard protection, the Block-DoT rule,
  WAN default-deny, SSH key-only auth, the WireGuard peer set, and more are
  re-checked every few minutes against the hardened baseline.
- 🔐 **DoH / 🧅 Tor bypass detection** — SYN-level watches for known DoH-provider
  and Tor-guard IPs, as backstops behind the firewall rules.

See `deploy/PHONE.md`.

## Tamper-evidence catalogue

Every item here produces an email to the partner:

| Signal | What it catches |
|--------|-----------------|
| ⚫ monitoring went dark | main agent stopped heartbeating for 3 min (killed, crashed, offline, Mac off) — sleep/DarkWake-aware so ordinary sleep doesn't fire it |
| ⚫ session watcher went dark | the root session/account watcher stopped reporting |
| 🚨 possible fake "asleep" signal | a clean-shutdown beacon was sent but the session watcher kept running afterward |
| 🚨 lost view of the screen | the agent is up but capture is returning black / frozen for 2+ min (Screen Recording revoked, display switched) — DRM-video playback is recognized and logged quietly instead |
| 🚨 detector may be broken | the agent is up and seeing the screen, but its live self-test is failing |
| 🚨 account / session / process anomaly | a new local user account, a wrong console user, an injected library, or an attached debugger |
| 🚨 code / config tampered | a deployed `*.py` hash doesn't match the published manifest |
| 🟡 new browser extension / VM software | a title-spoofer or a virtualization tool that could sidestep monitoring |
| 📵 phone went dark / 🔴 explicit domain / 🚨 router tampered / 🔐 DoH / 🧅 Tor | the phone/router signals above |
| 📡 context on an earlier gap | a follow-up once the Mac reconnects, saying whether a gone-dark gap looked like "no network at all" (benign) or "Supabase specifically blocked" (suspicious) |

## Cloud & partner layer

- **Supabase** — Postgres + Storage + Auth, owned by the partner. The agent only
  ever calls server-side RPCs with the public anon key; row-level security limits
  reads to the two pre-registered partner accounts; public signups are off. The
  dashboard can't edit or delete anything.
- **Dashboard** (`docs/index.html`) — a self-contained static page on the
  partner's GitHub Pages, magic-link login, read-only.
- **Email** — `pg_cron` + `pg_net` → Resend, from a dedicated sending subdomain.
- **Retention** — `pg_cron` wipes flag rows after 7 days; the agent wipes the
  cloud images and its local copies on the same schedule.
- **Releases** — every push to `main` that touches agent code triggers a GitHub
  Action that republishes the file-integrity manifest, and `deploy_watcher`
  pulls the change to the Mac within ~5 minutes.

## Repo layout

| Path | What |
|------|------|
| `eyeguard/` | the Mac agent — `capture`, `detector` (+ `clip_preprocess`, `clip_assets/`), `risk`, `context`, `logger`, `uploader`, `frame_crypto`, `net`, `menubar`, `retention`, `viewer`; the root daemons `session_watcher`, `deploy_watcher`; the tamper monitors `integrity`, `extensions`, `vm_monitor`; `findmy_watcher` |
| `router/` | `eyeguard-phone.py` (DNS wire capture), `eyeguard-router-watcher.py` (config/integrity), procd init scripts, config example |
| `supabase/*.sql` | schema, RLS lock, heartbeat + alert functions, the anon-client pivot, and every incremental alert-logic migration — run in the SQL Editor |
| `docs/index.html` | the partner dashboard (GitHub Pages) |
| `deploy/` | LaunchDaemon plists, `update.sh`, manifest publishers, `decrypt_frame.py`, and the current docs: `STATUS.md` (as-built + accepted residuals + open items), `WORKFLOW.md` (dev/deploy loop), `PHONE.md` (router monitoring), `RELEASE_CHECKLIST.md` |
| `tools/` | dev-only: `export_clip_onnx.py` (exports the CLIP vision encoder to ONNX), `build_text_features.py` (precomputes the prompt embeddings into `eyeguard/clip_assets/`) — both need `transformers`/`torch` and are run only when the model or prompt list changes |
| `config.yaml` | every threshold, prompt, context rule, retention window, and cloud setting |
| `models/` | the ONNX CLIP vision encoder (+ `clip_meta.json`); NudeNet's weights are pulled by its own package. Not committed — built with `tools/export_clip_onnx.py`, or shipped inside the packaged `.app` |
| `*.sh` | setup / build / install / pause scripts |

## Setup

Requires Python 3.12 (ML wheel availability).

```bash
./setup.sh            # create .venv and install runtime deps
                      # (models: build with tools/export_clip_onnx.py,
                      #  or use the packaged .app which bundles them)
./install_agent.sh    # run now + at every login, as a menu-bar app
```

Grant **Screen Recording** on first launch (System Settings → Privacy & Security →
Screen Recording). The menu-bar eye shows status: 🟢 watching · 🟡 recent
suggestive · 🔴 recent revealing · ⚠️ not watching. It relaunches if killed and
has no quit button (stop it with `./uninstall_agent.sh`, or the partner-held
pause password via `pause.sh`).

The root daemons (`session_watcher`, `deploy_watcher`), the router pieces, and the
cloud layer (Supabase project, Resend key, dashboard hosting, partner accounts,
device lockdown) are each set up separately — see `deploy/` and `router/`.

## Privacy & security

- **Detection is 100% local / on-wire.** Frames are analyzed in memory; the
  phone's traffic is classified on the router. Neither the raw screen nor raw
  packets leave the devices.
- **Only flags + a browsing trail + encrypted review images sync.** Review
  images are AES-256-GCM encrypted under a key only the partner's offline device
  can unwrap; RED frames are also blurred before encryption.
- **No secrets on the monitored Mac.** Public anon key only; every write is a
  server-validated RPC.
- **Partner data is read-only and account-locked** by row-level security.
- **Everything auto-deletes after 7 days**, on both devices and in the cloud.

## Status

| Area | State |
|------|-------|
| Mac detection core (capture, NudeNet + CLIP, tiling, context-risk, OCR) | ✅ running |
| Always-on (menu-bar agent + root session/deploy daemons, self-relaunching) | ✅ running |
| iPhone monitoring (router wire capture, phone-dark, Find My cross-check) | ✅ running |
| Partner layer (encrypted sync, browsing trail, dashboard, email alerts) | ✅ running |
| Tamper-evidence (gone-dark, blind, self-test, file-integrity manifest, session/account/dylib/debugger, router-config, DoH/Tor) | ✅ running |
| Admin-trust pivot (no secret on device, partner owns all backends, PR-gated deploys) | ✅ complete |
| Config lock — partner-held pause password + append-only + lockout | ✅ in place |
| Hardened-runtime code signing (denies `lldb` / `DYLD_INSERT_LIBRARIES` against the agent) | ✅ signed & enforcing — remaining gap: the interpreter binary is user-writable and manifest-uncovered (see `deploy/STATUS.md`) |
| MDM-managed browser / full MDM device management | ⬜ optional (paid) — see `deploy/STATUS.md` |
