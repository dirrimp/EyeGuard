# EyeGuard — where things stand

Everything in `README.md` is deployed and running: the Mac agent + root
`session_watcher` / `deploy_watcher`, the file-integrity manifest, the
router-side iPhone monitoring, the Supabase backend, the partner dashboard,
encrypted review frames, and the full tamper-evidence set. This file is the
short "as-built + what's left" record — it replaces the earlier roadmap /
deploy-day docs, which described work that is now done.

## Lockdown state

**Device (the Mac).** Jonah's daily account is Standard; a separate Admin
account's password is held only by Dad. FileVault is on with Dad as a volume
owner and Jonah explicitly *not* one (so Recovery is gated). Guest and
switching to any unmanaged account are off. The deployed tree
(`/Library/Application Support/EyeGuard`) is `root:wheel` — Jonah can read it,
not write it.

**Router.** Jonah has root SSH for network admin. `eyeguard-router-watcher.py`
runs as a separate process from `eyeguard-phone.py` so editing the latter is
caught; router-config drift, DoH, and Tor bypass attempts all alert.

**Backend.** Dad owns the Supabase project, the Resend account, and the GitHub
repo/dashboard. The agent holds **no secret** — public anon key only, through
RPCs that individually can't be misused (server-stamped heartbeat, append-only
flag insert via RLS). The `service_role` key lives only in Dad's Supabase
console and as a GitHub Actions secret for the manifest-publish workflow.

**Change control.** Jonah opens PRs; branch protection + `CODEOWNERS` make
Dad's review mandatory to merge; `deploy_watcher` ships merged commits to the
Mac within ~5 min (`deploy/update.sh` is the manual fallback). See
`deploy/WORKFLOW.md`.

## Accepted residuals — real, named, not closable at the app layer

These are `tamper-evident, not tamper-proof` in its purest form. Worth knowing
about; none has a userland fix.

- **Recovery Mode "Forgot Password" (Apple Silicon).** Force-boot to Recovery,
  choose "Forgot Password", authenticate with Jonah's *own* Apple ID (not
  Dad's admin, not FileVault) → an unfiltered, unmonitored instance of Apple's
  recovery Safari, running before macOS boots. The entire monitoring industry
  (Covenant Eyes, Accountable2You, Ever Accountable) has confirmed this is
  unfixable from userland. **Full escape, no on-device trace.** Only partial
  lever: the router-level DNS/DoT/DoH lockdown *may* still apply to
  Recovery's network traffic (never verified) — that would make it "unmonitored
  but still wire-logged" rather than a total blind spot. Full MDM with
  Recovery Lock would close it.
- **Safe Mode boot.** Hold Power → Safe Mode at the startup screen, no
  credentials. macOS boots without third-party LaunchAgents/LaunchDaemons —
  neither EyeGuard process starts, with a normal usable GUI + browser.
  **Not a silent permanent bypass:** the heartbeat going stale trips
  `eg_check_gone_dark` regardless of *why* it stopped, so a Safe Mode session
  longer than the ~3-min threshold does alert. The gap is a bounded,
  repeatable, alert-free window if kept under that threshold — with no local
  trace once back in normal mode. A boot-history tamper flag (check on next
  normal startup whether the prior boot was Safe, fire a tamper report if so)
  would close the "zero trace for short windows" part; not built.
- **In-memory patching of the agent.** The bundled Python interpreter is
  ad-hoc signed, not hardened-runtime signed, so a technical user with their
  own login can `lldb -p` the running agent (or `DYLD_INSERT_LIBRARIES`) and
  patch `detector.analyze` to return SAFE — it keeps heartbeating, keeps
  passing the self-test, just stops flagging. `session_watcher` catches an
  injected dylib or an attached debugger *while they're present*, which raises
  the bar, but the real fix is hardened-runtime signing — see Open items.
- **A second device / off-screen content / non-visual content.** EyeGuard
  watches *this* Mac's screen and *this* phone's DNS. A different device, DRM
  video pixels macOS blanks, AirPlay to another screen, audio, and plain text
  are out of scope by construction (titles / the green trail still log *that*
  a site was visited). DRM playback specifically is now recognized and logged
  quietly instead of firing a false blindness alert.
- **Router-side DoH on an unlisted IP, or Encrypted Client Hello.** The
  firewall + SNI/canary layers catch known DoH providers and default Tor; a
  self-hosted resolver on an unlisted IP, or ECH (increasingly on by default
  in browsers), isn't caught. Also noted in `deploy/PHONE.md`.

## Checked and cleared (not residuals)

- **`tccutil reset ScreenCapture`** — tested live as a Standard user: the
  command succeeds but does **not** disrupt the already-running agent (capture
  continued, fresh flags logged through and after). Non-issue.
- **Second monitor** — `capture.py` grabs all displays and re-enumerates every
  cycle for hot-plug.
- **VM in a window** — still pixels on the host framebuffer; captured normally.
  `vm_monitor.py` also flags virtualization-software *installation*.
- **Uninstall/tamper resistance, VPN/DNS-filter bypass, activity-fakery** —
  covered by the root-owned tree + Standard-user lockdown, the router's
  DoT/DoH lockdown + wire capture, and pixel-content analysis (not activity
  proxies), respectively.

## Open items

1. **Hardened-runtime code-signing of the agent** — the single most valuable
   remaining hardening. Free (no Apple Developer Program; notarization isn't
   needed for a locally-installed app). Requires bundling the agent into one
   Mach-O and signing with `--options runtime` + a
   `disable-library-validation` entitlement (so Python can still load
   onnxruntime/numpy/pyobjc) but **not** `get-task-allow` — its absence is
   what denies `lldb` and `DYLD_INSERT_LIBRARIES`. Turns the injected-dylib /
   debugger checks and the detector self-test from "raise the bar" into real
   guarantees. Script scaffold: `deploy/harden_codesign.sh`.
2. **MDM-managed browser** (optional, paid) — an enforced extension allow-list
   + managed content filter closes the window-title-spoofer and
   adversarial-overlay-extension attacks with prevention rather than evidence.
   `extensions.py` already makes a new extension *visible*; MDM would make it
   *impossible*.
3. **Full MDM device management** (optional, paid) — closes "get admin once
   and it's permanent" and adds Recovery Lock (which also narrows the Recovery
   Mode residual above) + wipe survival.
