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
- **In-memory patching of the agent — closed.** The bundled Python
  interpreter is hardened-runtime signed (verified live via `csops` on the
  running process: `CS_RUNTIME | CS_HARD | CS_KILL` set, `CS_GET_TASK_ALLOW`
  clear), so `lldb -p` on the live agent is denied and
  `DYLD_INSERT_LIBRARIES` is ignored. The interpreter binary lives in a
  user-writable path (`/Applications/EyeGuard.app/…`) outside the root-owned
  tree and the file-integrity manifest, so it could in principle be swapped
  for an unhardened build — now covered two ways: **prevention** —
  `install_app.sh` and `deploy_watcher` lock the `.app` bundle to `root:wheel`,
  non-user-writable, so a Standard user can't replace it; **evidence** —
  `session_watcher` checks the live agent's `csops` flags every cycle and
  fires the branch (e) anomaly alert (`p_agent_unhardened`,
  `supabase/agent_hardened_runtime_check.sql`) if `CS_RUNTIME` is ever
  missing or `CS_GET_TASK_ALLOW` is set, catching a swap done by someone with
  admin. `session_watcher` also still checks for an injected dylib / attached
  debugger as further defence in depth.
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

## Done since the roadmap docs

- **Hardened-runtime code-signing of the agent** (`deploy/harden_codesign.sh`).
  The interpreter is signed `--options runtime` with
  `com.apple.security.cs.disable-library-validation` (so onnxruntime / numpy /
  pyobjc still load) and no `get-task-allow`. Verified live on the running
  process. This was the old HARDENING_3.0.md #1 item.
- **Interpreter-swap protection** — bundle locked `root:wheel` /
  non-user-writable (`install_app.sh` + `deploy_watcher`, so a Standard user
  can't swap it), plus a per-cycle `csops` check in `session_watcher`
  (`p_agent_unhardened`) that alerts if the running agent ever loses
  `CS_RUNTIME` / gains `CS_GET_TASK_ALLOW`.
  **One-time on the already-deployed Mac (Dad, sudo):**
  `sudo chown -R root:wheel /Applications/EyeGuard.app && sudo chmod -R go-w /Applications/EyeGuard.app`
  — the next `deploy_watcher` deploy also does this automatically.

## Open items

1. **Sign the `.app` bundle itself** — currently only the interpreter inside it
   is signed. Cosmetic for launch (the LaunchAgent runs the interpreter by
   path, and the swap protections above cover the real risk), but worth doing
   for completeness / Gatekeeper.
2. **MDM-managed browser** (optional, paid) — an enforced extension allow-list
   + managed content filter closes the window-title-spoofer and
   adversarial-overlay-extension attacks with prevention rather than evidence.
   `extensions.py` already makes a new extension *visible*; MDM would make it
   *impossible*.
3. **Full MDM device management** (optional, paid) — closes "get admin once
   and it's permanent" and adds Recovery Lock (which also narrows the Recovery
   Mode residual above) + wipe survival.
