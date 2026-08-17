# EyeGuard vs. the public bypass-guide ecosystem (2026-08-16)

Every prior red-team of EyeGuard was self-generated — me attacking it as a
technical adversary from first principles. This pass is different: it mines
what's **publicly documented** about defeating Covenant Eyes, Accountable2You,
Bark, Qustodio, and screen-monitoring/content-filter software generally, then
checks each real-world technique against EyeGuard specifically. The value is
catching techniques that are known-effective against real shipped products,
not just theoretically clever ones.

Two genuinely new, high-severity findings came out of this that weren't part
of EyeGuard's threat model before. Several other categories turned out to
already be covered by existing hardening. None of this has been acted on yet
— this is the research/writeup pass; fixes are a separate next step.

## 🔴 Finding 1 — macOS Recovery Mode's "Forgot Password" flow (Apple Silicon)

**Source:** confirmed via a specific incident report — Covenant Eyes,
Accountable2You, and Ever Accountable were each asked about this directly and
each confirmed they have **no fix**. Covenant Eyes' own quote: *"there is not
a way to block this access. Apple did not create a way to do what you are
needing for the M1 Mac."*

**Mechanism:**
1. Force-restart into startup options (power button, on Apple Silicon).
2. Enter Recovery via the Options screen.
3. On the account picker, choose **"Forgot Password"**.
4. Authenticate with the **monitored user's own Apple ID / iCloud password**
   — not an admin's local password, not FileVault's.
5. This drops you into Recovery's password-reset utilities, which include an
   **unfiltered, unmonitored instance of Safari** (Apple's own recovery
   browser, used for account-recovery flows).

**Why this is worse than every other bypass in this doc:** it authenticates
with the *monitored user's own Apple ID*, which they obviously know — it does
NOT require Dad's admin password, does NOT require the FileVault password, and
does NOT require bypassing the Standard-user lockdown at all. It sidesteps the
entire account-privilege model this project spent the 2026-08-04 lockdown
building, because it happens **before macOS itself is even running** — nothing
EyeGuard does at the OS-user-permission layer can see or stop it.

**Applicability to EyeGuard:** structurally identical exposure. EyeGuard's
vault daemon and session agent are both regular launchd jobs that only exist
once macOS has fully booted into the installed system — Recovery's Safari
runs from Apple's own recovery OS image, entirely outside that. No local
process, root or not, root-owned or not, can observe or interfere with it.

**What's NOT yet known / worth verifying (not done tonight):**
- Whether Recovery Mode's network access on this specific machine is
  unrestricted, or whether the router-side DNS/DoT/DoH lockdown (which
  operates at the network layer, below the OS) still applies to whatever
  Recovery's Safari uses for DNS. If the router-level filtering still holds
  even here, this becomes "unmonitored but still filtered/logged at the wire"
  rather than a full escape — worth an actual controlled test.
- Whether disk encryption / FileVault's own pre-boot authentication (which is
  separate from the OS-user Apple ID flow) changes anything about which
  Recovery paths are reachable without it.

**Possible mitigations (not implemented, for discussion):**
- This can't be closed at the EyeGuard application layer — it's an
  Apple-Silicon-firmware-level gap the entire industry has independently
  confirmed is unfixable from userland.
- The one lever that *might* narrow it: if the router-level DNS/DoT/DoH
  lockdown does still apply to Recovery-mode network traffic (needs the
  verification above), the wire-capture tamper-evidence on the phone/router
  side is a template for doing the same on the router for the Mac's Recovery
  Safari session — still no on-device flag, but a same-day router-side log of
  what domains were hit. Worth scoping only if the verification above confirms
  it's actually reachable.
- Otherwise: this is a `philosophy: tamper-evident, not tamper-proof` residual
  in its purest form, same category as "a determined local admin can always
  eventually defeat local software." Worth explicitly naming this as an
  **accepted, not closable** gap rather than leaving it implicit.

## 🔴 Finding 2 — Safe Mode boot skips both EyeGuard processes entirely

**Source:** general macOS documentation + community reports, cross-checked
against Apple's own description of Safe Mode ("prevents certain software from
loading as your Mac starts up... login items and extensions that aren't
required by macOS").

**Mechanism:** power-cycle the Mac and hold Shift (Intel) / hold Power and
choose Safe Mode from the startup-options screen (Apple Silicon) — no
credentials of any kind required, this is a standard boot option available to
anyone with physical access to the power button. macOS then boots without
loading third-party LaunchAgents/LaunchDaemons (the exact mechanism both
`com.eyeguard.vault` and `com.eyeguard.monitor` rely on to start at all) while
still providing a completely normal, usable GUI login and full browser access
— Safe Mode is designed to be usable for troubleshooting, not a restricted
console.

**Applicability to EyeGuard:** if this holds as documented, **both halves**
of the split architecture — the root vault daemon and the session agent —
simply never start. No screen capture, no local flag log, no local tamper
checks. This isn't gated by the Standard-user lockdown at all (`launchctl
bootout` being refused doesn't matter if the daemon was never launched to
begin with) — it's a boot-time OS decision, made before any of EyeGuard's own
permission model is even relevant.

**Where this does NOT fully escape detection:** the vault daemon's heartbeat
going stale is exactly what the `eg_check_gone_dark` cron exists to catch,
and it doesn't care *why* the heartbeat stopped. So a Safe Mode session
**will** eventually trigger a real gone-dark alert once the heartbeat's been
stale past the cron's threshold — this isn't a silent, permanent bypass the
way the Recovery Mode finding above is. The actual gap is narrower but still
real: a **bounded window** (however long that threshold currently is) of
genuinely unmonitored, alert-free browsing, repeatable at will, with zero
credentials needed — and if the window used is shorter than the threshold,
there's no alert and no local trace at all once back in normal mode.

**Not yet verified (deliberately not tested live tonight):** whether
LaunchDaemons specifically (vs. classic Login Items, which is what the
clearest community reports actually observed) are suppressed the same way as
LaunchAgents in Safe Mode — the documentation is consistent but I don't have
a primary Apple source distinguishing the two mechanisms precisely. Testing
this for real means an actual Safe Mode boot on the monitored Mac, which is
disruptive to live monitoring and shouldn't happen without Dad's knowledge
and a deliberate, low-stakes moment chosen for it — not something to trigger
unilaterally.

**Possible mitigations (not implemented, for discussion):**
- **Boot-history tamper flag**: macOS can report whether the *previous* boot
  was a Safe Boot (via `nvram`/`sysctl`-level flags or unified-log boot
  records). EyeGuard's processes can't self-report *during* Safe Mode (they
  never start), but the vault daemon *can* check on its next normal startup
  whether the prior boot was Safe and, if so, immediately fire a tamper
  report — this doesn't close the live window, but it closes the "zero trace
  ever" gap for short windows under the gone-dark threshold, matching the
  project's existing tamper-evident philosophy exactly (can't prevent, can
  make sure Dad finds out).
- Shortening the gone-dark threshold narrows the alert-free window but trades
  against false-positive risk on ordinary hiccups — a real tradeoff, not a
  free win, matching the same tension already discussed for the sleep/wake
  race this session.

## 🟢 Categories already well-covered by existing hardening

Cross-checked against real bypass-guide content; EyeGuard already matches or
exceeds what's described for commercial tools:

- **Uninstall/tamper resistance** — public guides consistently describe
  Bark/Qustodio's protection as "requires parent credentials" / "device admin
  privileges." EyeGuard's root-owned code tree + Standard-user lockdown +
  `launchctl bootout` refusal is the same tier of protection, already built
  and verified (2026-08-04 lockdown).
- **VPN/DNS-filter bypass** (the most commonly cited technique across every
  guide found) — already the router side's entire design: Block-DoT + DoH
  hostname/SNI/canary lockdown, wire-capture that sees bypass *attempts* even
  when they fail (e.g. querying `8.8.8.8` directly). The one still-open
  residual here (self-hosted DoH on an unlisted IP, or ECH) was already
  self-documented in `PHONE.md` before this research pass — fresh research
  confirms it's getting *more* relevant over time (browsers now enable ECH by
  default when they detect valid config records), not less, which is worth
  flagging even though it doesn't change what to do about it yet.
- **Second-monitor / uncaptured-display blind spots** — a real technique
  found in general screenshot-monitoring bypass guides ("some tools miss the
  second screen"). Already closed here specifically: `capture.py` captures
  all displays and re-enumerates every cycle for hot-plug, so this doesn't
  apply to EyeGuard's design.
- **Virtual machine sandboxing** — guides suggest running a VM as an isolated
  workspace monitoring can't see into. For EyeGuard this doesn't actually
  work as an evasion on its own: a VM running in a window is still pixels on
  the host framebuffer EyeGuard captures like anything else; only a fully
  separate physical display would evade it (see display-capture point
  above). Separately, `vm_monitor.py` already flags the *installation* of
  virtualization software as a tamper-adjacent signal, which is the more
  relevant angle regardless.
- **Idle-window / activity-fakery tricks** (mouse jigglers, fake idle
  windows, predictable-interval timing) — these guides are written against
  tools that infer "working" from *activity metadata* (keystrokes, idle
  timers, screenshot cadence gaming). EyeGuard doesn't work that way — it
  directly analyzes captured pixel content continuously, not activity
  proxies — so this entire technique category doesn't transfer.

## 🟢 `tccutil reset ScreenCapture` — tested live, does not disrupt the running agent

Docs said this "typically" needs admin. Tested for real instead of trusting
that: ran `tccutil reset ScreenCapture` (no bundle ID — blanket reset for the
current user) as `jonahdirrim`, confirmed Standard/non-admin at the time
(`groups` — no `admin`). **The command itself succeeded with no privilege
error** (`Successfully reset ScreenCapture`, exit 0) — so the "needs admin"
claim doesn't hold as stated, at least not as a hard gate on running the
command.

But the actually-relevant question is whether it disrupted the *live,
already-granted* agent process, and it didn't: checked `flags.jsonl`
immediately after — fresh green activity entries logged within the same
minute, timestamps matching real time, agent PID unchanged and still running.
Capture continued uninterrupted through and after the reset call. Whatever
this command actually clears, it isn't pulling the grant out from under an
already-running background process the way it would for a foreground app
that gets re-prompted on next launch. Not fully characterized *why* (possibly
scoped to interactively-relaunchable apps rather than daemon-launched
background interpreters, possibly something about the invoking context) —
but the live behavior is what matters, and it's a non-event. Downgraded from
"needs verification" to confirmed low real-world severity.
- **Single-user mode** — deprecated on Apple Silicon and requires lowering
  the Secure Boot policy from Recovery (itself gated behind the same Apple ID
  auth as Finding 1, so it's not really a *separate* attack surface — more of
  a variant reachable through the same door). Not worth independent hardening
  effort beyond whatever's decided for Finding 1.

## Summary for prioritization

| Finding | Credentials needed | Detected? | Status |
|---|---|---|---|
| Recovery Mode "Forgot Password" (Finding 1) | Own Apple ID only | No — full escape, industry-wide unfixed | Needs a decision: verify router-layer reach, or accept as documented residual |
| Safe Mode boot (Finding 2) | None | Eventually, via gone-dark, IF window > threshold | Needs a decision: build boot-history tamper flag, and/or a real (planned) test |
| tccutil ScreenCapture reset | None (tested) | N/A — doesn't disrupt a live agent | Tested live, non-issue, closed |
| Everything else researched | — | — | Already covered by existing design |

Nothing above has been implemented. This doc is the research + analysis
deliverable; next step is picking which finding (if any) to act on first.
