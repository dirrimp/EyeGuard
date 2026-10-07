# G11 integrity watch: what is built, what it proves, and what would prove more

The G11 is the one machine in this system that the monitored person controls. Everything
that runs there (`poll.py`, `hook.py`, the reporter, the cron line) can be edited by someone
with root. This is how Dad's database watches it, and the honest limits of that.

## Layer 1 (this PR): approved hashes in Dad's database, compared by the database
1. A merge to `main` runs `.github/workflows/publish-g11-manifest.yml`, which inserts the
   sha256 of every file that runs on the G11, plus the exact poller cron line, into
   `public.g11_manifests` using Dad's service-role **GitHub secret**. The G11 and every agent
   session have no key that can write it; rows are insert-only (even the service role cannot
   update or delete), so approved history cannot be rewritten.
2. Every 5 minutes the G11 sends `{item: sha256}` (no content, no paths) via `eg-report.sh --attest`.
3. `eg_mdm_attest()` (server) classifies each item:

| Observed | Meaning | Action |
|---|---|---|
| equals the latest manifest | ok | nothing |
| equals an **earlier** manifest | reviewed code, deploy not done | email only after 24 h |
| matches **no** manifest, or is missing | code nobody approved | **email immediately**, open incident |
| reports stop while the heartbeat continues | someone disabled only the report | email after 15 min |

Each alert has an all-clear and a permanent row in `mdm_incidents` (shown in the dashboard).
A generator / installer / reporter agreement test guarantees a normal deploy never looks like drift.

### What Layer 1 does and does not prove
- **Catches:** hand edits on the G11, deploys that skipped review, a changed or removed cron
  line, a deleted file, and any tamper that forgets to also fake the report. It also enforces
  process: live code that was never merged by Dad is flagged, whoever or whatever changed it.
- **Does not stop** a user with root from making the reporter send the approved hashes while
  running other code. The report is produced on the machine being watched. A clean result is
  **evidence, not proof**. The email and dashboard say so.

## Layer 2 (not built; needs decisions): hardware root of trust
What would make the result **unforgeable from the G11**: a TPM 2.0 quote plus the kernel's
IMA measurement log, verified in Dad's system, not on the G11.
- The TPM signs the current PCR values with an attestation key whose private half never leaves
  the chip. Root can ask the TPM to sign, but only over the PCRs as they really are.
- With an IMA policy, the kernel extends PCR 10 with the hash of every file executed (and files
  root reads). The log can be replayed against PCR 10; root cannot delete an entry without the
  replay failing. Rebooting into something else changes the boot PCRs and is itself detected.
- The server then checks the signature, the replay, the boot PCRs, and each measured hash
  against an allowlist Dad controls.

### Checked on this G11 (read-only, 2026-10-07)
| Needed | Found |
|---|---|
| TPM 2.0 | **yes** (`/dev/tpm0`, `/dev/tpmrm0`, `tpm_crb`, UEFI TPM event log present) |
| Kernel IMA | **yes** (`/sys/kernel/security/ima`), but no policy active unless set at boot |
| Secure Boot | **off** (boot-chain trust is weaker until enabled) |
| `tpm2-tools` | **not installed** |
| Virtualisation | none (physical GMKtec NucBox G11) |

### What it needs, and who decides
1. Install `tpm2-tools` on the G11 (system change; Agent IT / Jonah).
2. Turn on an IMA policy on the kernel command line and reboot (system change; ideally measure
   only a dedicated filesystem holding the EyeGuard code so the allowlist stays small, instead
   of every binary on the box).
3. Decide on Secure Boot (without it the kernel/initrd/cmdline measurements are only as good
   as the firmware's measured boot).
4. **Enrol the attestation key with Dad present, while the G11 is known clean** (trust on first
   use). A key registered later could belong to an attacker.
5. A verifier Dad controls: a Supabase Edge Function that Dad deploys himself (it verifies the
   quote signature and replays the log), or Keylime on a machine Dad owns. Not on the G11.
6. An allowlist process: every legitimate update (apt, the repo) needs Dad's approval of the new hashes.

### Residual even with Layer 2
Code that IMA does not measure, firmware/physical attacks on the machine, and anything that
happens before the first enrolment. It is a large step up, not magic.

## The structural alternative
Run the MDM server and poller on a machine the monitored person has no root on (Dad's server).
That removes the problem instead of watching it, and fits the long-term remote-product goal.
