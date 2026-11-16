# Viewing encrypted review images in the browser: design (proposal, not built)

Status: proposal for Dad's review. Nothing here changes capture, detection, alerts or what is uploaded.
Author: Agent Sauron, 2026-11-16. Needs: Jonah's OK and Dad's GitHub review before any code.

## Problem
Since 2026-08-24 every review frame is encrypted on the Mac (AES-256-GCM, key wrapped with Dad's RSA public key,
`eyeguard/frame_crypto.py`). Only Dad's offline device can decrypt (`deploy/decrypt_frame.py`). The dashboard
(`docs/index.html`) put the ciphertext into an `<img>`, so every partner saw a broken-image icon. PR "Wording" replaces
the icon with a lock and fixes the email text. This document is how partners could actually see the image.

## Goals and non-goals
- Goal: a partner Dad approves can see a flagged frame in their own browser. The server (Supabase), the CDN, GitHub and
  a stolen anon key still see only ciphertext.
- Goal: nobody gets access by default. Access = a public key Dad merged into `config.yaml`.
- Non-goal: weaken Dad's offline key. It stays recipient #0 and `decrypt_frame.py` keeps working.
- Non-goal: show anything the Mac would not have uploaded anyway (RED frames are still blurred before encryption).

## Design

### 1. Each viewing device owns its own key, and it cannot be exported
The dashboard generates an RSA-OAEP (SHA-256, 3072-bit) key pair with WebCrypto `generateKey(..., extractable:false)`
and keeps the private `CryptoKey` in IndexedDB. A non-extractable key can be used by the page but its bytes can never
be read, not by the page, not by an injected script, not by a browser extension. It is never sent anywhere.
The page shows the public key (SPKI PEM) and a short fingerprint for the partner to send to Dad.

Rejected: pasting Dad's offline private key into the page. Any script that ever runs there could read it.
Rejected: decrypting on the server. The server would see every image.

### 2. Recipients are pinned in the repo, not fetched from the database
`config.yaml` gets `encryption.recipients:` (a list of public keys with a label). Adding one is a pull request that Dad
merges (CODEOWNERS), like every other change. The Mac then wraps each frame's AES key once per recipient.
Why not a `recipients` table the Mac reads? Anyone who controlled the database (or a leaked key with the wrong RLS)
could add their own key and read every new frame. Pinning in the repo keeps the only trust root = Dad's merge.

### 3. Wire format v2 (v1 stays readable)
```
"EGF2" | u8 n | n x [ 8-byte key id | u16 wrapped_len | wrapped AES key ] | 12-byte nonce | ciphertext+tag
key id = first 8 bytes of SHA-256(SPKI DER).   AES-GCM AAD = the stored file name (the row's image_path).
```
- v1 starts with a big-endian length (256/384/512), never the bytes `EGF2`, so readers tell them apart.
- AAD = file name means a frame moved to a different flag row fails to decrypt instead of showing the wrong image.
- `decrypt_frame.py` learns v2; v1 frames (all existing ones) stay Dad-only.

### 4. The browser decrypts in memory only
fetch signed URL -> read bytes -> find own key id -> `decrypt` (RSA-OAEP) the AES key -> AES-GCM decrypt ->
`Blob` -> `URL.createObjectURL` -> `<img>`; `revokeObjectURL` when the card leaves the screen. Nothing is written to
storage, nothing is uploaded. A frame with no entry for this device shows the lock placeholder.

## What this does NOT fix (be honest)
- **Old frames** are wrapped for Dad only. They stay lock-only for partners unless Dad re-wraps them with his offline key.
- **Revocation is forward-only.** Removing a recipient stops new frames. Frames already wrapped for that key stay readable
  by whoever holds it. Treat a recipient as permanent for the frames they were present for.
- **A compromised page can use the key while it is open** (not export it): it could decrypt frames and send them out.
  Today the page is exposed to that: it loads `supabase-js@2` from jsDelivr with a floating version and no integrity
  hash, has no Content-Security-Policy, and `docs/index.html` is on the review agent's ignore list. Before any key code
  ships: pin an exact supabase-js version with an SRI hash (or vendor it), add a CSP (`connect-src` = the project host
  only, `img-src blob:`, `script-src 'self'`+hash), and take `docs/index.html` off `.review/ignore.txt`.
- **Browser storage can be wiped** (Safari clears script storage after about 7 days without use unless installed as a
  web app; clearing site data too). The key is then gone: re-enroll, Dad adds the new key, older frames are lost to that
  device. Partners should treat the viewing key as per device, disposable.
- **Policy, not crypto:** who should see these frames at all is Jonah's and Dad's call. This design only makes sure the
  answer is enforced by a merged key, not by a database setting.

## Rollout (each step is its own PR, Dad reviews)
1. Dashboard hardening: pinned supabase-js + SRI, CSP, review-agent ignore removed. No behaviour change.
2. Format v2 + multi-recipient encrypt in `frame_crypto.py`, `decrypt_frame.py` v2, round-trip tests (Python), config
   `recipients: []` (empty = identical to today). Mac auto-deploys it; with no recipients nothing changes.
3. Dashboard enrollment + decrypt. Test the browser code against frames produced by the Python encryptor.
4. First recipient: Dad merges a PR adding the key. Verify on a synthetic frame first, never a real one.

Optional later: bind the key to a passkey (WebAuthn PRF) so it lives in the device's secure hardware.

## Decisions needed
1. Do you want partners (Jada, Dad's browser) to see frames at all, or Dad's device only?
2. If yes: which devices, and who verifies a new key's fingerprint (suggest: Dad, in person or by voice).
3. OK to start with step 1 (hardening only)?
