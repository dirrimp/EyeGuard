# Vendored: @supabase/supabase-js 2.118.0 (UMD build)

`supabase-js-2.118.0.umd.js` is `dist/umd/supabase.js` from the npm package `@supabase/supabase-js@2.118.0`
(published 2026-10-15). It replaces `cdn.jsdelivr.net/npm/@supabase/supabase-js@2`, which floated to whatever
2.x was newest and had no integrity check, so a compromised release would have run in the dashboard unnoticed.

- sha256: `ee3be8de192b97cb1d73d1e95d6b82bb1f6b658c0f97c4ef757fc331996ed3d3`
- sha384 (SRI): `TcHRA3zBbn+Lexh5n+Oil4guNPOS3rjNDpGRAN46u/s/mB2IZ50ceC6TYDU2yvgK`
- Verified on 2026-11-16: the jsDelivr bytes are identical to the file inside the npm registry tarball.
- Contains no `eval(` / `new Function(` (so the page's Content-Security-Policy needs no `unsafe-eval`).

To upgrade: download the new version from npm, compare it with a second source, update the file name, the `<script>`
tag (and its `integrity`), this README, and re-run `tests/test_dashboard_csp.py`.
