# Scoping: route the vault daemon's own traffic off the on-demand VPN tunnel

Prompted by PR #24's diagnosis of the 2026-08-17 ~00:07 lid-close gone-dark
alert: this Mac's default route is frequently the on-demand WireGuard tunnel
(`utun1`), which `scutil` itself flags as "Transient Connection" and which
showed live, reproducible DNS-resolution failures during that investigation.
The vault daemon's heartbeat currently rides whatever the default route is —
so its reliability is hostage to the tunnel's own connect/reconnect state
machine, especially right at a sleep transition. This document scopes a fix,
not yet implemented.

## Options considered

**1. Bind the daemon's own sockets to the physical interface (recommended)**
Use macOS's `IP_BOUND_IF`/`IPV6_BOUND_IF` socket options to force the vault
daemon's HTTPS connections onto the physical Wi-Fi/Ethernet interface
specifically, regardless of what the system's default route currently is.
This is a pure code change, entirely within EyeGuard's own control — no
dependency on the WireGuard app's config, which the daemon has no visibility
into and which could change (different VPN app, different profile, interface
renamed) without EyeGuard's knowledge.

**Verified working today, live, not just documented:** bound a raw socket to
`en0` (`IP_BOUND_IF = 25`, confirmed from `/usr/include/netinet/in.h` on this
machine), resolved `ucgldleacehxjjwwqomk.supabase.co` for real, connected on
port 443, and completed a full TLS 1.3 handshake — while the tunnel remained
the system's default route the entire time. This is a real capability on
this Mac, not a theoretical option.

**2. Static host route pinning `route add -host <supabase-ip> -interface en0`**
Rejected as the primary approach: Supabase's IP isn't fixed (DNS-based,
cloud-provider-managed, can change on their end without notice), so a static
route would silently go stale and this Mac would fall back to the tunnel
again with no one aware it happened. Would need its own re-resolution/refresh
logic to stay correct, at which point it's more moving parts than option 1
for a strictly worse result (a route-table side effect outside the process
itself, vs. a self-contained socket option scoped to exactly the connections
that need it).

**3. WireGuard `AllowedIPs` split-tunnel exclusion (config-level, not code)**
The "correct" networking-textbook answer — exclude Supabase's IP range from
the tunnel's routing at the VPN profile level, so ALL apps' traffic to that
destination bypasses the tunnel by design. Rejected as the *primary* fix
here because it lives entirely outside the EyeGuard codebase (the Mac's
WireGuard app/profile, not `git`-tracked, not something a PR touches), has
the same IP-can-change fragility as option 2 unless scoped by hostname (which
WireGuard's `AllowedIPs` doesn't support natively), and depends on whoever
manages that VPN profile keeping it in sync — none of which EyeGuard can
verify or enforce. Could be a *complementary* belt-and-suspenders addition
later, but shouldn't be the only fix.

## Recommended approach: interface-bound sockets in `uploader.py`

### Interface selection — dynamic, not hardcoded
Don't hardcode `en0` — Ethernet, a different Wi-Fi interface name, or docking
could all change which interface is actually "the physical one" on a given
day. Use `scutil --nwi`'s own priority-ordered interface list (this is the
same list macOS itself uses to decide the default route) and pick the first
entry that ISN'T a tunnel-looking prefix (`utun`, `ppp`, `ipsec`, `awdl`):

```python
def _physical_interface() -> str | None:
    """First non-tunnel interface in macOS's own priority order, or None if
    none found (e.g. the only path really is the tunnel -- caller should fall
    back to default/unbound routing, not hard-fail)."""
    try:
        out = subprocess.run(["scutil", "--nwi"], capture_output=True,
                              text=True, timeout=5).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if line.startswith("Network interfaces:"):
            for name in line.split(":", 1)[1].split():
                if not name.startswith(("utun", "ppp", "ipsec", "awdl")):
                    return name
    return None
```

Verified live against this Mac's actual `scutil --nwi` output today: returns
`utun1 en0` in that priority order, filters correctly to `en0`.

### Wiring into the HTTP layer
`uploader.py` uses `urllib.request.urlopen()` directly in three places
(`_post_status`, `_put_image`, `_post_row`). `urllib` doesn't expose a socket
hook directly, so the clean way in is a custom `http.client.HTTPSConnection`
subclass that binds before connecting, wired through a custom
`HTTPSHandler`/opener:

```python
class _BoundHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        iface = _physical_interface()
        if iface:
            ifindex = socket.if_nametoindex(iface)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, ifindex)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        else:
            super().connect()  # no physical interface found -- default behavior
```

...used via a module-level `opener = urllib.request.build_opener(_BoundHTTPSHandler)`,
replacing the three bare `urllib.request.urlopen(req, ...)` calls with
`opener.open(req, ...)`. Falls back to normal (tunnel-following) behavior if
`_physical_interface()` finds nothing — so a Mac with genuinely no physical
uplink (only reachable via the tunnel) doesn't get hard-broken by this
change, it just behaves exactly as it does today.

### Scope: all uploader traffic, not just the heartbeat
Recommend applying this to all three call sites (`_post_status` heartbeat,
`_put_image`, `_post_row`), not just the heartbeat — flag/image uploads have
the same "shouldn't depend on an unrelated app's tunnel state" argument, and
there's no reason to special-case just one.

## Open questions for a decision before implementing

1. **Privacy tradeoff worth naming explicitly:** bypassing the VPN for
   EyeGuard's own traffic means Supabase (and anything on the physical
   network path) sees this Mac's real IP/location for *that* traffic,
   independent of whatever the VPN is otherwise hiding for everything else.
   Given the traffic itself is just flags/heartbeat metadata Dad already
   receives regardless, this is likely a non-issue -- but it's a real,
   distinct question from "does this fix the bug," worth a conscious yes
   rather than an implicit one.
2. **Fallback behavior when no physical interface exists at all** (Mac is
   genuinely only reachable via the tunnel, e.g. cellular-hotspot-through-VPN
   setups) — proposed: fall back to default/unbound connection (today's
   behavior), so this change can only ever make things more reliable, never
   less, even in a Mac configuration this hasn't been tested against.
3. Should this be paired with option 3 (WireGuard `AllowedIPs` exclusion) as
   a second, independent layer, or is the code-level fix sufficient on its
   own? Leaning toward code-only for now — it's the layer EyeGuard actually
   controls and verifies, and a second layer adds complexity for marginal
   benefit given the code fix alone is already a full bypass.

Nothing here has been implemented yet — this is the scoping/design
deliverable, verified feasible with real live tests, not the fix itself.
