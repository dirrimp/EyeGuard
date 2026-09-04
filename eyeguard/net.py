"""Shared HTTPS transport: route every call off the system default route.

The default route is often an on-demand VPN tunnel (confirmed live
2026-08-17: scutil flags it "Transient Connection", and it was caught
mid-DNS-resolution-failure during a real gone-dark investigation). This Mac's
own network state shouldn't be able to interrupt the accountability channel,
so every request binds to the physical interface directly via IP_BOUND_IF,
independent of whatever the tunnel is doing at that moment. IP_BOUND_IF=25,
confirmed from this machine's own /usr/include/netinet/in.h (not guessed).

Originally built directly inside uploader.py (2026-08-19); extracted here
2026-08-25 after the admin-trust-pivot session added session_watcher.py and
deploy_watcher.py, both of which reinvented raw urllib.request.urlopen()
networking and so never got this fix -- confirmed live via their own logs
hitting the identical tunnel-instability error signatures uploader.py used to
hit before this existed. session_watcher.py's heartbeat is especially
exposed: at its 120s check_seconds, just TWO consecutive network blips (240s)
exceed eg_check_gone_dark()'s 3-minute staleness threshold for
watcher_last_heartbeat -- a much tighter margin than the old vault daemon's
60s retry cycle ever had. All Supabase/GitHub-calling code in this project
should import `opener` from here rather than using urllib.request.urlopen()
directly, so this fix can't silently miss a future new file the same way.

GAP FOUND + FIXED (2026-08-31): the interface-binding above only ever
protected the DATA connection -- `sock.connect((self.host, self.port))`
still resolves `self.host` via the system's own DNS resolver first, before
the bound socket is even created. Confirmed live via `scutil --dns`: this
Mac's ENTIRE DNS resolution goes through the WireGuard tunnel's own
nameserver (10.1.0.1, over utun0) -- there is no separate resolver for the
physical interface at all. So the exact instability this file was built to
route around (an unstable on-demand tunnel) was still able to break every
single request at the hostname-lookup step, regardless of the interface bind
that happens after. Confirmed live: session_watcher.py's own log full of
"nodename nor servname provided" even while on ordinary home wifi, tracing
directly to tunnel renegotiation blips. This explained a real share of the
"monitoring went dark"/"session watcher went dark" alert noise that
survived every other fix in this project's history -- not sleep, not the
phone wg_peer bug, a genuine DNS-resolution gap in this exact file.

Fix: resolve the hostname ourselves via a hand-rolled DNS-over-UDP query,
sent on a socket ALSO bound to the physical interface via the same
IP_BOUND_IF mechanism -- so hostname lookup is now just as tunnel-
independent as the data connection already was. Queries a short list of
well-known public resolvers (Cloudflare, then Google) for resilience against
either one being briefly unreachable. Falls back to ordinary system
resolution (today's existing behavior) on ANY failure -- a parse error, a
timeout, an unexpected response shape -- so this can only ever ADD a more
reliable path, never remove the one that worked before this existed.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import socket
import struct
import subprocess
import urllib.request

_IP_BOUND_IF = 25

# Well-known public resolvers, tried in order. Two independent providers so
# one being briefly unreachable (its own outage, or blocked on this specific
# network) doesn't take hostname resolution down with it.
_DNS_SERVERS = ("1.1.1.1", "8.8.8.8")


def physical_interface() -> str | None:
    """First non-tunnel interface in macOS's own priority order (scutil
    --nwi's own "Network interfaces:" line -- the same list macOS itself
    uses to pick the default route), or None if none found. Re-checked on
    every connection attempt (not cached) since the active interface can
    change -- Wi-Fi<->Ethernet, docking -- while a process runs for days.
    Never raises: a scutil hiccup should fall back to default routing, not
    break every request."""
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


def _bound_udp_socket(iface: str) -> socket.socket:
    ifindex = socket.if_nametoindex(iface)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, ifindex)
    sock.settimeout(3)
    return sock


def _encode_qname(hostname: str) -> bytes:
    out = bytearray()
    for label in hostname.encode("ascii").split(b"."):
        if not label or len(label) > 63:
            raise ValueError(f"bad DNS label in {hostname!r}")
        out += bytes([len(label)]) + label
    out += b"\x00"
    return bytes(out)


def _skip_name(buf: bytes, offset: int) -> int:
    """Advances past a (possibly compressed) DNS name starting at `offset`,
    returning the offset immediately after it. Only needs to handle what a
    well-formed response actually contains -- raises on anything else, which
    the caller treats as "give up, fall back to system resolution", same as
    every other failure mode here."""
    while True:
        length = buf[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer, always 2 bytes
            return offset + 2
        offset += 1 + length


def _dns_query_a(hostname: str, iface: str, server: str) -> str | None:
    """One A-record query to `server`, over a socket bound to `iface`.
    Returns the first A record's dotted-quad string, or None if the query
    failed, timed out, or the response didn't parse as expected -- never
    raises, this is always a best-effort attempt with a real fallback
    waiting behind it."""
    qname = _encode_qname(hostname)
    txn_id = int.from_bytes(os.urandom(2), "big")
    # header: id, flags(recursion desired), qdcount=1, an/ns/ar=0
    query = (struct.pack(">HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
              + qname + struct.pack(">HH", 1, 1))  # QTYPE=A, QCLASS=IN
    sock = _bound_udp_socket(iface)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(512)
    finally:
        sock.close()

    resp_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if resp_id != txn_id or ancount < 1:
        return None
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset) + 4  # + QTYPE/QCLASS
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack(
            ">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:  # A record
            return ".".join(str(b) for b in data[offset:offset + 4])
        offset += rdlength
    return None


def resolve_via_physical_interface(hostname: str, iface: str) -> str | None:
    """Tries each server in _DNS_SERVERS in turn; returns the first
    successful A-record answer, or None if all fail. Every failure mode
    (network error, malformed response, timeout) is swallowed here -- the
    caller's own fallback to system resolution is the safety net, not this
    function raising."""
    for server in _DNS_SERVERS:
        try:
            ip = _dns_query_a(hostname, iface, server)
            if ip:
                return ip
        except Exception:
            continue
    return None


@contextlib.contextmanager
def hardened_dns():
    """Confirmed live (2026-09-04): eyeguard/findmy_watcher.py hit the
    exact same "nodename nor servname provided" DNS failure this whole
    module exists to route around (idmsa.apple.com, while on the AmneziaWG
    tunnel at the station) -- but pyicloud manages its own requests.Session()
    internally, with no way to hand it this module's own physical-
    interface-bound opener the way every other HTTP call in this project
    already does. socket.getaddrinfo is the one layer pyicloud (via
    requests -> urllib3) can't avoid going through, so this patches THAT
    instead, narrowly, for the duration of a `with` block.

    Every lookup made inside the block tries resolve_via_physical_interface()
    first; only on failure (or no physical interface found) does it fall
    through to the ORIGINAL system resolver -- so this can only ever ADD a
    more reliable path, never remove the one that worked before this
    existed. Restores the original getaddrinfo unconditionally on exit,
    even on an exception, so a caller elsewhere in the same process is
    never left with a patched resolver by accident.

    Does NOT bind the actual data connection to the physical interface the
    way _BoundHTTPSConnection does for this project's own HTTP calls (see
    this module's own docstring for why DNS alone wasn't originally
    considered sufficient) -- pyicloud/requests/urllib3 don't expose a
    clean hook for that the way http.client.HTTPSConnection.connect() does.
    Accepted, narrower scope: this fixes the DNS-resolution failure mode
    actually observed and confirmed live; a tunnel instability that
    manifests as a data-connection failure AFTER successful DNS resolution
    is not covered by this specific fix."""
    original = socket.getaddrinfo
    iface = physical_interface()

    def _patched(host, *args, **kwargs):
        if iface and isinstance(host, str):
            ip = resolve_via_physical_interface(host, iface)
            if ip:
                try:
                    return original(ip, *args, **kwargs)
                except Exception:
                    pass
        return original(host, *args, **kwargs)

    socket.getaddrinfo = _patched
    try:
        yield
    finally:
        socket.getaddrinfo = original


def general_internet_reachable() -> bool:
    """Best-effort: is there a path to the general internet right now at
    all, independent of Supabase specifically and independent of DNS (a raw
    IP connect to the same well-known resolvers already used above, bound
    to the physical interface like everything else here)? Used only to tell
    "the whole network is genuinely down" (nothing risky possible either)
    apart from "this Mac's path to Supabase specifically is broken while
    the rest of the internet works fine" -- see uploader.py's
    note_screen_asleep()'s sibling reasoning and _heartbeat_failed()'s use
    of this. Feeds only a RETROACTIVE follow-up email once reconnected
    (eg_report_network_gap), never the real-time gone-dark alert itself,
    which must stay fail-safe and unconditional regardless of what this
    returns -- a client that can't reach the internet also can't call the
    RPC that reports it couldn't. Never raises: any failure here just means
    "couldn't confirm reachable" (False), not "confirmed unreachable"."""
    iface = physical_interface()
    for ip in _DNS_SERVERS:  # 1.1.1.1 / 8.8.8.8 -- effectively always-up anycast
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if iface:
                sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF,
                                 socket.if_nametoindex(iface))
            sock.settimeout(3)
            sock.connect((ip, 443))
            return True
        except Exception:
            continue
        finally:
            if sock is not None:
                sock.close()
    return False


class _BoundHTTPSConnection(http.client.HTTPSConnection):
    """Binds to the physical interface before connecting, so this request's
    route is independent of the system default route. Falls back to normal
    (default-route-following) behavior if no physical interface is found or
    the bind/connect itself fails -- this can only ever ADD a more reliable
    path, never remove the one that already existed before this."""

    def connect(self):
        iface = physical_interface()
        if not iface:
            super().connect()
            return
        try:
            ifindex = socket.if_nametoindex(iface)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, ifindex)
            if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(self.timeout)
            # Resolve via the physical interface first, bypassing the
            # system resolver (which may depend entirely on an unstable
            # tunnel -- see this file's module docstring). connect()ing to
            # a bare IP string skips hostname resolution inside the socket
            # call entirely, so this is immune to that failure mode once we
            # have an IP. server_hostname stays the real hostname either
            # way, for correct TLS SNI/certificate validation.
            target = resolve_via_physical_interface(self.host, iface) or self.host
            sock.connect((target, self.port))
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except OSError:
            super().connect()  # bind/connect on the physical interface failed


class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_BoundHTTPSConnection, req)


opener = urllib.request.build_opener(_BoundHTTPSHandler)
