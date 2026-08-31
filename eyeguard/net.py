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
