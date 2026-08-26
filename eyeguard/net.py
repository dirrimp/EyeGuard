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
"""

from __future__ import annotations

import http.client
import socket
import subprocess
import urllib.request

_IP_BOUND_IF = 25


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
            sock.connect((self.host, self.port))
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except OSError:
            super().connect()  # bind/connect on the physical interface failed


class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_BoundHTTPSConnection, req)


opener = urllib.request.build_opener(_BoundHTTPSHandler)
