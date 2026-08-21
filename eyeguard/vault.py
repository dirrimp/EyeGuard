"""EyeGuard vault daemon — the privileged half of the split (light-stack) build.

Runs as root (a LaunchDaemon). Holds the Supabase secret key and performs ALL
network writes: flag + image upload, heartbeat, tamper reports, clean beacons.
The unprivileged *session agent* captures the screen and runs detection, then
sends results here over a local unix socket. So:

  * the key never lives in a process the monitored user runs;
  * the agent's code can be root-owned (run-but-not-edit);
  * killing just the capture agent is caught — the daemon reports screen_ok=false
    (blind alert) when the agent goes silent, and the heartbeat stops entirely
    (gone-dark) only if the daemon dies too.

Protocol: newline-delimited JSON over the socket. Ops: flag / status / tamper /
suspend / resume.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from .uploader import SupabaseUploader

_BASE = Path(__file__).resolve().parent.parent

# ---- peer verification: prove the socket client is the real managed agent ----
# The kernel tells us the connecting PID (unforgeable); from it we read the
# process's executable + launch args (also kernel-provided). We require an exact
# match to the managed agent's invocation, so a home-rolled forger that tries to
# fake "I'm alive and seeing" is rejected. To PASS, you'd have to launch the real
# root-owned launcher — which actually captures the screen. Residual (needs a
# code-signed hardened binary to close): injecting into / debugging the real
# process.
_libc = ctypes.CDLL(None, use_errno=True)
_CTL_KERN, _KERN_ARGMAX, _KERN_PROCARGS2 = 1, 8, 49
_SOL_LOCAL, _LOCAL_PEERPID = 0, 0x002


def _peer_pid(conn: socket.socket) -> int:
    raw = conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID, 4)
    return struct.unpack("i", raw)[0]


def _argmax() -> int:
    val = ctypes.c_int(0)
    sz = ctypes.c_size_t(ctypes.sizeof(val))
    mib = (ctypes.c_int * 2)(_CTL_KERN, _KERN_ARGMAX)
    _libc.sysctl(mib, 2, ctypes.byref(val), ctypes.byref(sz), None, 0)
    return val.value or 262144


def _proc_argv(pid: int) -> tuple[str, list[str]]:
    """(executable_path, argv) for a pid, via sysctl KERN_PROCARGS2."""
    n = _argmax()
    buf = ctypes.create_string_buffer(n)
    sz = ctypes.c_size_t(n)
    mib = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROCARGS2, pid)
    if _libc.sysctl(mib, 3, buf, ctypes.byref(sz), None, 0) != 0:
        raise OSError("sysctl KERN_PROCARGS2 failed")
    data = buf.raw[:sz.value]
    argc = struct.unpack("i", data[:4])[0]
    parts = data[4:].split(b"\x00")
    exec_path = parts[0].decode("utf-8", "replace")
    i = 1
    while i < len(parts) and parts[i] == b"":  # padding after exec_path
        i += 1
    argv = []
    while i < len(parts) and len(argv) < argc:
        argv.append(parts[i].decode("utf-8", "replace"))
        i += 1
    return exec_path, argv


_IOKit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
_CF = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")

_IOServiceInterestCallback = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)

_IOKit.IORegisterForSystemPower.restype = ctypes.c_uint32
_IOKit.IORegisterForSystemPower.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    _IOServiceInterestCallback, ctypes.POINTER(ctypes.c_uint32)]
_IOKit.IONotificationPortGetRunLoopSource.restype = ctypes.c_void_p
_IOKit.IONotificationPortGetRunLoopSource.argtypes = [ctypes.c_void_p]
_IOKit.IOAllowPowerChange.restype = ctypes.c_int
_IOKit.IOAllowPowerChange.argtypes = [ctypes.c_uint32, ctypes.c_long]

_CF.CFRunLoopGetCurrent.restype = ctypes.c_void_p
_CF.CFRunLoopAddSource.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_CF.CFRunLoopRun.restype = None
_kCFRunLoopDefaultMode = ctypes.c_void_p.in_dll(_CF, "kCFRunLoopDefaultMode")

# IOMessage.h: iokit_common_msg(x) = 0xe0000000 | x
_K_CAN_SLEEP = 0xE0000270
_K_WILL_SLEEP = 0xE0000280
_K_WILL_NOT_SLEEP = 0xE0000290
_K_HAS_POWERED_ON = 0xE0000300
_K_WILL_POWER_OFF = 0xE0000250  # real shutdown, not sleep
_K_WILL_RESTART = 0xE0000310

# How long the agent's OWN self-reported screen_ok=false may persist before
# VaultDaemon._status() forwards it upstream as a real blind condition.
# Confirmed live (2026-08-20 23:37-23:39): a post-wake black/frozen probe
# self-resolved in ~2m43s with no real problem. Comfortably longer than that.
SCREEN_OK_GRACE_SECONDS = 180


class SleepWatcher:
    """Root-level sleep/wake via IOKit, so the vault daemon reacts directly --
    no agent, no socket round-trip. A LaunchDaemon has no GUI session for
    NSWorkspace's WillSleep (why the agent used that instead originally), but
    IORegisterForSystemPower is the kernel-level equivalent, and crucially the
    daemon can hold up the actual sleep transition (via IOAllowPowerChange)
    until send_heartbeat() has genuinely returned -- closing the lid-close
    race for good regardless of how short that trigger's grace period is,
    unlike the old agent-socket-daemon relay it replaces as the primary path."""

    def __init__(self, uploader: SupabaseUploader):
        self.uploader = uploader
        self._root_port = 0
        self._callback = None  # kept alive so ctypes can't GC the trampoline

    def _handle(self, refcon, service, message_type, message_arg):
        # Logged unconditionally (not just on failure) -- without this line,
        # "suspend() ran and quietly succeeded" and "the callback never fired
        # at all" are indistinguishable from the logs alone, which is exactly
        # the gap that made a real gone-dark alert (2026-08-17, lid-close at
        # ~00:07) undiagnosable after the fact: uploader.py only logs
        # heartbeat FAILURES, so a silent success looks identical to a silent
        # non-event. Timestamped so it can actually be correlated to when an
        # alert email landed, unlike every other line in this log before this.
        ts = datetime.now().isoformat()
        try:
            if message_type == _K_WILL_SLEEP:
                print(f"[vault] {ts} IOKit: WillSleep -- calling suspend()",
                      flush=True)
                try:
                    self.uploader.suspend()
                except Exception:
                    pass
                _IOKit.IOAllowPowerChange(self._root_port, message_arg)
            elif message_type == _K_CAN_SLEEP:
                _IOKit.IOAllowPowerChange(self._root_port, message_arg)
            elif message_type == _K_WILL_NOT_SLEEP:
                # Sleep was requested then cancelled/aborted (e.g. vetoed by
                # another app, or the system backed out) -- WillSleep already
                # ran and set _suspended=True, but since the Mac never
                # actually slept, there's no corresponding HasPoweredOn to
                # clear it. Without this, _suspended stays stuck True
                # indefinitely: every future heartbeat would keep posting
                # 'clean_shutdown' while the Mac is genuinely awake and in
                # use, silently disabling the gone-dark alert for real. Treat
                # it the same as a wake -- back to alive.
                print(f"[vault] {ts} IOKit: WillNotSleep (sleep cancelled) "
                      f"-- calling resume()", flush=True)
                try:
                    self.uploader.resume()
                except Exception:
                    pass
            elif message_type == _K_HAS_POWERED_ON:
                print(f"[vault] {ts} IOKit: HasPoweredOn -- calling resume()",
                      flush=True)
                try:
                    self.uploader.resume()
                except Exception:
                    pass
            elif message_type in (_K_WILL_POWER_OFF, _K_WILL_RESTART):
                # A real shutdown/restart is a DIFFERENT IOKit message family
                # from sleep (WillSleep never fires for this) -- added after
                # noticing this daemon never registered for it at all, so an
                # actual power-off/restart got zero coverage from any of the
                # sleep-specific work tonight, falling back entirely to the
                # old agent-side NSWorkspace+socket path (the original
                # race-prone mechanism). NOT verified live (would require an
                # actual shutdown to trigger, which isn't something to force
                # just to test) -- Apple's IORegisterForSystemPower docs
                # focus on sleep/wake, so whether these two message types are
                # actually delivered through this same registration is
                # unconfirmed. Harmless if they never fire; real coverage if
                # they do. Deliberately NOT a generic SIGTERM handler instead
                # -- that would conflate "Dad legitimately stopped
                # monitoring" with "the Mac is shutting down" and silently
                # defeat gone-dark's whole purpose as a tamper check (see
                # suspend()'s own docstring: a manual stop must still alert).
                kind = "WillPowerOff" if message_type == _K_WILL_POWER_OFF \
                    else "WillRestart"
                print(f"[vault] {ts} IOKit: {kind} -- calling suspend()",
                      flush=True)
                try:
                    self.uploader.suspend()
                except Exception:
                    pass
                _IOKit.IOAllowPowerChange(self._root_port, message_arg)
        except Exception:
            pass  # a bad power notification must never kill this thread

    def run(self):
        """Blocks forever running a CFRunLoop -- call on its own daemon thread."""
        notify_port = ctypes.c_void_p()
        notifier = ctypes.c_uint32()
        self._callback = _IOServiceInterestCallback(self._handle)
        self._root_port = _IOKit.IORegisterForSystemPower(
            None, ctypes.byref(notify_port), self._callback, ctypes.byref(notifier))
        if not self._root_port:
            print("[vault] IORegisterForSystemPower failed -- sleep beacon "
                  "falls back to the agent's socket path only", flush=True)
            return
        rl_source = _IOKit.IONotificationPortGetRunLoopSource(notify_port)
        _CF.CFRunLoopAddSource(_CF.CFRunLoopGetCurrent(), rl_source,
                                _kCFRunLoopDefaultMode)
        print("[vault] IOKit sleep/wake watcher active", flush=True)
        _CF.CFRunLoopRun()


class VaultDaemon:
    def __init__(self, uploader: SupabaseUploader, socket_path: str,
                 agent_timeout: int = 90, verify_peer: bool = True,
                 expected_launcher: str | None = None):
        self.uploader = uploader
        self.socket_path = socket_path
        self.agent_timeout = agent_timeout
        self.verify_peer = verify_peer
        # The managed agent must be launched as `<python> <base>/run_agent.py`.
        # Running via an absolute launcher path means the code dir wins sys.path,
        # so PYTHONPATH/cwd can't be used to shadow in fake code.
        self.expected_exec = os.path.realpath(sys.executable)
        self.expected_launcher = os.path.realpath(
            expected_launcher or str(_BASE / "run_agent.py"))
        # Starting this at 0.0 (epoch) meant the FIRST heartbeat after every
        # daemon restart -- which fires immediately, before the agent has any
        # chance to reconnect -- computed staleness against Jan 1 1970 and
        # forced screen_ok=False into it. Confirmed live (2026-08-19 22:09:41,
        # via this daemon's own new transition logging): "no contact for
        # 1787191782s" -- ~56 years -- tripped a real blind alert 22s after a
        # routine restart, 53s before the agent had even reconnected. Starting
        # this at "now" instead gives the agent the same normal agent_timeout
        # grace window a fresh restart should get, matching how
        # recently_resumed() already protects the equivalent wake-from-sleep
        # case -- this was the cold-start version of the same bug.
        self._last_agent = time.time()
        self._last_status = {"screen_ok": True, "frames_analyzed": 0,
                             "detector_ok": True}
        self._blind_since: float | None = None  # when the agent's own
                                                   # screen_ok=false report started
        self._lock = threading.Lock()
        self._reported_blind = False  # last value WE sent upstream, for edge logging
        # The daemon's heartbeat carries the agent's last-known screen health,
        # but only while the agent is fresh — a silent agent reads as blind.
        uploader.set_status_provider(self._status)

    def _status(self) -> dict:
        with self._lock:
            fresh = (time.time() - self._last_agent) < self.agent_timeout
            last_agent = self._last_agent
            blind_since = self._blind_since
            st = dict(self._last_status)
        # A just-woken agent hasn't had a chance to reconnect yet -- its
        # staleness right at wake reflects the sleep duration, not a real
        # blind condition. See SupabaseUploader.recently_resumed()'s
        # docstring for the live-confirmed failure mode this closes.
        agent_silent = not fresh and not self.uploader.recently_resumed()
        cause = None
        if agent_silent:
            st["screen_ok"] = False  # capture agent went silent -> blind
            cause = "silent"
        elif st.get("screen_ok") is False:
            # The agent is FRESH (actively reporting) but self-reported
            # screen_ok=false itself -- e.g. its own frozen/black-screen probe
            # tripped, often right after a real wake while the display is
            # still initializing. Confirmed live (2026-08-20 23:37-23:39) this
            # self-resolves in ~2-3 minutes without ever being a real problem,
            # same as the wake-grace and cold-start cases already fixed --
            # just triggered from the agent's own report instead of this
            # daemon's staleness inference. Give it SCREEN_OK_GRACE_SECONDS to
            # clear before forwarding it upstream as a real blind condition.
            if blind_since is not None and time.time() - blind_since < SCREEN_OK_GRACE_SECONDS:
                st["screen_ok"] = True
            else:
                cause = "self-reported"
        # Logged only on the transition, not every call (this runs on every
        # heartbeat) -- a real blind alert (2026-08-19, ~19:34/20:20) had NO
        # corresponding sleep/wake event and left zero trace anywhere: the
        # agent's own plist defines no stdout/stderr log path (its print()
        # diagnostics go nowhere), and this daemon never recorded WHY it
        # decided the agent was silent. This closes that gap -- the log now
        # distinguishes "daemon's own timeout tripped" (agent_silent -- no
        # contact for a non-sleep reason, e.g. the detection loop stalling on
        # a slow inference/OCR cycle) from "agent self-reported blind" (a
        # real capture/frozen/permission problem that outlasted the grace
        # window), instead of one misleading "no contact" message for both.
        will_report_blind = bool(st.get("screen_ok") is False)
        if will_report_blind != self._reported_blind:
            ts = datetime.now().isoformat()
            if will_report_blind and cause == "silent":
                idle = time.time() - last_agent
                print(f"[vault] {ts} agent presumed blind: no contact for "
                      f"{idle:.0f}s (agent_timeout={self.agent_timeout}s)",
                      flush=True)
            elif will_report_blind:
                idle = time.time() - blind_since if blind_since else 0.0
                print(f"[vault] {ts} agent self-reported blind for "
                      f"{idle:.0f}s (grace={SCREEN_OK_GRACE_SECONDS}s) "
                      f"-- forwarding as real", flush=True)
            else:
                print(f"[vault] {ts} agent no longer presumed blind",
                      flush=True)
            self._reported_blind = will_report_blind
        return st

    def _handle(self, msg: dict):
        op = msg.get("op")
        if op == "flag":
            rec = msg.get("record")
            if isinstance(rec, dict):
                self.uploader.enqueue(rec)
        elif op == "tamper":
            self.uploader.report_tamper(str(msg.get("detail", "unknown")))
        elif op == "suspend":
            self.uploader.suspend()
        elif op == "resume":
            self.uploader.resume()
        elif op == "status":
            s = msg.get("status") or {}
            with self._lock:
                self._last_agent = time.time()
                if "screen_ok" in s:
                    ok = bool(s["screen_ok"])
                    self._last_status["screen_ok"] = ok
                    if not ok:
                        if self._blind_since is None:
                            self._blind_since = time.time()
                    else:
                        self._blind_since = None
                if "frames_analyzed" in s:
                    self._last_status["frames_analyzed"] = int(s["frames_analyzed"])
                # Previously silently dropped -- the agent has always sent this
                # (menubar.py's status provider includes it), but this daemon
                # never read it, so eg_check_gone_dark()'s self-test-failure
                # check (part c: "detector broken") could never fire in split
                # mode -- device_status.detector_ok never got a real value.
                if "detector_ok" in s:
                    self._last_status["detector_ok"] = bool(s["detector_ok"])

    def serve(self):
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.socket_path)
        # The session agent (a different, unprivileged user) must be able to
        # connect. It can only ADD detections — never delete or forge a beacon —
        # so an open socket is safe (worst case is self-incriminating noise).
        os.chmod(self.socket_path, 0o666)
        srv.listen(16)
        self.uploader.start()  # heartbeat + upload worker
        # Direct kernel-level sleep/wake -- see SleepWatcher docstring. The
        # agent's own suspend()/resume() calls over the socket still happen
        # too; both paths call the same idempotent uploader methods, so this
        # is pure redundancy, not a replacement that can race the old one.
        threading.Thread(target=SleepWatcher(self.uploader).run,
                         daemon=True).start()
        print(f"[vault] listening on {self.socket_path}", flush=True)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._client, args=(conn,),
                             daemon=True).start()

    def _verify(self, conn: socket.socket) -> bool:
        """True iff the connecting process is the real managed agent."""
        if not self.verify_peer:
            return True
        try:
            exec_path, argv = _proc_argv(_peer_pid(conn))
        except Exception:
            return False
        # The real gate: the process was launched as `<python> <launcher>` where
        # <launcher> is the root-owned run_agent.py. Because that's an absolute
        # script path, its directory wins sys.path — so it loads the real
        # root-owned code, not a PYTHONPATH/cwd-shadowed copy. (We don't pin the
        # exact python binary: framework-python's launcher stub differs from the
        # running Mach-O, and any python running the real launcher runs the real
        # agent anyway.)
        return (len(argv) == 2
                and "python" in os.path.basename(exec_path).lower()
                and os.path.realpath(argv[1]) == self.expected_launcher)

    def _client(self, conn: socket.socket):
        if not self._verify(conn):
            print("[vault] rejected unverified peer", flush=True)
            conn.close()
            return
        buf = b""
        try:
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                buf += data
                if len(buf) > 1_000_000:  # a real message is tiny; drop floods
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        try:
                            msg = json.loads(line)
                            self._handle(msg)
                            if msg.get("op") == "suspend":
                                # Ack only after suspend's own send_heartbeat()
                                # call above has actually returned, so the
                                # client's blocking recv() genuinely means the
                                # Supabase post completed (or was attempted).
                                conn.sendall(b"ack\n")
                        except Exception:
                            pass  # never let one bad message kill the daemon
        finally:
            conn.close()


def build_uploader_from_config(cfg: dict) -> SupabaseUploader:
    sb = cfg.get("supabase", {})
    secret_path = Path(sb.get("secret_file", ".supabase_secret"))
    if not secret_path.is_absolute():
        secret_path = _BASE / secret_path
    secret = secret_path.read_text().strip()
    pending = Path(sb.get("pending_file", "pending_uploads.jsonl"))
    if not pending.is_absolute():
        pending = _BASE / pending
    return SupabaseUploader(url=sb["url"], secret=secret,
                            pending_path=str(pending),
                            retry_seconds=int(sb.get("retry_seconds", 60)),
                            heartbeat=bool(sb.get("heartbeat", True)),
                            publishable_key=sb.get("publishable_key"))


def main():
    import argparse
    from .main import load_config
    p = argparse.ArgumentParser(prog="eyeguard-vault")
    p.add_argument("--config", default=str(_BASE / "config.yaml"))
    args = p.parse_args()
    cfg = load_config(args.config)
    sb = cfg.get("supabase", {})
    sock = sb.get("socket_path", "/var/run/eyeguard.sock")
    uploader = build_uploader_from_config(cfg)
    VaultDaemon(uploader, sock,
                agent_timeout=int(sb.get("agent_timeout", 90)),
                verify_peer=bool(sb.get("verify_peer", True))).serve()


if __name__ == "__main__":
    main()
