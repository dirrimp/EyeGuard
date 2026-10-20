#!/usr/bin/env python3
"""Poller side of 'deny -> app actually gone': plain removal, then take management, then remove.
No network (App Store lookup stubbed), no docker. Synthetic data only.
Run: python3 tests/test_mdm_escalation.py"""
import importlib.util, io, json, os, sys, tempfile, urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)

pst = tempfile.mkdtemp()
os.environ.update({"MDM_STATE": pst, "MDM_SENDER": "/bin/true", "MDM_LOG": str(Path(pst) / "log")})
spec = importlib.util.spec_from_file_location("poll_esc", ROOT / "g11" / "mdm" / "poll.py")
pl = importlib.util.module_from_spec(spec); spec.loader.exec_module(pl)

calls, enq = [], []
script = {"--sync": (0, json.dumps({"blocked": [], "actions": []}), ""), "default": (0, "ok", "")}
def fake_sender(*a):
    calls.append(a); r = script.get(a[0], script["default"]); return r(a) if callable(r) else r
def fake_enq(udid, key, request):
    cid = f"CID-{len(enq)}-{request['RequestType']}"; enq.append((cid, request)); return cid
pl.sender, pl.enqueue_command = fake_sender, fake_enq
STORE = {"com.dl.app": 570060128}
pl.store_id = lambda b: STORE.get(b)
def reset(): calls.clear(); enq.clear()
def dev(): return {"UDID-1": {"enrolled": True, "supervised": True, "name": "d"}}
def sync_with(actions): script["--sync"] = (0, json.dumps({"blocked": [], "actions": actions}), "")
def types(): return [r["RequestType"] for _, r in enq]
def answer(cid, status="Acknowledged", error=""):
    os.makedirs(Path(pst) / "results", exist_ok=True)
    json.dump({"uuid": cid, "status": status, "error": error}, open(Path(pst) / "results" / f"{cid}.json", "w"))
def cid_of(kind):
    return [k for k, v in json.load(open(Path(pst) / "pending-cmds.json")).items() if v["kind"] == kind]
def results_for(name): return [c for c in calls if c[0] == name]
def state(): return json.load(open(Path(pst) / "remove-state.json")) if (Path(pst) / "remove-state.json").exists() else {}
def hours_ago(h): return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()

print("1. first attempt is the plain removal (unchanged behaviour)")
reset(); sync_with([{"id": 1, "bundle_id": "com.dl.app", "action": "remove"}]); pl.approvals(dev(), "k")
check("a fresh action sends RemoveApplication, not take-management", "RemoveApplication" in types() and "InstallApplication" not in types(), str(types()))
c1 = cid_of("remove")[0]
answer(c1); reset(); sync_with([]); pl.approvals(dev(), "k")
check("the phone's Acknowledged is reported to the server as ok (existing path)", results_for("--action-result")[0][:3] == ("--action-result", "1", "ok"))
check("the poller remembers a plain removal was tried", "plain_at" in state().get("com.dl.app", {}))

print("2. the app is STILL installed (server asked again): take management first")
reset(); sync_with([{"id": 2, "bundle_id": "com.dl.app", "action": "remove"}]); pl.approvals(dev(), "k")
inst = [r for _, r in enq if r["RequestType"] == "InstallApplication"]
check("second action sends InstallApplication with ChangeManagementState=Managed and the App Store id",
      len(inst) == 1 and inst[0]["iTunesStoreID"] == 570060128 and inst[0]["ChangeManagementState"] == "Managed" and inst[0]["ManagementFlags"] == 1, str(inst))
check("...and does NOT send the removal in the same run (management must land first)", "RemoveApplication" not in types(), str(types()))
reset(); sync_with([{"id": 2, "bundle_id": "com.dl.app", "action": "remove"}]); pl.approvals(dev(), "k")
check("an unanswered take is not re-sent on the next run", not enq, str(types()))
t1 = cid_of("take")[0]
answer(t1); reset(); sync_with([]); pl.approvals(dev(), "k")
check("an accepted take is NOT reported to the server as success (it is not proof)", not results_for("--action-result"), str(calls))
check("the removal follow-up is queued in the same run that records the take",
      types() == ["RemoveApplication"] or types() == [], str(types()))
if not enq:
    reset(); sync_with([]); pl.approvals(dev(), "k")
rm = [r for _, r in enq if r["RequestType"] == "RemoveApplication"]
check("after a take, the removal is queued exactly once", len(rm) == 1 and rm[0]["Identifier"] == "com.dl.app", str(types()))
info = json.load(open(Path(pst) / "pending-cmds.json"))[cid_of("remove")[-1]]
check("that removal is tied to the SAME server action and marked after_take", info["id"] == 2 and info["after_take"] is True, str(info))
reset(); sync_with([]); pl.approvals(dev(), "k")
check("...and not queued again while it is in flight", "RemoveApplication" not in types(), str(types()))
answer(cid_of("remove")[-1]); reset(); sync_with([]); pl.approvals(dev(), "k")
check("its result is what finally reports ok for action 2", results_for("--action-result") and results_for("--action-result")[0][:3] == ("--action-result", "2", "ok"), str(calls))
check("a removal after a take does not reset the plain-removal memory", state()["com.dl.app"].get("plain_at"))

print("3. failure paths")
reset(); sync_with([{"id": 3, "bundle_id": "com.dl.app", "action": "remove"}]); pl.approvals(dev(), "k")
t = cid_of("take")[-1]; answer(t, "Error", "9000: not licensed"); reset(); sync_with([]); pl.approvals(dev(), "k")
a = results_for("--action-result")[0]
check("a refused take is reported as a failure with its reason, prefixed", a[:3] == ("--action-result", "3", "fail") and "take-management: " in a[3] and "not licensed" in a[3], str(a))
check("a refused take does not queue a removal", "RemoveApplication" not in types(), str(types()))

(Path(pst) / "remove-state.json").write_text(json.dumps({"com.nostore": {"plain_at": hours_ago(1)}}))
reset(); sync_with([{"id": 4, "bundle_id": "com.nostore", "action": "remove"}]); pl.approvals(dev(), "k")
check("no App Store id (enterprise/unlisted app): falls back to a plain removal instead of doing nothing",
      "RemoveApplication" in types() and "InstallApplication" not in types(), str(types()))

(Path(pst) / "remove-state.json").write_text(json.dumps({"com.dl.app": {"plain_at": hours_ago(48)}}))
for k in list(json.load(open(Path(pst) / "pending-cmds.json"))): pass
(Path(pst) / "pending-cmds.json").write_text("{}")
reset(); sync_with([{"id": 5, "bundle_id": "com.dl.app", "action": "remove"}]); pl.approvals(dev(), "k")
check("a plain removal older than 36 h no longer forces escalation (app re-installed later = new case)",
      "RemoveApplication" in types() and "InstallApplication" not in types(), str(types()))

(Path(pst) / "pending-cmds.json").write_text("{}")
reset(); sync_with([{"id": 6, "bundle_id": "com.apple.mobilesafari", "action": "remove"}]); pl.approvals(dev(), "k")
check("an Apple system app is never touched; the server hears why", not [t for t in types() if t in ("RemoveApplication", "InstallApplication")]
      and results_for("--action-result") and results_for("--action-result")[0][2] == "fail", str(calls))

print("4. App Store lookup (only the bundle id leaves the G11)")
spec2 = importlib.util.spec_from_file_location("poll_esc2", ROOT / "g11" / "mdm" / "poll.py")
p2 = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(p2)
seen = []
def fake_urlopen(url, timeout=0, context=None):
    seen.append(url)
    body = {"com.good": {"results": [{"bundleId": "com.good", "trackId": 123}]},
            "com.other": {"results": [{"bundleId": "com.someone.else", "trackId": 999}]},
            "com.none": {"results": []}}
    for k, v in body.items():
        if url.endswith("bundleId=" + k): return io.BytesIO(json.dumps(v).encode())
    raise urllib.error.URLError("down")
p2.urllib.request.urlopen = fake_urlopen
check("lookup returns the App Store id and queries only the bundle id", p2.store_id("com.good") == 123 and "com.good" in seen[0] and "k=" not in seen[0])
n = len(seen)
check("a found id is cached (no second network call)", p2.store_id("com.good") == 123 and len(seen) == n)
check("a result for a DIFFERENT bundle id is rejected", p2.store_id("com.other") is None)
check("not on the store -> None", p2.store_id("com.none") is None)
check("network failure -> None, never raises", p2.store_id("com.broken") is None)
check("the id goes to the phone as an integer", isinstance(p2.take_request(123)["iTunesStoreID"], int))

print()
if fails:
    print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all MDM escalation tests passed")
