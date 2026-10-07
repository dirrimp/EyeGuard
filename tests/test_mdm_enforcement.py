#!/usr/bin/env python3
"""G11-side tests for the approve/deny system: hook.py snapshots + command results,
eg_report.py snapshot routing and one-shot commands, poll.py enforcement
(removals, supervision-gated block profile, result reporting, housekeeping).
No network, no docker. Synthetic data only. Run: python3 tests/test_mdm_enforcement.py"""
import base64, importlib.util, json, os, plistlib, sys, tempfile, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok: fails.append(name)
def load_module(path, name, env):
    for k, v in env.items(): os.environ[k] = v
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
def ack(pl, uuid_="U-1", status=None):
    ev = {"udid": "UDID-1", "raw_payload": base64.b64encode(plistlib.dumps(pl)).decode(), "command_uuid": uuid_}
    if status: ev["status"] = status
    return ev
def outbox(st):
    d = Path(st) / "outbox"
    return [json.load(open(p)) for p in sorted(d.glob("*.json"))] if d.is_dir() else []
APPS = [{"Identifier": "com.a", "Name": "A", "ShortVersion": "1"}, {"Identifier": "com.b", "Name": "B"}]

print("1. hook.py")
st = tempfile.mkdtemp()
h = load_module(str(ROOT / "g11/mdm/hook.py"), "hook_e", {"HOOK_STATE": st})
h.handle_checkin({"udid": "UDID-1", "message_type": "Authenticate"})
h.handle_ack(ack({"Status": "Acknowledged", "InstalledApplicationList": APPS}))
ev = outbox(st)
check("an app list becomes exactly ONE app_snapshot event", len(ev) == 1 and ev[0]["type"] == "app_snapshot", str(ev))
check("snapshot carries bundle_id/name/version for every app",
      ev[0]["apps"] == [{"bundle_id": "com.a", "name": "A", "version": "1"}, {"bundle_id": "com.b", "name": "B", "version": ""}])
check("supervision unknown before it has been asked", ev[0]["supervised"] is None)
h.handle_ack(ack({"Status": "Acknowledged", "InstalledApplicationList": APPS + [{"Identifier": "com.c", "Name": "C"}]}))
check("a later list with a new app still emits only snapshots (the server diffs)",
      all(e["type"] == "app_snapshot" for e in outbox(st)) and len(outbox(st)) == 2)
check("no per-device baseline file is kept on the G11 any more", not list(Path(st).glob("apps-*.json")))
h.handle_ack(ack({"Status": "Acknowledged", "InstalledApplicationList": []}))
check("an EMPTY app list is never forwarded", len(outbox(st)) == 2)
h.handle_ack(ack({"Status": "Acknowledged", "QueryResponses": {"IsSupervised": True}}))
check("DeviceInformation ack records supervision", json.load(open(Path(st) / "devices.json"))["UDID-1"]["supervised"] is True)
h.handle_ack(ack({"Status": "Acknowledged", "InstalledApplicationList": APPS}))
check("next snapshot reports supervised=true", outbox(st)[-1]["supervised"] is True)

json.dump({"CMD-REMOVE": {"kind": "remove", "id": 7, "at": "x"}}, open(Path(st) / "pending-cmds.json", "w"))
h.handle_ack(ack({"Status": "Error", "ErrorChain": [{"ErrorCode": 4000, "USEnglishDescription": "App is not managed"}]}, "CMD-REMOVE"))
res = json.load(open(Path(st) / "results" / "CMD-REMOVE.json"))
check("outcome of a poller-sent command is recorded with the phone's error",
      res["status"] == "Error" and "4000" in res["error"] and "not managed" in res["error"], str(res))
h.handle_ack(ack({"Status": "Acknowledged"}, "SOMEONE-ELSES"))
check("results are recorded ONLY for commands the poller tracked (no path tricks)",
      not (Path(st) / "results" / "SOMEONE-ELSES.json").exists())
h.handle_ack(ack({"Status": "NotNow"}, "CMD-REMOVE"))
check("NotNow is not an outcome", json.load(open(Path(st) / "results" / "CMD-REMOVE.json"))["status"] == "Error")
h.handle_ack(ack({"Status": "Acknowledged"}, "../../etc/x"))
check("a hostile command uuid writes nothing outside results/", not list(Path(st).glob("../*etc*")))

print("2. eg_report.py")
cdir = tempfile.mkdtemp(); conf = os.path.join(cdir, "c.json")
json.dump({"supabase_url": "https://x.invalid", "anon_key": "anon", "device_token": "t" * 64}, open(conf, "w")); os.chmod(conf, 0o600)
rep = load_module(str(ROOT / "g11/eg_report.py"), "rep_e", {"EG_REPORT_CONF": conf, "EG_REPORT_QUEUE": os.path.join(cdir, "q")})
seen = []; mode = {"code": 200, "body": '{"blocked":[],"actions":[]}'}
def fake_open(req, timeout=0):
    seen.append((req.full_url.rsplit("/", 1)[-1], json.loads(req.data)))
    if mode["code"] != 200: raise rep.urllib.error.HTTPError(req.full_url, mode["code"], "x", {}, None)
    class R:
        def __enter__(s): return s
        def __exit__(s, *a): pass
        def read(s): return mode["body"].encode()
        status = 200
    return R()
rep.urllib.request.urlopen = fake_open
snap = {"type": "app_snapshot", "detected_at": "2026-10-07T12:00:00Z", "apps": [{"bundle_id": "com.a", "name": "A"}]}
rep.validate(snap); check("valid app_snapshot passes validation", True)
for bad, why in (({**snap, "apps": []}, "empty"), ({**snap, "apps": [{"name": "x"}]}, "no bundle_id"), ({**snap, "apps": "x"}, "not a list")):
    try: rep.validate(bad); ok = False
    except ValueError: ok = True
    check(f"app_snapshot rejected: {why}", ok)
seen.clear(); rep.post(rep.load_conf(), snap)
check("snapshots go to eg_mdm_snapshot as p_snapshot",
      seen[0][0] == "eg_mdm_snapshot" and seen[0][1]["p_snapshot"]["apps"][0]["bundle_id"] == "com.a" and seen[0][1]["p_token"] == "t" * 64)
seen.clear(); rep.post(rep.load_conf(), {"type": "device_unreachable", "detected_at": "2026-10-07T12:00:00Z"})
check("other events still go to eg_report_mdm_event", seen[0][0] == "eg_report_mdm_event")
seen.clear(); rc = rep.main(["x", "--sync"])
check("--sync -> exit 0 and posts to eg_mdm_sync", rc == 0 and seen[0][0] == "eg_mdm_sync")
seen.clear(); rc = rep.main(["x", "--action-result", "7", "fail", "NotManaged"])
check("--action-result maps id/ok/detail",
      rc == 0 and seen[0][1]["p_id"] == 7 and seen[0][1]["p_ok"] is False and seen[0][1]["p_detail"] == "NotManaged")
seen.clear(); rc = rep.main(["x", "--block-result", "ok", "3", "applied"])
check("--block-result maps ok/count/detail", rc == 0 and seen[0][1]["p_ok"] is True and seen[0][1]["p_count"] == 3)
check("bad arguments -> exit 2", rep.main(["x", "--action-result", "abc", "ok"]) == 2 and rep.main(["x", "--block-result", "maybe", "1"]) == 2)
qd = Path(rep.QDIR); [f.unlink() for f in qd.glob("*.json")] if qd.is_dir() else None
mode["code"] = 503
for i in range(4):
    rep.main(["x", json.dumps({**snap, "detected_at": f"2026-10-07T12:0{i}:00Z"})])
rep.main(["x", json.dumps({"type": "device_unreachable", "detected_at": "2026-10-07T12:09:00Z"})])
q = [json.load(open(qd / f)) for f in rep.queued()]
check("while the server is down only the NEWEST snapshot stays queued; other events are kept",
      sorted(e["type"] for e in q) == ["app_snapshot", "device_unreachable"]
      and [e for e in q if e["type"] == "app_snapshot"][0]["detected_at"].endswith("12:03:00Z"), str(q))
[f.unlink() for f in qd.glob("*.json")]
mode["code"] = 401; check("401 -> exit 3", rep.main(["x", "--sync"]) == 3)
mode["code"] = 503; check("503 -> exit 4", rep.main(["x", "--sync"]) == 4)
check("one-shot commands are never queued", not os.path.isdir(rep.QDIR) or not rep.queued())

print("3. poll.py enforcement")
pst = tempfile.mkdtemp()
pl = load_module(str(ROOT / "g11/mdm/poll.py"), "poll_e",
                 {"MDM_STATE": pst, "MDM_SENDER": "/bin/true", "MDM_LOG": str(Path(pst) / "log")})
calls, enq = [], []
script = {"--sync": (0, json.dumps({"blocked": [], "actions": []}), ""), "default": (0, "ok", "")}
def fake_sender(*a):
    calls.append(a); r = script.get(a[0], script["default"]); return r(a) if callable(r) else r
def fake_enq(udid, key, request):
    cid = f"CID-{len(enq)}"; enq.append((cid, request)); return cid
pl.sender, pl.enqueue_command = fake_sender, fake_enq
def reset(): calls.clear(); enq.clear()
def dev(sup): return {"UDID-1": {"enrolled": True, "supervised": sup, "name": "d"}}
def args_of(name): return [c for c in calls if c[0] == name]

pl.approvals({}, "k"); check("no enrolled phone -> does nothing", not calls and not enq)

reset(); script["--sync"] = (0, json.dumps({"blocked": [], "actions": [{"id": 7, "bundle_id": "com.x", "action": "remove"}]}), "")
pl.approvals(dev(True), "k")
rm = [r for _, r in enq if r["RequestType"] == "RemoveApplication"]
check("a queued removal becomes an MDM RemoveApplication for that bundle id", rm and rm[0]["Identifier"] == "com.x")
check("poller asks the phone whether it is supervised", any(r["RequestType"] == "DeviceInformation" for _, r in enq))
reset(); pl.approvals(dev(True), "k")
check("...but only once an hour, not every 5-minute run", not [1 for _, r in enq if r["RequestType"] == "DeviceInformation"])
check("an unanswered removal is not re-sent within 20 minutes", not [1 for _, r in enq if r["RequestType"] == "RemoveApplication"])

reset(); cid = json.load(open(Path(pst) / "pending-cmds.json")); cid = [k for k, v in cid.items() if v["kind"] == "remove"][0]
os.makedirs(Path(pst) / "results", exist_ok=True)
json.dump({"uuid": cid, "status": "Error", "error": "4000: not managed"}, open(Path(pst) / "results" / "r.json", "w"))
script["--action-result"] = (4, "", "transient")
pl.approvals(dev(True), "k")
check("failed report to the server keeps the result for the next run", (Path(pst) / "results" / "r.json").exists())
script["--action-result"] = (0, "ok", "")
pl.approvals(dev(True), "k")
a = args_of("--action-result")[-1]
check("phone's failure is reported to the server with its reason", a[:3] == ("--action-result", "7", "fail") and "not managed" in a[3], str(a))
check("reported result is cleaned up", not (Path(pst) / "results" / "r.json").exists() and cid not in json.load(open(Path(pst) / "pending-cmds.json")))

def blocked_run(sup, blocked, **kw):
    reset(); script["--sync"] = (0, json.dumps({"blocked": blocked, "actions": []}), ""); pl.approvals(dev(sup), "k")
for f in ("block-state.json",): (Path(pst) / f).unlink(missing_ok=True)
blocked_run(False, ["com.bad"])
check("UNSUPERVISED phone: no profile pushed, failure reported honestly",
      not [1 for _, r in enq if r["RequestType"] == "InstallProfile"]
      and args_of("--block-result")[0][1] == "fail" and "not supervised" in args_of("--block-result")[0][3])
blocked_run(None, ["com.bad"])
check("supervision UNKNOWN: not pushed, says so", not [1 for _, r in enq if r["RequestType"] == "InstallProfile"] and "unknown" in args_of("--block-result")[0][3])
blocked_run(True, ["com.bad", "com.worse", "x; rm -rf /", "../evil", ""])
ip = [r for _, r in enq if r["RequestType"] == "InstallProfile"]
check("SUPERVISED phone: block profile pushed", len(ip) == 1)
prof = plistlib.loads(ip[0]["Payload"]); inner = prof["PayloadContent"][0]
check("profile blocks exactly the valid denied ids (hostile ids dropped), both key names",
      inner["blockedAppBundleIDs"] == ["com.bad", "com.worse"] and inner["blacklistedAppBundleIDs"] == ["com.bad", "com.worse"]
      and inner["PayloadType"] == "com.apple.applicationaccess", str(inner))
p2 = plistlib.loads(pl.block_profile(["com.other"]))
check("profile has stable identifiers so a re-push UPDATES rather than stacks",
      prof["PayloadIdentifier"] == p2["PayloadIdentifier"] == "me.orthanc.eyeguard.blocklist"
      and prof["PayloadUUID"] == p2["PayloadUUID"]
      and prof["PayloadContent"][0]["PayloadUUID"] == p2["PayloadContent"][0]["PayloadUUID"])
bc = [k for k, v in json.load(open(Path(pst) / "pending-cmds.json")).items() if v["kind"] == "block"][0]
json.dump({"uuid": bc, "status": "Acknowledged", "error": ""}, open(Path(pst) / "results" / "b.json", "w"))
reset(); script["--sync"] = (0, json.dumps({"blocked": ["com.bad", "com.worse"], "actions": []}), ""); pl.approvals(dev(True), "k")
check("phone's OK is reported (--block-result ok 2)", args_of("--block-result") and args_of("--block-result")[0][:3] == ("--block-result", "ok", "2"), str(calls))
reset(); script["--sync"] = (0, json.dumps({"blocked": ["com.bad", "com.worse"], "actions": []}), ""); pl.approvals(dev(True), "k")
check("an applied, unchanged list is not re-pushed", not [1 for _, r in enq if r["RequestType"] == "InstallProfile"])
blocked_run(True, ["com.bad", "com.worse", "com.new"])
check("a CHANGED list is pushed again", len([1 for _, r in enq if r["RequestType"] == "InstallProfile"]) == 1)
(Path(pst) / "block-state.json").unlink(); (Path(pst) / "pending-cmds.json").write_text("{}")
blocked_run(True, [])
check("nothing denied and nothing ever applied -> no profile", not [1 for _, r in enq if r["RequestType"] == "InstallProfile"])
script["--sync"] = (4, "", "down"); reset(); pl.approvals(dev(True), "k")
check("server unreachable -> no commands issued", not [1 for _, r in enq if r["RequestType"] in ("InstallProfile", "RemoveApplication")])

print("4. housekeeping")
ob = Path(pst) / "outbox"; ob.mkdir(exist_ok=True)
for i, t in enumerate(("app_snapshot", "app_snapshot", "device_unreachable", "app_snapshot")):
    json.dump({"type": t, "n": i}, open(ob / f"{i:03d}.json", "w"))
pl.coalesce_snapshots()
left = sorted(json.load(open(f))["n"] for f in ob.glob("*.json"))
check("only the NEWEST queued snapshot survives; other events untouched", left == [2, 3], str(left))
sd = Path(pst) / "sent"; sd.mkdir(exist_ok=True)
old, new = sd / "old.json", sd / "new.json"; old.write_text("{}"); new.write_text("{}")
os.utime(old, (time.time() - 3 * 86400,) * 2); pl.prune_sent()
check("sent/ files older than 2 days are pruned, recent kept", not old.exists() and new.exists())

print()
if fails: print(f"FAILED {len(fails)}: " + "; ".join(fails)); sys.exit(1)
print("all MDM enforcement tests passed")
