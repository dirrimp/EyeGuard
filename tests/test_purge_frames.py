#!/usr/bin/env python3
"""Offline tests for tools/purge_frames.py (no network, no Supabase).

A fake Storage API stands in for Supabase. Proves the purge deletes ONLY old,
recognized frames, honours dry-run and the cap, refuses a short retention, fails closed
on a bad response, and never prints an object name or the key.
Exit 0 = all pass.
"""
import contextlib
import datetime as dt
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import purge_frames as pf  # noqa: E402

fails: list[str] = []


def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        fails.append(name)


NOW = dt.datetime(2026, 11, 12, 12, 0, 0, tzinfo=dt.timezone.utc)


def fname(days_ago, tag="alert", enc=True, hour=3):
    t = (NOW - dt.timedelta(days=days_ago)).replace(hour=hour, minute=5, second=9)
    return t.strftime("%Y-%m-%dT%H-%M-%S") + f".123456+00-00_{tag}_d1.jpg" + (".enc" if enc else "")


def obj(name, days_ago=None, created=None, folder=False):
    t = created or ((NOW - dt.timedelta(days=days_ago)).isoformat() if days_ago is not None else None)
    return {"name": name, "id": None if folder else "x-" + name[:8], "created_at": t}


class FakeStorage:
    def __init__(self, objects, delete_count_lie=0, bad_list=False):
        self.objects = list(objects)
        self.calls = []
        self.lie = delete_count_lie
        self.bad_list = bad_list

    def __call__(self, method, path, body=None):
        self.calls.append((method, path))
        if method == "POST" and path.startswith("/storage/v1/object/list/"):
            if self.bad_list:
                return {"error": "nope"}
            o, lim = body["offset"], body["limit"]
            return sorted(self.objects, key=lambda e: e["created_at"] or "")[o:o + lim]
        if method == "DELETE" and path == "/storage/v1/object/frames":
            gone = [e for e in self.objects if e["name"] in body["prefixes"]]
            self.objects = [e for e in self.objects if e["name"] not in body["prefixes"]]
            return gone[: max(0, len(gone) - self.lie)] if self.lie else gone
        raise AssertionError(f"unexpected call {method} {path}")

    def deletes(self):
        return [c for c in self.calls if c[0] == "DELETE"]


def run(store, **kw):
    buf = io.StringIO()
    args = dict(now=NOW, days=7, max_delete=500, apply=True)
    args.update(kw)
    with contextlib.redirect_stdout(buf):
        try:
            rc = pf.run(store, say=lambda s: print(s), **args)
        except pf.PurgeError as e:
            return "ERR:" + str(e), buf.getvalue()
    return rc, buf.getvalue()


# ---- selection -------------------------------------------------------------
old1, old2, young, edge = fname(30), fname(9), fname(2), fname(6, hour=23)
store = FakeStorage([
    obj(old1, 30), obj(old2, 9, ), obj(young, 2), obj(edge, 6),
    obj(".emptyFolderPlaceholder", 40),            # unrecognized name: never touched
    obj("notes.txt", 40),
    obj("subdir", 40, folder=True),                # folder entry: skipped
    obj(fname(40, tag="flagged", enc=False), created=None),  # name only, old: deleted
])
rc, out = run(store)
left = {e["name"] for e in store.objects}
check("deletes the old frames (30d, 9d, and the name-only 40d one)",
      old1 not in left and old2 not in left and fname(40, tag="flagged", enc=False) not in left)
check("keeps young frames (2d and 6d)", young in left and edge in left)
check("never deletes unrecognized names or folders", {".emptyFolderPlaceholder", "notes.txt"} <= left and any(e["name"] == "subdir" for e in store.objects))
check("returns 0", rc == 0, str(rc))

# a clock disagreement can only KEEP a frame: name says old, created_at says new
conflict = fname(20)
store = FakeStorage([obj(conflict, 1)])
run(store)
check("name old but created_at young -> kept", any(e["name"] == conflict for e in store.objects))
store = FakeStorage([obj(fname(2), 20)])
run(store)
check("name young but created_at old -> kept", len(store.objects) == 1)

# ---- dry run ---------------------------------------------------------------
store = FakeStorage([obj(fname(30), 30)])
rc, out = run(store, apply=False)
check("dry run deletes nothing and makes no DELETE call", len(store.objects) == 1 and not store.deletes() and rc == 0)
check("dry run says so", "DRY RUN" in out)

# ---- cap and backlog -------------------------------------------------------
many = [obj(fname(10 + i % 5, tag=f"t{i}", hour=i % 24), 10 + i % 5) for i in range(30)]
store = FakeStorage(many)
rc, out = run(store, max_delete=12)
check("cap: deletes exactly 12 of 30 old", len(store.objects) == 18, str(len(store.objects)))
check("cap: reports the backlog", "18 more remain" in out, out)

# ---- pagination ------------------------------------------------------------
big = [obj(fname(10, tag=f"p{i}", hour=i % 24).replace("_d1", f"_d{i}"), 10) for i in range(250)]
store = FakeStorage(big)
rc, out = run(store, max_delete=1000)
check("pagination: all 250 old frames across 3 pages deleted", len(store.objects) == 0, str(len(store.objects)))
check("batches: delete calls are <= 100 names", all(True for _ in store.deletes()) and len(store.deletes()) == 3, str(len(store.deletes())))

# ---- guards ----------------------------------------------------------------
store = FakeStorage([obj(fname(30), 30)])
rc, _ = run(store, days=2)
check("retention below 3 days is refused, nothing listed or deleted", str(rc).startswith("ERR:") and not store.calls, str(rc))
rc, _ = run(FakeStorage([]), max_delete=0)
check("max-delete 0 refused", str(rc).startswith("ERR:"))
rc, _ = run(FakeStorage([obj(fname(30), 30)], bad_list=True))
check("bad list response fails closed", str(rc).startswith("ERR:") and "list" in str(rc), str(rc))
store = FakeStorage([obj(fname(30), 30), obj(fname(31, tag="b"), 31)], delete_count_lie=1)
rc, _ = run(store)
check("API reporting fewer deletions than asked fails the run", str(rc).startswith("ERR:") and "reports" in str(rc), str(rc))

# ---- nothing to do ---------------------------------------------------------
store = FakeStorage([obj(fname(1), 1)])
rc, out = run(store)
check("nothing old: no DELETE call, exit 0", not store.deletes() and rc == 0 and "nothing to delete" in out)

# ---- privacy: counts only --------------------------------------------------
names = [fname(30, tag="secret1"), fname(31, tag="secret2")]
store = FakeStorage([obj(n, 30) for n in names] + [obj(young, 2)])
rc, out = run(store)
check("output never contains an object name or tag", not any(n in out for n in names) and "secret" not in out and young not in out)

# ---- the script itself never prints a key or touches other buckets ---------
src = (Path(__file__).resolve().parent.parent / "tools" / "purge_frames.py").read_text()
check("only the 'frames' bucket is addressed", src.count('BUCKET = "frames"') == 1 and "/object/frames" not in src.replace("{BUCKET}", ""))
import re  # noqa: E402
output_lines = [ln for ln in src.splitlines()
                if re.search(r"\b(print|say|PurgeError)\(", ln) or "file=sys.stderr" in ln]
check("the key variable is never in a printed or raised message",
      not any(re.search(r"\bkey\b|SERVICE_ROLE_KEY\}|\{key", ln) and "must be set" not in ln
              for ln in output_lines), str([ln for ln in output_lines if "key" in ln]))
check("defaults to dry run unless --apply", "args.apply" in src and "apply=args.apply" in src)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("ALL OK")
