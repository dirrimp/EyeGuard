import base64, hmac, hashlib, json, os, re, subprocess, sys, time, urllib.request, urllib.error
NET, DB, SMTP, AUTH = "egauth", "egauth-db", "egauth-smtp", "egauth-auth"
SECRET = "test-secret-0123456789-0123456789-abcdef"
OLD, NEW = "old.account@example.test", "jadadirrim@pm.me"
SQL = open("supabase/change_partner_email.sql").read()
def sh(cmd, check=True, inp=None):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, input=inp)
    if check and r.returncode: raise RuntimeError(f"{cmd}\n{r.stderr[-600:]}")
    return r
def psql(sql, err_ok=False):
    r = subprocess.run(["docker","exec","-i",DB,"psql","-U","postgres","-X","-q","-t","-A","-v","ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True)
    if r.returncode and not err_ok: raise RuntimeError(r.stderr[-600:])
    return r.stdout.strip(), r.stderr.strip()
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def jwt(claims): 
    h = b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode()); p = b64(json.dumps(claims).encode())
    return f"{h}.{p}.{b64(hmac.new(SECRET.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())}"
def api(method, path, body=None, tok=None):
    req = urllib.request.Request("http://127.0.0.1:19999"+path, method=method, data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type":"application/json", **({"Authorization":"Bearer "+tok} if tok else {})})
    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    try:
        with urllib.request.build_opener(NoRedir).open(req, timeout=20) as r: return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e: return e.code, e.read().decode(), dict(e.headers)
    except OSError: return 0, '', {}
def cleanup():
    for c in (AUTH, SMTP, DB): sh(f"docker rm -f {c}", check=False)
    sh(f"docker network rm {NET}", check=False)
results = []
def check(name, ok, detail=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else "")); results.append(ok)
try:
    cleanup()
    sh(f"docker network create {NET}")
    sh(f"docker run -d --name {DB} --network {NET} -e POSTGRES_PASSWORD=pw -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine")
    for _ in range(40):
        if sh(f"docker exec {DB} pg_isready -U postgres", check=False).returncode == 0: break
        time.sleep(1)
    time.sleep(2)
    psql("""create role anon nologin; create role authenticated nologin; create role service_role nologin; create role dashboard_user nologin;
create role supabase_auth_admin login password 'authpw' noinherit createrole;
create schema auth authorization supabase_auth_admin; grant all on schema auth to supabase_auth_admin;
alter user supabase_auth_admin set search_path = 'auth';""")
    sink = r'''
import socket, threading, os
os.makedirs("/mail", exist_ok=True); n=[0]
def handle(c):
    f=c.makefile("rwb", buffering=0); f.write(b"220 sink\r\n"); data=False; buf=b""
    while True:
        line=f.readline()
        if not line: break
        if data:
            buf+=line
            if line==b".\r\n":
                n[0]+=1; open(f"/mail/{n[0]}.eml","wb").write(buf); buf=b""; data=False; f.write(b"250 ok\r\n")
            continue
        u=line.upper()
        if u.startswith(b"DATA"): data=True; f.write(b"354 go\r\n")
        elif u.startswith(b"QUIT"): f.write(b"221 bye\r\n"); break
        elif u.startswith(b"EHLO"): f.write(b"250-sink\r\n250 8BITMIME\r\n")
        else: f.write(b"250 ok\r\n")
    c.close()
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",2525)); s.listen(5)
while True:
    c,_=s.accept(); threading.Thread(target=handle,args=(c,),daemon=True).start()
'''
    open("/tmp/sink.py","w").write(sink)
    sh(f"docker run -d --name {SMTP} --network {NET} -v /tmp/sink.py:/sink.py:ro python:3.13-alpine python /sink.py")
    env = {"GOTRUE_API_HOST":"0.0.0.0","PORT":"9999","API_EXTERNAL_URL":"http://localhost:9999","GOTRUE_DB_DRIVER":"postgres",
      "GOTRUE_DB_DATABASE_URL":f"postgres://supabase_auth_admin:authpw@{DB}:5432/postgres","GOTRUE_SITE_URL":"http://localhost:3000",
      "GOTRUE_JWT_SECRET":SECRET,"GOTRUE_JWT_EXP":"3600","GOTRUE_JWT_AUD":"authenticated","GOTRUE_SMTP_MAX_FREQUENCY":"1s","GOTRUE_JWT_DEFAULT_GROUP_NAME":"authenticated","GOTRUE_DISABLE_SIGNUP":"true","GOTRUE_EXTERNAL_EMAIL_ENABLED":"true",
      "GOTRUE_MAILER_AUTOCONFIRM":"false","GOTRUE_SMTP_HOST":SMTP,"GOTRUE_SMTP_PORT":"2525","GOTRUE_SMTP_ADMIN_EMAIL":"admin@example.test",
      "GOTRUE_SMTP_SENDER_NAME":"t","GOTRUE_MAILER_OTP_EXP":"3600","GOTRUE_RATE_LIMIT_EMAIL_SENT":"1000","GOTRUE_URI_ALLOW_LIST":"http://localhost:3000"}
    e = " ".join(f"-e {k}='{v}'" for k,v in env.items())
    sh(f"docker run -d --name {AUTH} --network {NET} -p 127.0.0.1:19999:9999 {e} supabase/auth:v2.176.1")
    up = False
    for _ in range(60):
        s,_,_ = api("GET","/health")
        if s == 200: up = True; break
        time.sleep(1)
    if not up: print(sh(f"docker logs --tail 20 {AUTH}", check=False).stdout[-1500:]); raise SystemExit("auth server did not start")
    admin = jwt({"role":"service_role","aud":"authenticated","iss":"test","exp":int(time.time())+3600})
    s,b,_ = api("POST","/admin/users",{"email":OLD,"email_confirm":True}, admin)
    uid = json.loads(b)["id"]; print("test user created:", uid, OLD)
    check("sanity: signups are disabled (unknown email -> refused like the dashboard)", api("POST","/otp",{"email":NEW,"create_user":False})[0] == 422)
    s,b,_ = api("POST","/otp",{"email":NEW,"create_user":False}); check("...with the message the dashboard maps to \"isn't registered for access\"", "ignups not allowed" in b, b[:150])
    s1,b1,_ = api("POST","/otp",{"email":OLD,"create_user":False})
    check("sanity: the existing email is accepted (magic link sent)", s1 == 200, f"{s1} {b1[:200]}")
    print("   DEBUG user row:", psql("select id, aud, role, instance_id, email, is_sso_user, deleted_at is not null as deleted, confirmed_at is not null as confirmed from auth.users")[0])
    print("   DEBUG auth logs:", sh(f"docker logs --tail 6 {AUTH} 2>&1").stdout[-700:].replace(chr(10)," | "))
    sql = SQL.replace("1818ac68-7ecf-4e39-a758-8526e496247d", uid)
    out, err = psql(sql, err_ok=True)
    print("   SQL notices:", [l for l in err.splitlines() if "NOTICE" in l][:3]); print("   SQL result :", out)
    check("the SQL ran without error", "ERROR" not in err, err[-300:])
    s,b,_ = api("POST","/otp",{"email":NEW,"create_user":False}); check("the NEW email is now accepted (magic link sent)", s == 200, f"{s} {b[:150]}")
    s,b,_ = api("POST","/otp",{"email":OLD,"create_user":False}); check("the OLD email is no longer accepted", s == 422, f"{s} {b[:100]}")
    s,b,_ = api("GET",f"/admin/users/{uid}",None,admin); u = json.loads(b)
    check("same account: id unchanged, email updated, still confirmed", u["id"] == uid and u["email"] == NEW and u.get("email_confirmed_at"), str(u)[:200])
    check("identity record updated too", any((i.get("identity_data") or {}).get("email") == NEW for i in u.get("identities", [])), str(u.get("identities"))[:200])
    # END TO END: read the emailed link for the new address and complete the login
    time.sleep(1)
    mails = sh(f"docker exec {SMTP} sh -c 'ls /mail | sort -n | tail -3'").stdout.split()
    link = None
    for m in reversed(mails):
        body = sh(f"docker exec {SMTP} cat /mail/{m}").stdout
        if f"To: {NEW}" in body or NEW in body.split("\n\n")[0]:
            body = re.sub(r"=\r?\n", "", body).replace("=3D", "=").replace("&amp;", "&")
            m2 = re.search(r"http://[^\s\"'<>]*verify\?[^\s\"'<>]+", body); link = m2.group(0) if m2 else None; break
    check("a login email was produced for the NEW address", bool(link), str(mails))
    if link:
        path = link.split("http://localhost:9999",1)[-1] if "localhost:9999" in link else "/"+link.split("/",3)[3]
        s,b,h = api("GET", path)
        loc = h.get("Location","")
        tok = re.search(r"access_token=([^&]+)", loc)
        if tok:
            payload = json.loads(base64.urlsafe_b64decode(tok.group(1).split(".")[1] + "=="))
            check("END TO END: clicking the link logs in as the SAME user id with the new email", payload.get("sub") == uid and payload.get("email") == NEW, str(payload)[:200])
        else:
            check("END TO END: clicking the link logs in", False, f"{s} {loc[:160]} {b[:120]}")
    print("\n", "ALL PASSED" if all(results) else f"{results.count(False)} FAILED")
finally:
    cleanup()
