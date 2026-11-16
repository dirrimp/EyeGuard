// EyeGuard partner dashboard. Loaded as an external script (not inline) so the Content-Security-Policy in
// index.html can say script-src 'self' with no per-edit hash.
// ---- config (public: publishable key is client-safe; data is protected by
// row-level security + disabled signups) ----
const SUPABASE_URL = "https://ucgldleacehxjjwwqomk.supabase.co";
const SUPABASE_KEY = "sb_publishable_y9pDf3aBNY4Le5u9tbUXzg_qCRvMn-b";
const sb = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

const $ = (id) => document.getElementById(id);
let pollTimer = null;

// ---------- auth ----------
async function sendLink(){
  const email = $("email").value.trim();
  const msg = $("loginMsg");
  if(!email){ msg.className="msg err"; msg.textContent="Enter your email."; return; }
  $("sendBtn").disabled = true;
  const { error } = await sb.auth.signInWithOtp({
    email,
    options:{ shouldCreateUser:false,
              emailRedirectTo: location.origin + location.pathname }
  });
  $("sendBtn").disabled = false;
  if(error){ msg.className="msg err";
    msg.textContent = /not allowed|signups|Signups/.test(error.message)
      ? "This email isn't registered for access." : error.message; }
  else{ msg.className="msg ok";
    msg.textContent="Check your email for a login link."; }
}
async function signOut(){ await sb.auth.signOut(); location.reload(); }

async function boot(){
  const { data:{ session } } = await sb.auth.getSession();
  if(session){ showApp(session); } else { $("login").classList.remove("hidden"); }
  sb.auth.onAuthStateChange((_e, s)=>{
    if(s && $("app").classList.contains("hidden")) showApp(s);
  });
}
function showApp(session){
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
  $("who").textContent = session.user.email;
  history.replaceState(null,"",location.pathname); // strip auth tokens from URL
  load();
  if(pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(load, 20000); // live refresh
}

// ---------- data ----------
const esc = (s)=>String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;")
  .replace(/>/g,"&gt;").replace(/"/g,"&quot;");

// ---------- apps (MDM official list: approve / deny) ----------
// All rights are enforced on the SERVER (eg_mdm_decide accepts only the two partner
// accounts). If this account is not a partner or the SQL is not installed yet the
// panel simply stays hidden.
function ago(iso){
  if(!iso) return "never";
  const m = Math.round((Date.now()-new Date(iso).getTime())/60000);
  return m<2 ? "just now" : m<90 ? m+" min ago" : m<2880 ? Math.round(m/60)+" h ago" : Math.round(m/1440)+" d ago";
}
function arow(a, btns){
  const name = esc(a.app_name||a.bundle_id);
  const sub = esc(a.bundle_id)+(a.app_version? " · v"+esc(a.app_version):"")
    + (a.present? "" : " · not installed now") + " · first seen " + esc(ago(a.first_seen_at));
  return `<div class="arow"><div><div class="aname">${name}</div><div class="asub">${sub}</div></div>`
    + `<div class="abtns">${btns.map(([d,l])=>`<button class="abtn ${d}" data-b="${esc(a.bundle_id)}" data-n="${name}" data-d="${d}">${l}</button>`).join("")}</div></div>`;
}
const KIND = {monitor_silent:"Monitor stopped reporting", no_phone_watched:"No phone being watched",
  app_list_stale:"Phone's app list went stale", phone_unreachable:"Phone unreachable",
  g11_drift:"G11 code differed from approved", g11_outdated:"G11 ran older approved code",
  g11_attest_missing:"G11 integrity report stopped"};
function dur(a,b){
  const m = Math.max(0, Math.round(((b?new Date(b):new Date())-new Date(a))/60000));
  return m<90 ? m+" min" : m<2880 ? (m/60).toFixed(1)+" h" : Math.round(m/1440)+" d";
}
async function loadApps(){
  const box = $("apps");
  const [ov, ap, inc, at] = await Promise.all([sb.rpc("eg_mdm_overview"),
    sb.from("mdm_apps").select("*").order("first_seen_at",{ascending:false}),
    sb.from("mdm_incidents").select("*").order("started_at",{ascending:false}).limit(30),
    sb.rpc("eg_mdm_attest_status")]);
  if(ov.error || ap.error){ box.innerHTML=""; return; }
  const gaps = inc.error ? [] : (inc.data||[]);
  const o = ov.data||{}, apps = ap.data||[];
  const pend = apps.filter(a=>a.status==="pending"), den = apps.filter(a=>a.status==="denied"),
        okk = apps.filter(a=>a.status==="approved");
  const sup = o.supervised===true ? ["ok","Phone supervised: enforcement possible"]
            : o.supervised===false ? ["warn","Phone NOT supervised: deny flags only, cannot block"]
            : ["warn","Supervision unknown"];
  const blk = den.length===0 ? null
            : o.block_ok===true ? ["ok","Block list applied ("+esc(o.block_count)+")"]
            : ["bad","Block list not applied"+(o.block_detail? ": "+esc(o.block_detail):"")];
  // G11 code integrity: the G11's own report compared by the database with what Dad's CI published
  const as = at && !at.error && at.data ? at.data.state : null;
  const att = as==="ok" ? ["ok","G11 code matches approved (self-reported)"]
            : as==="outdated" ? ["warn","G11 running older approved code"]
            : as==="drift" ? ["bad","G11 CODE DIFFERS FROM APPROVED"]
            : as==="no_manifest" ? ["warn","No approved G11 manifest published yet"] : null;
  const chips = [sup, att, ["", "Last app list "+esc(ago(o.last_snapshot_at))],
                 ["ok", okk.length+" approved"], pend.length? ["warn", pend.length+" pending"] : null,
                 den.length? ["bad", den.length+" denied"] : null, blk].filter(Boolean)
    .map(([c,t])=>`<span class="chip ${c}">${t}</span>`).join("");
  let html = `<div class="apanel"><h2>Apps on the phone</h2><div class="chips">${chips}</div>`;
  if(!o.baseline_closed){
    html += `<div class="asub">Waiting for the first app list from the phone. It becomes the approved list.</div>`;
  }
  if(pend.length) html += `<div class="asec"><h3>Awaiting your decision</h3>`
    + pend.map(a=>arow(a,[["approve","Approve"],["deny","Deny"]])).join("")+`</div>`;
  if(den.length) html += `<div class="asec"><h3>Denied</h3>`
    + den.map(a=>arow(a,[["approve","Approve instead"]])).join("")+`</div>`;
  if(okk.length) html += `<details class="asec"><summary>Approved list (${okk.length})</summary>`
    + okk.map(a=>arow(a,[["revoke","Revoke"]])).join("")+`</details>`;
  if(gaps.length) html += `<details class="asec"${gaps.some(g=>!g.ended_at)?" open":""}><summary>Monitoring gaps (${gaps.length})</summary>`
    + gaps.map(g=>`<div class="arow"><div><div class="aname">${esc(KIND[g.kind]||g.kind)}</div>`
      + `<div class="asub">${esc(new Date(g.started_at).toLocaleString([],{month:"short",day:"numeric",hour:"numeric",minute:"2-digit"}))}`
      + ` · ${g.ended_at? "lasted "+esc(dur(g.started_at,g.ended_at)) : "STILL OPEN ("+esc(dur(g.started_at))+" so far)"}`
      + `${g.detail? " · "+esc(g.detail):""}</div></div>`
      + `<span class="chip ${g.ended_at?"warn":"bad"}">${g.ended_at?"resolved":"open"}</span></div>`).join("")
    + `<div class="asub" style="margin-top:8px">A resolved gap is not proof nothing happened: MDM sees which apps are installed at each check, not what happened in between.</div></details>`;
  html += `<div class="aerr" id="aerr"></div></div>`;
  const wasOpen = [...box.querySelectorAll("details")].map(d=>d.open);   // don't collapse them under the reader
  box.innerHTML = html;
  box.querySelectorAll("details").forEach((d,i)=>{ if(wasOpen[i]) d.open = true; });
}
document.addEventListener("click", async (e)=>{
  const b = e.target.closest(".abtn[data-b]");
  if(!b) return;
  const d = b.dataset.d, n = b.dataset.n || b.dataset.b;
  const q = d==="deny" ? `Deny "${n}"?\n\nIt is flagged and reminded about daily. If the phone is supervised it is also blocked and a removal is attempted. Both partners are emailed.`
          : d==="revoke" ? `Take "${n}" off the approved list?\n\nIt goes back to pending until someone approves it again.`
          : `Approve "${n}"?\n\nIt joins the official list. Both partners are emailed.`;
  if(!confirm(q)) return;
  document.querySelectorAll(".abtn").forEach(x=>x.disabled=true);
  const { error } = await sb.rpc("eg_mdm_decide", {p_bundle_id:b.dataset.b, p_decision:d});
  if(error){ await loadApps(); const el=$("aerr"); if(el) el.textContent="Could not save: "+(error.message||"error"); return; }
  await loadApps();
});

async function load(){
  loadApps().catch(console.error);
  const { data, error } = await sb.from("flags")
    .select("*").order("flagged_at",{ascending:false}).limit(1200);
  if(error){ console.error(error); return; }
  const rows = data || [];

  // counts
  $("cRed").textContent    = rows.filter(r=>r.verdict==="flagged").length;
  $("cYellow").textContent = rows.filter(r=>r.verdict==="alert").length;
  $("cGreen").textContent  = rows.filter(r=>r.verdict==="clear").length;
  if(rows.length){
    const t = new Date(rows[0].flagged_at);
    $("lastSeen").textContent = "Last activity " + t.toLocaleString([],
      {month:"short",day:"numeric",hour:"numeric",minute:"2-digit"});
  }

  // signed URLs for the images (private bucket)
  const paths = rows.filter(r=>r.image_path).map(r=>r.image_path);
  const signed = {};
  if(paths.length){
    const { data:sd } = await sb.storage.from("frames").createSignedUrls(paths, 3600);
    (sd||[]).forEach(x=>{ if(x.signedUrl) signed[x.path]=x.signedUrl; });
  }

  // group by local day
  const byDay = {}; const order = [];
  for(const r of rows){
    const dt = new Date(r.flagged_at);
    const day = dt.toLocaleDateString([], {weekday:"long",month:"long",day:"numeric"});
    if(!byDay[day]){ byDay[day]=[]; order.push(day); }
    byDay[day].push(card(r, dt, signed));
  }
  const feed = $("feed");
  if(!rows.length){ feed.innerHTML='<div class="empty">NO ACTIVITY YET</div>'; return; }
  feed.innerHTML = order.map(day=>
    `<section class="day"><h2>${esc(day)}<span class="daycount">${byDay[day].length}</span></h2>`
    + `<div class="grid">${byDay[day].join("")}</div></section>`).join("");
  feed.querySelectorAll("img.thumb").forEach(img=>{
    img.onclick=()=>window.open(img.src,"_blank"); });
}

function where(r){
  const app = esc(r.app||"an app");
  const loc = r.url||r.window_title;
  return app + (loc? ` — ${esc(loc)}` : "");
}
// A second monitored phone (2026-10-01, Jada's) prefixes its reasons with
// "jada-" so the server never mistakes them for Jonah's phone. Strip it here
// so the card renders as a Phone card; the device shows via r.app.
function devReason(x){ x = x||""; return x.startsWith("jada-") ? x.slice(5) : x; }
function card(r, dt, signed){
  const time = dt.toLocaleTimeString([], {hour:"numeric",minute:"2-digit"});
  if(r.verdict==="clear"){
    const label = devReason(r.reason).startsWith("phone") ? "Phone" : "Browsing";
    return `<div class="card green"><div class="body"><div class="rtop">`
      + `<span class="time">${time}</span><span class="pill green">${label}</span></div>`
      + `<div class="where">${where(r)}</div></div></div>`;
  }
  const red = r.verdict==="flagged";
  const rs = devReason(r.reason);
  const drm = rs.startsWith("drm"), tamper = rs.startsWith("tamper"), ext = rs.startsWith("extension");
  const vm = rs.startsWith("vm");
  const txt = rs.startsWith("text"), sig = rs.startsWith("signal"), phone = rs.startsWith("phone");
  const sevCls = red?"red":"yellow";
  const sevTxt = phone ? "Phone"
                     : red ? (tamper?"Tamper":sig?"Search":(r.is_nudity?"Nudity":"Revealing"))
                     : (drm?"DRM Video":ext?"Extension":vm?"Virtualization":txt?"Text":sig?"Search":"Suggestive");
  const gcls = {Likely:"g-hi",Possible:"g-mid",Borderline:"g-lo"}[r.grade]||"";
  const grade = r.grade? `<span class="grade ${gcls}">${esc(r.grade)}</span>` : "";
  const url = r.image_path && signed[r.image_path];
  const img = url? `<img class="thumb" src="${url}" loading="lazy">` : "";
  const detail = esc((rs.split(/—(.+)/)[1]||"").trim());
  const what = phone ? esc(rs.split(/:(.+)/)[1]||"").trim()+" ("+esc(r.app||"iPhone")+", via network)"
                   : tamper ? esc(rs.split(/:(.+)/)[1]||"").trim()+" — a possible attempt to defeat monitoring."
                   : ext ? esc(rs.split(/:(.+)/)[1]||"").trim()+" — review whether it's legitimate."
                   : vm ? esc(rs.split(/:(.+)/)[1]||"").trim()+" — review whether it's legitimate."
                   : txt ? "Explicit text on screen — "+detail
                   : sig ? "Explicit term in the URL / search — "+detail
                   : red ? (r.is_nudity? "explicit nudity / exposed body — see image"
                                 : "very revealing content — see image")
                   : drm ? "Not a content flag — macOS blanks DRM-protected video, so EyeGuard couldn't view it. The title is logged so you can review it yourself."
                   : esc((r.reason||"").split(":").pop()||"suggestive content");
  return `<div class="card ${sevCls}">${img}<div class="body"><div class="rtop">`
    + `<span class="time">${time}</span><span class="pill ${sevCls}">${sevTxt}</span>${grade}`
    + `</div><div class="where">${where(r)}</div><div class="what">${what}</div></div></div>`;
}

// ---------- filters ----------
function flt(s){
  document.body.dataset.filter=s;
  document.querySelectorAll(".fbtn").forEach(b=>b.classList.toggle("active",b.dataset.sev===s));
}
// Event wiring lives here, not in onclick="" attributes: the Content-Security-Policy above allows no inline handlers.
document.getElementById("sendBtn").addEventListener("click", sendLink);
document.getElementById("signOutBtn").addEventListener("click", signOut);
document.querySelectorAll(".fbtn").forEach(b => b.addEventListener("click", () => flt(b.dataset.sev)));
boot();
