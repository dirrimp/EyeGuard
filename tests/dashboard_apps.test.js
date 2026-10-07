// DOM test for the partner dashboard's Apps panel (docs/index.html) with a fake
// Supabase client. Synthetic apps only. Needs jsdom:  npm i jsdom (anywhere) and run
//   NODE_PATH=<dir>/node_modules node tests/dashboard_apps.test.js
// Skips (exit 0) if jsdom is missing.
let JSDOM; try { ({ JSDOM } = require("jsdom")); } catch { console.log("  [skip] jsdom not installed"); process.exit(0); }
const fs = require("fs"), path = require("path");
const page = fs.readFileSync(path.join(__dirname, "..", "docs", "index.html"), "utf8");
let fails = 0;
const check = (n, ok, d = "") => { console.log(`  [${ok ? "ok  " : "FAIL"}] ${n}${!ok && d ? " -- " + d : ""}`); if (!ok) fails++; };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const STUB = `<script>
const mk=(n,b,v,bid,st)=>({bundle_id:bid,app_name:n,app_version:v,status:st,present:true,first_seen_at:new Date(Date.now()-3600e3*b).toISOString()});
window.__apps=[mk("Cool Game",2,"3.1","com.cool.game","pending"),mk("<img src=x onerror=document.title='XSS'>",1,"1","com.evil","pending"),
  mk("Sketchy Chat",30,"2","com.sketchy.chat","denied"),mk("Calendar",900,"9","com.cal","approved")];
window.__calls=[]; window.__ov={data:{baseline_closed:true,supervised:false,last_snapshot_at:new Date().toISOString(),block_ok:null}};
window.__decide={data:{ok:true}}; window.__confirmMsgs=[]; window.__confirmAnswer=true;
window.confirm=(m)=>{window.__confirmMsgs.push(m);return window.__confirmAnswer;};
window.supabase={createClient:()=>({
 auth:{getSession:async()=>({data:{session:{user:{email:"dad@example.test"}}}}),onAuthStateChange:()=>{},signOut:async()=>{}},
 rpc:async(fn,a)=>{window.__calls.push([fn,a]);return fn==="eg_mdm_overview"?window.__ov:window.__decide;},
 from:(t)=>t==="mdm_apps"?{select:()=>({order:async()=>({data:window.__apps})})}:{select:()=>({order:()=>({limit:async()=>({data:[]})})})},
 storage:{from:()=>({createSignedUrls:async()=>({data:[]})})}})};
</script>`;
const html = page.replace(/<script src="https:\/\/cdn\.jsdelivr\.net[^"]*"><\/script>/, () => STUB);

async function boot(setup) {
  const dom = new JSDOM(html, { runScripts: "dangerously", url: "https://example.test/", pretendToBeVisual: true,
    beforeParse(w) { if (setup) w.__setup = setup; } });
  for (let i = 0; i < 40 && !dom.window.document.getElementById("apps").innerHTML; i++) await sleep(25);
  return dom;
}
(async () => {
  let dom = await boot(); let w = dom.window, d = w.document;
  const box = d.getElementById("apps");
  check("panel renders pending / denied / approved sections",
    /Awaiting your decision/.test(box.textContent) && /Denied/.test(box.textContent) && /Approved list \(1\)/.test(box.textContent));
  check("unsupervised phone is called out plainly", /NOT supervised/i.test(box.textContent));
  check("hostile app name is rendered as text, never as markup", !box.querySelector("img") && w.document.title !== "XSS"
    && box.textContent.includes("<img src=x onerror=document.title='XSS'>"));

  w.__confirmAnswer = false;
  box.querySelector('.abtn.approve[data-b="com.cool.game"]').click(); await sleep(50);
  check("declining the confirm makes NO decision call", !w.__calls.some(c => c[0] === "eg_mdm_decide") && w.__confirmMsgs.length === 1);

  w.__confirmAnswer = true;
  box.querySelector('.abtn.approve[data-b="com.cool.game"]').click(); await sleep(80);
  const dec = w.__calls.filter(c => c[0] === "eg_mdm_decide");
  check("Approve -> eg_mdm_decide(bundle, 'approve')", dec.length === 1 && dec[0][1].p_bundle_id === "com.cool.game" && dec[0][1].p_decision === "approve", JSON.stringify(dec));

  box.querySelector('.abtn.deny[data-b="com.cool.game"]').click(); await sleep(80);
  const dd = w.__calls.filter(c => c[0] === "eg_mdm_decide").pop();
  check("Deny -> eg_mdm_decide(bundle, 'deny') after a warning that names the app and the consequences",
    dd[1].p_decision === "deny" && /Deny "Cool Game"/.test(w.__confirmMsgs.at(-1)) && /flagged/.test(w.__confirmMsgs.at(-1)));

  d.getElementById("apps").querySelector("details summary").click();
  box.querySelector('.abtn.revoke[data-b="com.cal"]').click(); await sleep(80);
  check("Revoke on the approved list -> 'revoke'", w.__calls.filter(c => c[0] === "eg_mdm_decide").pop()[1].p_decision === "revoke");

  w.__decide = { error: { message: "not allowed" } };
  box.querySelector('.abtn.approve[data-b="com.cool.game"]').click(); await sleep(100);
  check("a server refusal is shown to the user and the buttons come back",
    /Could not save: not allowed/.test(d.getElementById("aerr").textContent) && !d.querySelector(".abtn").disabled);
  w.close();

  // a logged-in account that is NOT a partner (or SQL not installed): panel stays hidden
  const dom2 = new JSDOM(html.replace('window.__ov={data:', 'window.__ov={error:{message:"not allowed"},data:'), { runScripts: "dangerously", url: "https://example.test/", pretendToBeVisual: true });
  await sleep(300);
  check("non-partner account: the Apps panel is hidden entirely", dom2.window.document.getElementById("apps").innerHTML === "");
  dom2.window.close();

  const dom3 = new JSDOM(html.replace('mk("Cool Game",2,"3.1","com.cool.game","pending"),', '').replace(/mk\("<img[^)]*\),/, '').replace('mk("Sketchy Chat",30,"2","com.sketchy.chat","denied"),', '').replace('mk("Calendar",900,"9","com.cal","approved")', '').replace('window.__ov={data:{baseline_closed:true', 'window.__ov={data:{baseline_closed:false'), { runScripts: "dangerously", url: "https://example.test/", pretendToBeVisual: true });
  await sleep(300);
  check("before the first app list: says it is waiting", /Waiting for the first app list/.test(dom3.window.document.getElementById("apps").textContent), dom3.window.document.getElementById("apps").textContent.slice(0, 120));
  dom3.window.close();
  console.log(fails ? `\nFAILED ${fails}` : "\nall dashboard apps tests passed"); process.exit(fails ? 1 : 0);
})();
