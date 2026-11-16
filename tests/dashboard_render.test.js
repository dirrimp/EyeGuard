// Runs the REAL docs/dashboard.js in a Node vm with a stub DOM and a fake Supabase client, calls load(), and checks the
// feed actually renders. (An earlier release had `isEnc` defined inside load() but used in card(): every flag card threw a
// ReferenceError and the partners saw counts but an EMPTY feed. String checks did not catch it; running the code does.)
//   node tests/dashboard_render.test.js
const fs = require("fs"), path = require("path"), vm = require("vm");
const code = fs.readFileSync(path.join(__dirname, "..", "docs", "dashboard.js"), "utf8");
let fails = 0;
const check = (n, ok, d = "") => { console.log(`  [${ok ? "ok  " : "FAIL"}] ${n}${!ok && d ? " -- " + d : ""}`); if (!ok) fails++; };

function run(rows, { device = null } = {}) {
  const els = {}, errors = [];
  const el = (id) => els[id] || (els[id] = { id, innerHTML: "", textContent: "", value: "", dataset: {}, style: {}, className: "",
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false }, addEventListener() {}, append() {}, replaceChildren() {},
    querySelectorAll: () => [], disabled: false });
  const chain = (data) => { const o = { select: () => o, order: () => o, limit: () => o, eq: () => o, in: () => o, then: (r) => r({ data }) }; return o; };
  const ctx = {
    console: { log() {}, error: (...a) => errors.push(a.map(String).join(" ")) }, setInterval() {}, clearInterval() {}, URL, Blob, alert() {}, confirm: () => true,
    history: { replaceState() {} }, location: { origin: "https://x.test", pathname: "/", reload() {} }, navigator: {}, fetch() {},
    window: {}, document: { getElementById: el, querySelectorAll: () => [], addEventListener() {}, body: { dataset: {} }, createElement: () => el("tmp") },
    supabase: { createClient: () => ({
      auth: { getSession: async () => ({ data: { session: null } }), onAuthStateChange() {}, signInWithOtp: async () => ({}), signOut: async () => ({}) },
      from: (t) => chain(t === "flags" ? rows : []),
      rpc: async () => ({ data: null }),
      storage: { from: () => ({ createSignedUrls: async () => ({ data: [] }), createSignedUrl: async () => ({ data: null, error: "x" }) }) } }) },
  };
  ctx.window.document = ctx.document; ctx.window.crypto = {}; ctx.window.indexedDB = {};
  vm.createContext(ctx); vm.runInContext(code + "\n;globalThis.__load = load; globalThis.__setDevice = (d) => { device = d; };", ctx);
  if (device) ctx.__setDevice(device);
  return ctx.__load().then(() => ({ feed: els.feed ? els.feed.innerHTML : "", errors, els }));
}
const enc = "2026-11-16T18-00-00.123456+00-00_alert_d1.jpg.enc";
const rows = [
  { verdict: "flagged", flagged_at: "2026-11-16T18:00:05+00:00", reason: "nudenet: x", app: "Zen", grade: "Likely", is_nudity: true, image_path: enc.replace("alert", "flagged") },
  { verdict: "alert", flagged_at: "2026-11-16T18:00:00.123456+00:00", reason: "clear -> clip-yellow x", app: "Zen", grade: "Possible", image_path: enc },
  { verdict: "alert", flagged_at: "2026-11-16T17:00:00+00:00", reason: "clear -> clip-yellow y", app: "Zen", grade: "Possible", image_path: "plain.jpg" },
  { verdict: "clear", flagged_at: "2026-11-16T17:55:00+00:00", reason: "browsing", app: "Zen" },
  { verdict: "flagged", flagged_at: "2026-11-16T17:50:00+00:00", reason: "net-bypass: known VPN server contacted 1.2.3.4 from Mac", app: "Network" },
];
(async () => {
  const a = await run(rows);
  check("load() renders the feed (not empty) with red, yellow and green cards", /class="card red"/.test(a.feed) && /class="card yellow"/.test(a.feed) && /class="card green"/.test(a.feed), a.feed.slice(0, 80));
  check("no script errors while rendering", a.errors.length === 0, a.errors.join(" | ").slice(0, 200));
  check("an encrypted frame shows the lock card with its path and flag time for later decryption", /class="thumb-enc" data-path="[^"]*\.jpg\.enc" data-flag="2026-11-16T18:00:00\.123456\+00:00"/.test(a.feed));
  check("a non-encrypted image still renders as an <img> only when it has a signed URL (none here: no broken <img>)", !/<img class="thumb" src="undefined"/.test(a.feed));
  const netCard = a.feed.split('<div class="card ').find((c) => /known VPN server/.test(c)) || "";
  check("a router network flag shows what it is, labelled Network, with no image wording", /known VPN server contacted 1\.2\.3\.4/.test(netCard) && />Network</.test(netCard) && !/image saved|encrypted/i.test(netCard), netCard.slice(0, 160));
  check("the counts are filled in", a.els.cRed.textContent === 2 && a.els.cYellow.textContent === 2 && a.els.cGreen.textContent === 1);
  const b = await run(rows, { device: { privateKey: {}, keyId: new Uint8Array(8), fingerprint: "x", pem: "p" } });
  check("with a device key enrolled the placeholder says it is decrypting", /Decrypting on this device/.test(b.feed) && b.errors.length === 0, b.errors.join("|").slice(0, 160));
  const c = await run([]);
  check("an empty list shows the empty state, no errors", /NO ACTIVITY YET/.test(c.feed) && c.errors.length === 0);
  console.log(fails ? `\nFAILED: ${fails}` : "\nALL OK"); process.exit(fails ? 1 : 0);
})().catch((e) => { console.error("harness error:", e); process.exit(1); });
