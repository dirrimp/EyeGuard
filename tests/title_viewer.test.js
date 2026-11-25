// Test for the Onn title records in docs/frame-viewer.js (EGViewer.decryptTitle): records made by the PYTHON encryptor (same EGF2 envelope
// as the Mac's frames and the TV app's Egf2.java) must decrypt in WebCrypto with a device key, and the refusals must hold. Throwaway keys and
// synthetic text only; no real title or frame is ever used.
//   node tests/title_viewer.test.js        (uses the bundled python; override with EG_PY=/path/to/python3)
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const V = require("../docs/frame-viewer.js");
const PY = process.env.EG_PY || "/Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12";
const ROOT = path.join(__dirname, "..");
let fails = 0;
const check = (n, ok, d = "") => { console.log(`  [${ok ? "ok  " : "FAIL"}] ${n}${!ok && d ? " -- " + d : ""}`); if (!ok) fails++; };
const b64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const throws = async (fn) => { try { await fn(); return null; } catch (e) { return e.code || e.name; } };
const py = (code) => execFileSync(PY, ["-c", code], { cwd: ROOT, encoding: "utf8", maxBuffer: 1 << 26 }).trim();

const vec = JSON.parse(py(`
import base64, json, sys
sys.path.insert(0, ".")
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import rsa
from eyeguard import frame_crypto as fc
b = base64.b64encode
def key(bits):
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return (k.private_bytes(s.Encoding.DER, s.PrivateFormat.PKCS8, s.NoEncryption()),
            k.public_key().public_bytes(s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo),
            k.public_key().public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo).decode())
dev, dad = key(3072), key(2048)
name = "onn-title/2026-11-24T22:10:05.123000+00:00_title.enc"
YT = "com.google.android.youtube.tvunplugged"
def rec(obj): return b(fc.encrypt_frame_v2(json.dumps(obj).encode("utf-8"), [dad[2], dev[2]], name)).decode()
print(json.dumps(dict(
  dev_pkcs8=b(dev[0]).decode(), dev_spki=b(dev[1]).decode(), name=name,
  good=rec({"v": 1, "pkg": YT, "at": 1795000000000, "title": "Some Show S2 E4 \\u2014 Caf\\u00e9 \\u65e5\\u672c <b>x</b>"}),
  other_pkg=rec({"v": 1, "pkg": "org.smarttube.stable", "at": 1, "title": "x"}),
  bad_version=rec({"v": 2, "pkg": YT, "at": 1, "title": "x"}),
  empty=rec({"v": 1, "pkg": YT, "at": 1, "title": ""}),
  huge=rec({"v": 1, "pkg": YT, "at": 1, "title": "x" * 401}),
  not_json=b(fc.encrypt_frame_v2(b"just words, not json", [dad[2], dev[2]], name)).decode(),
  jpeg_bytes=b(fc.encrypt_frame_v2(b"\\xff\\xd8\\xff\\xe0" + b"0" * 40, [dad[2], dev[2]], name)).decode(),
  dad_only=b(fc.encrypt_frame_v2(json.dumps({"v": 1, "pkg": YT, "at": 1, "title": "x"}).encode(), [dad[2]], name)).decode())))
`));

(async () => {
  const subtle = globalThis.crypto.subtle;
  const priv = await subtle.importKey("pkcs8", b64(vec.dev_pkcs8), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  const pub = await subtle.importKey("spki", b64(vec.dev_spki), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
  const device = { privateKey: priv, keyId: await V.keyIdOf(pub) };

  const t = await V.decryptTitle(b64(vec.good), device, vec.name);
  check("a record from the Python encryptor decrypts and parses", t.title === "Some Show S2 E4 — Café 日本 <b>x</b>" && t.at === 1795000000000 && t.pkg === "com.google.android.youtube.tvunplugged", JSON.stringify(t));
  check("markup in a title is returned as plain text (the dashboard shows it with textContent)", t.title.includes("<b>x</b>"));
  check("a record for Dad only is refused (not a recipient)", await throws(() => V.decryptTitle(b64(vec.dad_only), device, vec.name)) === "not-recipient");
  check("another object name fails authentication (a record cannot be moved)", await throws(() => V.decryptTitle(b64(vec.good), device, "onn-title/other_title.enc")) === "auth");
  const flip = b64(vec.good); flip[flip.length - 1] ^= 1;
  check("a flipped ciphertext bit fails authentication", await throws(() => V.decryptTitle(flip, device, vec.name)) === "auth");
  check("a record for another package (SmartTube) is refused", await throws(() => V.decryptTitle(b64(vec.other_pkg), device, vec.name)) === "not-title");
  check("an unknown version is refused", await throws(() => V.decryptTitle(b64(vec.bad_version), device, vec.name)) === "not-title");
  check("an empty title is refused", await throws(() => V.decryptTitle(b64(vec.empty), device, vec.name)) === "not-title");
  check("a title over 400 characters is refused", await throws(() => V.decryptTitle(b64(vec.huge), device, vec.name)) === "not-title");
  check("plaintext that is not JSON is refused", await throws(() => V.decryptTitle(b64(vec.not_json), device, vec.name)) === "not-title");
  check("a JPEG is not a title, and a title is not a frame", await throws(() => V.decryptTitle(b64(vec.jpeg_bytes), device, vec.name)) === "not-title"
        && await throws(() => V.decryptFrame(b64(vec.good), device, vec.name)) === "not-image");
  check("frames still decrypt exactly as before (JPEG path unchanged)", (await V.decryptFrame(b64(vec.jpeg_bytes), device, vec.name)).length === 44);
  check("garbage is refused as a bad format", ["bad-format", "legacy"].includes(await throws(() => V.decryptTitle(new Uint8Array(64), device, vec.name))));
  console.log(fails === 0 ? "\nALL OK" : `\nFAILED: ${fails}`);
  process.exit(fails === 0 ? 0 : 1);
})();
