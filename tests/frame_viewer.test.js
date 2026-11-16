// Interop + security test for docs/frame-viewer.js: frames made by the PYTHON encryptor (eyeguard/frame_crypto.py)
// must decrypt in WebCrypto, and the refusals must hold. Synthetic frames and throwaway keys only.
//   node tests/frame_viewer.test.js        (uses the bundled python; override with EG_PY=/path/to/python3)
const { execFileSync } = require("node:child_process");
const path = require("node:path"), fs = require("node:fs"), os = require("node:os");
const V = require("../docs/frame-viewer.js");
const PY = process.env.EG_PY || "/Applications/EyeGuard.app/Contents/Resources/python/bin/python3.12";
const ROOT = path.join(__dirname, "..");
let fails = 0;
const check = (n, ok, d = "") => { console.log(`  [${ok ? "ok  " : "FAIL"}] ${n}${!ok && d ? " -- " + d : ""}`); if (!ok) fails++; };
const b64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const py = (code, ...args) => execFileSync(PY, ["-c", code, ...args], { cwd: ROOT, encoding: "utf8", maxBuffer: 1 << 26 }).trim();
const throws = async (fn) => { try { await fn(); return null; } catch (e) { return e.code || e.name; } };

// Python makes: a throwaway 3072-bit "device" key, Dad's 2048 key, and frames for them (v2 two-recipient, v2 Dad-only, v1).
const vec = JSON.parse(py(`
import base64, io, json, sys
sys.path.insert(0, ".")
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import rsa
from eyeguard import frame_crypto as fc
from PIL import Image
b = base64.b64encode
def key(bits):
    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return (k.private_bytes(s.Encoding.DER, s.PrivateFormat.PKCS8, s.NoEncryption()),
            k.public_key().public_bytes(s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo),
            k.public_key().public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo).decode())
dev, dad = key(3072), key(2048)
im = Image.new("RGB", (64, 48), (200, 30, 30)); buf = io.BytesIO(); im.save(buf, "JPEG"); jpg = buf.getvalue()
name = "2026-11-16T12-00-00.123456+00-00_alert_d1.jpg.enc"
print(json.dumps(dict(
  dev_pkcs8=b(dev[0]).decode(), dev_spki=b(dev[1]).decode(), jpg=b(jpg).decode(), name=name,
  two=b(fc.encrypt_frame_v2(jpg, [dad[2], dev[2]], name)).decode(),
  dad_only=b(fc.encrypt_frame_v2(jpg, [dad[2]], name)).decode(),
  v1=b(fc.encrypt_frame(jpg, dad[2])).decode())))
`));

(async () => {
  const subtle = globalThis.crypto.subtle;
  const params = { name: "RSA-OAEP", hash: "SHA-256" };
  const priv = await subtle.importKey("pkcs8", b64(vec.dev_pkcs8), params, false, ["decrypt"]);
  const pub = await subtle.importKey("spki", b64(vec.dev_spki), params, true, ["encrypt"]);
  const device = { privateKey: priv, keyId: await V.keyIdOf(pub) };
  const jpg = b64(vec.jpg), eq = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

  // ---- Python -> WebCrypto ----
  check("a frame from the Python encryptor decrypts in WebCrypto (3072-bit device key)", eq(await V.decryptFrame(b64(vec.two), device, vec.name), jpg));
  check("the key id WebCrypto computes matches the one Python wrote into the header", V.parse(b64(vec.two)).entries.some(e => eq(e.kid, device.keyId)));
  check("a frame for Dad only is refused (not a recipient)", await throws(() => V.decryptFrame(b64(vec.dad_only), device, vec.name)) === "not-recipient");
  check("an old v1 frame is reported as legacy (Dad's device only)", await throws(() => V.decryptFrame(b64(vec.v1), device, vec.name)) === "legacy");
  check("a frame under another object name fails authentication", await throws(() => V.decryptFrame(b64(vec.two), device, "other.jpg.enc")) === "auth");
  const flip = b64(vec.two); flip[flip.length - 3] ^= 1;
  check("a flipped ciphertext bit fails authentication", await throws(() => V.decryptFrame(flip, device, vec.name)) === "auth");
  const hdr = b64(vec.two); { let pos = 5; for (let i = 0; i < hdr[4]; i++) { const len = (hdr[pos + 8] << 8) | hdr[pos + 9];
    if (eq(hdr.slice(pos, pos + 8), device.keyId)) { hdr[pos + 10 + 7] ^= 1; break; } pos += 10 + len; } }  // flip a byte of THIS device's wrapped key
  const t1 = await throws(() => V.decryptFrame(hdr, device, vec.name));
  check("a corrupted wrapped key is refused, never decrypted to garbage", ["auth", "not-recipient"].includes(t1), String(t1));
  const trunc = b64(vec.two).slice(0, 60);
  check("a truncated frame is refused as bad-format", await throws(() => V.decryptFrame(trunc, device, vec.name)) === "bad-format");
  check("random bytes are refused as bad-format", await throws(() => V.decryptFrame(globalThis.crypto.getRandomValues(new Uint8Array(900)), device, vec.name)) === "bad-format");
  const bigN = b64(vec.two); bigN[4] = 200;
  check("an absurd recipient count is refused", await throws(() => V.decryptFrame(bigN, device, vec.name)) === "bad-format");

  // ---- the production path: the BROWSER generates the key, PYTHON encrypts for its public PEM, the browser decrypts ----
  const pair = await V.generateDeviceKey();
  check("the device private key is not extractable", pair.privateKey.extractable === false && (await throws(() => subtle.exportKey("pkcs8", pair.privateKey))) !== null);
  check("the public key is exportable and is a 3072-bit RSA-OAEP key", pair.publicKey.extractable === true && pair.publicKey.algorithm.modulusLength === 3072);
  const pem = await V.publicKeyPem(pair.publicKey);
  check("the public key PEM is a standard SPKI PEM", /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n$/.test(pem));
  const f = path.join(os.tmpdir(), "egv-" + process.pid + ".pem"); fs.writeFileSync(f, pem);
  const blob = b64(py(`
import base64, sys
sys.path.insert(0, ".")
from eyeguard import frame_crypto as fc
dad = fc.load_recipient  # noqa
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import rsa
dadk = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo)
print(base64.b64encode(fc.encrypt_frame_v2(base64.b64decode(sys.argv[2]), [dadk, open(sys.argv[1]).read()], sys.argv[3])).decode())
`, f, vec.jpg, vec.name)); fs.unlinkSync(f);
  const dev2 = { privateKey: pair.privateKey, keyId: await V.keyIdOf(pair.publicKey) };
  check("PYTHON-encrypted for the browser-generated key's PEM, the browser decrypts it (end to end)", eq(await V.decryptFrame(blob, dev2, vec.name), jpg));
  check("the first device cannot read a frame made for the second", await throws(() => V.decryptFrame(blob, device, vec.name)) === "not-recipient");
  check("the fingerprint is the grouped SHA-256 of the SPKI", /^([0-9a-f]{4} ){15}[0-9a-f]{4}$/.test(await V.fingerprintOf(pair.publicKey)));

  // ---- not an image ----
  const notImg = b64(py(`
import base64, sys
sys.path.insert(0, ".")
from eyeguard import frame_crypto as fc
print(base64.b64encode(fc.encrypt_frame_v2(b"<html>not a jpeg</html>", [open(sys.argv[1]).read()], sys.argv[2])).decode())
`, (() => { fs.writeFileSync(f, pem); return f; })(), vec.name)); fs.unlinkSync(f);
  check("a frame that decrypts to something that is not a JPEG is refused", await throws(() => V.decryptFrame(notImg, dev2, vec.name)) === "not-image");

  // ---- frame name vs flag time ----
  const N = "2026-11-16T12-00-00.123456+00-00_alert_d1.jpg.enc";
  check("name time equals the flag time -> matches", V.nameMatchesFlag(N, "2026-11-16T12:00:00.123456+00:00"));
  check("flag time in another timezone notation -> still matches", V.nameMatchesFlag(N, "2026-11-16T07:00:00.123456-05:00"));
  check("a frame from another moment does not match the flag", !V.nameMatchesFlag(N, "2026-11-16T12:05:00+00:00"));
  check("a name that is not in the uploader format never matches", !V.nameMatchesFlag("evil.jpg.enc", "2026-11-16T12:00:00+00:00") && !V.nameMatchesFlag("", "x"));

  console.log(fails ? `\nFAILED: ${fails}` : "\nALL OK"); process.exit(fails ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
