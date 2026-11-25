// EyeGuard review-frame viewer: decrypts "EGF2" frames in the browser with a per-device key that cannot be exported.
// Design and limits: docs/BROWSER-IMAGE-VIEWING-DESIGN.md. Wire format: eyeguard/frame_crypto.py.
//
//   "EGF2" | u8 n | n x [ 8-byte key id | u16 wrapped length | RSA-OAEP(SHA-256) wrapped AES key ]
//          | 12-byte nonce | AES-256-GCM ciphertext+tag        AES-GCM additional data = "EGF2|" + object name
//   key id = first 8 bytes of SHA-256(DER SubjectPublicKeyInfo)
//
// The private key is generated with extractable:false and stored as a CryptoKey in IndexedDB: this page can USE it
// but nothing (this script, an extension, devtools) can read its bytes. It is never sent anywhere. Decrypted bytes live
// only in memory (a blob: URL). Works in the browser (window.EGViewer) and in Node (module.exports) for tests.
(function (root) {
  "use strict";
  const subtle = (root.crypto || require("node:crypto").webcrypto).subtle;
  const MAGIC = [0x45, 0x47, 0x46, 0x32]; // "EGF2"
  const RSA = { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };

  class ViewError extends Error {
    // code: legacy | not-recipient | bad-format | auth | mismatch | not-image | not-title
    constructor(code, message) { super(message || code); this.code = code; }
  }

  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
  const toB64 = (u8) => { let s = ""; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
  const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  // ---- key helpers ----------------------------------------------------------------------------
  async function spkiOf(publicKey) { return new Uint8Array(await subtle.exportKey("spki", publicKey)); }
  async function keyIdOf(publicKey) { return new Uint8Array(await subtle.digest("SHA-256", await spkiOf(publicKey))).slice(0, 8); }
  async function fingerprintOf(publicKey) {  // full SHA-256 of the SPKI, grouped, for reading aloud / comparing
    const h = hex(new Uint8Array(await subtle.digest("SHA-256", await spkiOf(publicKey))));
    return h.match(/.{1,4}/g).join(" ");
  }
  async function publicKeyPem(publicKey) {
    const b64 = toB64(await spkiOf(publicKey)).match(/.{1,64}/g).join("\n");
    return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";
  }
  // extractable:false => the PRIVATE key can never be exported; the public key is always exportable.
  async function generateDeviceKey() { return subtle.generateKey(RSA, false, ["decrypt"]); }

  // ---- format -----------------------------------------------------------------------------------
  function parse(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    if (bytes.length < 5 + 12 + 16) throw new ViewError("bad-format", "too short");
    if (!MAGIC.every((m, i) => bytes[i] === m)) {
      const first = (bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]) >>> 0;  // v1 starts with a length
      throw new ViewError(first > 0 && first < 1024 ? "legacy" : "bad-format", "not an EGF2 frame");
    }
    const n = bytes[4];
    if (n < 1 || n > 8) throw new ViewError("bad-format", "recipient count");
    let pos = 5; const entries = [];
    for (let i = 0; i < n; i++) {
      if (pos + 10 > bytes.length) throw new ViewError("bad-format", "truncated header");
      const len = (bytes[pos + 8] << 8) | bytes[pos + 9];
      if (len < 128 || pos + 10 + len > bytes.length) throw new ViewError("bad-format", "bad wrapped key length");
      entries.push({ kid: bytes.slice(pos, pos + 8), wrapped: bytes.slice(pos + 10, pos + 10 + len) });
      pos += 10 + len;
    }
    if (bytes.length < pos + 12 + 16) throw new ViewError("bad-format", "truncated body");
    return { entries, nonce: bytes.slice(pos, pos + 12), ct: bytes.slice(pos + 12) };
  }

  const isJpeg = (u8) => u8.length > 3 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff;

  // Open one EGF2 envelope: returns the plaintext bytes. `device` = { privateKey: CryptoKey, keyId: Uint8Array(8) }.
  async function openEnvelope(bytes, device, objectName) {
    const f = parse(bytes);
    const mine = f.entries.find((e) => sameBytes(e.kid, device.keyId));
    if (!mine) throw new ViewError("not-recipient", "this device is not a recipient of this record");
    let aesRaw;
    try { aesRaw = new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, device.privateKey, mine.wrapped)); }
    catch (e) { throw new ViewError("auth", "could not unwrap the record key"); }
    let plain;
    try {
      const aes = await subtle.importKey("raw", aesRaw, "AES-GCM", false, ["decrypt"]);
      plain = new Uint8Array(await subtle.decrypt(
        { name: "AES-GCM", iv: f.nonce, additionalData: new TextEncoder().encode("EGF2|" + objectName) }, aes, f.ct));
    } catch (e) { throw new ViewError("auth", "record failed authentication (wrong name, or altered)"); }
    finally { aesRaw.fill(0); }
    return plain;
  }

  // Decrypt one frame. Returns JPEG bytes.
  async function decryptFrame(bytes, device, objectName) {
    const plain = await openEnvelope(bytes, device, objectName);
    if (!isJpeg(plain)) throw new ViewError("not-image", "decrypted bytes are not a JPEG");
    return plain;
  }

  // Decrypt one Onn "what YouTube TV was playing" record (2026-11-24; the same keys and envelope as a frame). The plaintext is
  // {"v":1,"pkg":"com.google.android.youtube.tvunplugged","at":<epoch ms>,"title":"..."}; anything else is refused. The caller must show
  // the title with textContent (never as HTML).
  const YT_PKG = "com.google.android.youtube.tvunplugged";
  async function decryptTitle(bytes, device, objectName) {
    const plain = await openEnvelope(bytes, device, objectName);
    let o;
    try { o = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain)); }
    catch (e) { throw new ViewError("not-title", "decrypted bytes are not a title record"); }
    if (!o || typeof o !== "object" || o.v !== 1 || o.pkg !== YT_PKG || typeof o.title !== "string"
        || o.title.length < 1 || o.title.length > 400 || typeof o.at !== "number" || !Number.isFinite(o.at))
      throw new ViewError("not-title", "decrypted bytes are not a title record");
    return { title: o.title, at: o.at, pkg: o.pkg };
  }

  // The uploader names a frame <timestamp with ':' -> '-'>_<verdict>_d<N>.jpg(.enc); the flag row carries the same
  // timestamp. A frame attached to a flag from another moment is not shown (a server cannot swap images between rows).
  function nameMatchesFlag(objectName, flaggedAt, toleranceMs) {
    const m = /^(\d{4}-\d\d-\d\d)T(\d\d)-(\d\d)-(\d\d(?:\.\d+)?)([+-])(\d\d)-(\d\d)_/.exec(objectName || "");
    if (!m) return false;
    const t = Date.parse(`${m[1]}T${m[2]}:${m[3]}:${m[4]}${m[5]}${m[6]}:${m[7]}`), r = Date.parse(flaggedAt);
    return Number.isFinite(t) && Number.isFinite(r) && Math.abs(t - r) <= (toleranceMs ?? 2000);
  }

  // ---- storage of the device key (browser only) ------------------------------------------------
  const DB = "eyeguard-viewer", STORE = "keys", ID = "device";
  function idb() {
    return new Promise((res, rej) => {
      const r = root.indexedDB.open(DB, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(STORE);
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
  }
  async function tx(mode, fn) {
    const db = await idb();
    return new Promise((res, rej) => {
      const t = db.transaction(STORE, mode), out = fn(t.objectStore(STORE));
      t.oncomplete = () => { db.close(); res(out && out.result); }; t.onerror = () => { db.close(); rej(t.error); };
    });
  }
  async function enroll() {
    const pair = await generateDeviceKey();
    const rec = { privateKey: pair.privateKey, publicKey: pair.publicKey, createdAt: Date.now() };
    await tx("readwrite", (s) => s.put(rec, ID));
    try { if (root.navigator && root.navigator.storage && root.navigator.storage.persist) await root.navigator.storage.persist(); } catch (e) {}
    return describe(rec);
  }
  async function describe(rec) {
    return { privateKey: rec.privateKey, publicKey: rec.publicKey, keyId: await keyIdOf(rec.publicKey),
             fingerprint: await fingerprintOf(rec.publicKey), pem: await publicKeyPem(rec.publicKey), createdAt: rec.createdAt };
  }
  async function loadDevice() {
    let rec; try { rec = await tx("readonly", (s) => s.get(ID)); } catch (e) { return null; }
    return rec && rec.privateKey ? describe(rec) : null;
  }
  async function removeDevice() { await tx("readwrite", (s) => s.delete(ID)); }

  root.EGViewer = { ViewError, generateDeviceKey, keyIdOf, fingerprintOf, publicKeyPem, parse, decryptFrame, decryptTitle,
                    nameMatchesFlag, enroll, loadDevice, removeDevice, isJpeg };
  if (typeof module !== "undefined" && module.exports) module.exports = root.EGViewer;
})(typeof window !== "undefined" ? window : globalThis);
