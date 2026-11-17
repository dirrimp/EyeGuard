package com.eyeguard.onn;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/** EGF2 frame encryption, byte-compatible with eyeguard/frame_crypto.py (encrypt_frame_v2) and the dashboard viewer.
 *  Pure JDK (no Android classes) so it can be unit-tested on a plain JVM against the Python decryptor.
 *
 *  "EGF2" | u8 n | n x [8-byte key id | u16 wrapped length | RSA-OAEP(SHA-256, MGF1-SHA-256) wrapped AES key]
 *         | 12-byte nonce | AES-256-GCM ciphertext+tag      AAD = "EGF2|" + the stored object name
 *  key id = first 8 bytes of SHA-256(DER SubjectPublicKeyInfo).  Max 8 recipients, RSA >= 2048.
 *  Only PUBLIC keys ever exist in this app. A frame is encrypted in memory, so the plaintext never touches storage. */
final class Egf2 {
    static final int MAX_RECIPIENTS = 8;
    static final int MIN_RSA_BITS = 2048;
    private static final byte[] MAGIC = {'E', 'G', 'F', '2'};

    private Egf2() {}

    /** One recipient: the key and its 8-byte id, both derived from the SAME DER bytes the PEM carries. */
    static final class Recipient {
        final byte[] kid;
        final PublicKey key;
        private Recipient(byte[] kid, PublicKey key) { this.kid = kid; this.key = key; }
    }

    /** Parse a "-----BEGIN PUBLIC KEY-----" PEM; refuses anything that is not RSA of at least 2048 bits. */
    static Recipient parse(String pem) throws GeneralSecurityException {
        String b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(b64);
        PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        if (!(pk instanceof RSAPublicKey) || ((RSAPublicKey) pk).getModulus().bitLength() < MIN_RSA_BITS) {
            throw new InvalidKeyException("recipient key must be RSA >= 2048 bits");
        }
        return new Recipient(Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(der), 8), pk);
    }

    /** Parse many PEMs; keys that do not parse are SKIPPED (the Mac does the same) but the first one (Dad's) must be valid. */
    static List<Recipient> parseAll(String[] pems) throws GeneralSecurityException {
        List<Recipient> out = new ArrayList<>();
        for (int i = 0; i < pems.length; i++) {
            try {
                out.add(parse(pems[i]));
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                if (i == 0) throw new InvalidKeyException("Dad's key (recipient #1) is not usable");
            }
        }
        return out;
    }

    static byte[] encrypt(byte[] plain, List<Recipient> recipients, String objectName) throws GeneralSecurityException {
        LinkedHashMap<String, Recipient> distinct = new LinkedHashMap<>();
        for (Recipient r : recipients) distinct.putIfAbsent(Arrays.toString(r.kid), r);
        int n = distinct.size();
        if (n < 1 || n > MAX_RECIPIENTS) throw new InvalidKeyException("need 1.." + MAX_RECIPIENTS + " distinct recipients, got " + n);

        SecureRandom rnd = new SecureRandom();
        byte[] aes = new byte[32];
        byte[] nonce = new byte[12];
        rnd.nextBytes(aes);
        rnd.nextBytes(nonce);
        try {
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(128, nonce));
            gcm.updateAAD(("EGF2|" + objectName).getBytes(StandardCharsets.UTF_8));
            byte[] ct = gcm.doFinal(plain);

            ByteArrayOutputStream out = new ByteArrayOutputStream(ct.length + 600 * n);
            out.write(MAGIC, 0, 4);
            out.write(n);
            OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            for (Recipient r : distinct.values()) {
                Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsa.init(Cipher.ENCRYPT_MODE, r.key, oaep);
                byte[] wrapped = rsa.doFinal(aes);
                out.write(r.kid, 0, 8);
                out.write(wrapped.length >> 8);
                out.write(wrapped.length & 0xff);
                out.write(wrapped, 0, wrapped.length);
            }
            out.write(nonce, 0, 12);
            out.write(ct, 0, ct.length);
            return out.toByteArray();
        } finally {
            Arrays.fill(aes, (byte) 0);
        }
    }
}
