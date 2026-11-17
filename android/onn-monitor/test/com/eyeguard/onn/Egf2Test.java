package com.eyeguard.onn;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/** Plain-JVM test for Egf2 (NOT part of the APK: build.sh compiles only src/). Run against the vectors made by
 *  tools/onn_egf2_interop.py:  java -cp <classes> com.eyeguard.onn.Egf2Test <dir>
 *  It decrypts the PYTHON-made frame with every recipient key, tries the attacks that must fail, and writes java.enc,
 *  which the Python tool then decrypts (the other direction). Exit code 0 only if everything passes. */
public class Egf2Test {
    static int fails = 0;

    static void check(String name, boolean ok) {
        System.out.println("  [" + (ok ? "ok  " : "FAIL") + "] " + name);
        if (!ok) fails++;
    }

    static byte[] decrypt(byte[] blob, PrivateKey priv, byte[] myKid, String name) throws Exception {
        if (blob.length < 5 + 12 + 16 || blob[0] != 'E' || blob[1] != 'G' || blob[2] != 'F' || blob[3] != '2') throw new IllegalArgumentException("not EGF2");
        int n = blob[4] & 0xff, pos = 5;
        byte[] wrapped = null;
        for (int i = 0; i < n; i++) {
            byte[] kid = Arrays.copyOfRange(blob, pos, pos + 8);
            int len = ((blob[pos + 8] & 0xff) << 8) | (blob[pos + 9] & 0xff);
            if (Arrays.equals(kid, myKid)) wrapped = Arrays.copyOfRange(blob, pos + 10, pos + 10 + len);
            pos += 10 + len;
        }
        if (wrapped == null) throw new SecurityException("not a recipient");
        byte[] nonce = Arrays.copyOfRange(blob, pos, pos + 12);
        byte[] ct = Arrays.copyOfRange(blob, pos + 12, blob.length);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, priv, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] aes = rsa.doFinal(wrapped);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(128, nonce));
        gcm.updateAAD(("EGF2|" + name).getBytes(StandardCharsets.UTF_8));
        return gcm.doFinal(ct);
    }

    static boolean fails(Runnable r) { try { r.run(); return false; } catch (RuntimeException e) { return true; } }

    public static void main(String[] a) throws Exception {
        Path d = Paths.get(a[0]);
        byte[] plain = Files.readAllBytes(d.resolve("plain.bin"));
        String name = new String(Files.readAllBytes(d.resolve("name.txt")), StandardCharsets.UTF_8).trim();
        byte[] py = Files.readAllBytes(d.resolve("py.enc"));
        int count = Integer.parseInt(new String(Files.readAllBytes(d.resolve("count.txt")), StandardCharsets.UTF_8).trim());
        List<Egf2.Recipient> rec = new ArrayList<>();
        List<PrivateKey> privs = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            rec.add(Egf2.parse(new String(Files.readAllBytes(d.resolve("pub" + i + ".pem")), StandardCharsets.UTF_8)));
            privs.add(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(d.resolve("priv" + i + ".pk8")))));
        }

        System.out.println("Java decrypts the Python-made frame");
        for (int i = 0; i < count; i++) {
            byte[] got = decrypt(py, privs.get(i), rec.get(i).kid, name);
            check("recipient " + i + " (key id " + hex(rec.get(i).kid) + ") recovers the plaintext", Arrays.equals(got, plain));
        }
        final int last = count - 1;
        check("a different object name fails (AAD binds the name)", fails(() -> { try { decrypt(py, privs.get(0), rec.get(0).kid, "x" + name); } catch (Exception e) { throw new RuntimeException(e); } }));
        byte[] flipped = py.clone(); flipped[flipped.length - 20] ^= 1;
        check("one flipped ciphertext bit fails (GCM tag)", fails(() -> { try { decrypt(flipped, privs.get(0), rec.get(0).kid, name); } catch (Exception e) { throw new RuntimeException(e); } }));
        check("a key that is not a recipient is refused", fails(() -> { try { decrypt(py, privs.get(0), new byte[8], name); } catch (Exception e) { throw new RuntimeException(e); } }));

        System.out.println("Java encrypts, Python will decrypt");
        byte[] mine = Egf2.encrypt(plain, rec, name);
        Files.write(d.resolve("java.enc"), mine);
        check("starts with EGF2 and the right recipient count", mine[0] == 'E' && mine[1] == 'G' && mine[2] == 'F' && mine[3] == '2' && (mine[4] & 0xff) == count);
        for (int i = 0; i < count; i++) check("Java round trip for recipient " + i, Arrays.equals(decrypt(mine, privs.get(i), rec.get(i).kid, name), plain));
        check("two encryptions of the same frame differ (fresh key and nonce)", !Arrays.equals(mine, Egf2.encrypt(plain, rec, name)));

        System.out.println("limits");
        List<Egf2.Recipient> dup = new ArrayList<>(rec); dup.add(rec.get(0));
        check("a duplicate recipient is counted once", (Egf2.encrypt(plain, dup, name)[4] & 0xff) == count);
        check("zero recipients are refused", fails(() -> { try { Egf2.encrypt(plain, new ArrayList<>(), name); } catch (Exception e) { throw new RuntimeException(e); } }));
        check("a key under 2048 bits is refused", fails(() -> { try { Egf2.parse(new String(Files.readAllBytes(d.resolve("small.pem")), StandardCharsets.UTF_8)); } catch (Exception e) { throw new RuntimeException(e); } }));
        check("an unusable first (Dad's) key aborts parseAll", fails(() -> { try { Egf2.parseAll(new String[] {"not a key"}); } catch (Exception e) { throw new RuntimeException(e); } }));
        check("an unusable later key is skipped, not fatal", Egf2.parseAll(new String[] {new String(Files.readAllBytes(d.resolve("pub0.pem")), StandardCharsets.UTF_8), "not a key"}).size() == 1);
        List<Egf2.Recipient> nine = new ArrayList<>();
        for (int i = 0; i < 9; i++) nine.add(Egf2.parse(new String(Files.readAllBytes(d.resolve("extra" + i + ".pem")), StandardCharsets.UTF_8)));
        check("nine distinct recipients are refused (max 8)", fails(() -> { try { Egf2.encrypt(plain, nine, name); } catch (Exception e) { throw new RuntimeException(e); } }));

        System.out.println(fails == 0 ? "\nALL OK" : "\nFAILED: " + fails);
        System.exit(fails == 0 ? 0 : 1);
    }

    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x & 0xff)); return s.toString(); }
}
