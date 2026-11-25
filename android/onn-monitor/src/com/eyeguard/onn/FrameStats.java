package com.eyeguard.onn;

import java.security.MessageDigest;
import java.util.HashSet;

/** Counts for ONE heartbeat window. Touched only from the single "io" thread, so no locking.
 *  A frame is examined in memory (32x32 luma) and DISCARDED: nothing about its content leaves the box except
 *  these counts. Invariants the server requires: succeeded <= attempted, analysed <= succeeded,
 *  black <= analysed, distinctHashes <= analysed. attempted is counted when a result ARRIVES (success or failure),
 *  so a result that straddles two windows can never make succeeded exceed attempted. */
final class FrameStats {
    static final int SIDE = 32;
    /** A frame is "black" when every sampled pixel's luma is at most this (0..255). */
    static final int BLACK_MAX_LUMA = 16;

    int attempted, succeeded, analysed, black;
    /** Black frames excused as YouTube TV playing (MediaFacts.exempt). Counted only right after a black frame, so it can never exceed black. */
    int blackExempt;
    /** Was the frame passed to the last success() black? (io thread only, read straight after success().) */
    boolean lastBlack;
    long screenOnMs;
    private final HashSet<Long> hashes = new HashSet<>();

    void failure() { attempted++; }

    /** luma: SIDE*SIDE values 0..255 from the downscaled frame. */
    void success(int[] luma) {
        attempted++; succeeded++;
        lastBlack = false;
        int max = 0;
        for (int v : luma) if (v > max) max = v;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] b = new byte[luma.length];
            for (int i = 0; i < luma.length; i++) b[i] = (byte) (luma[i] >> 2);   // coarse: ignore tiny noise
            byte[] d = md.digest(b);
            long h = 0; for (int i = 0; i < 8; i++) h = (h << 8) | (d[i] & 0xff);
            hashes.add(h);
        } catch (Exception e) {
            return;                              // not analysed: succeeded stays > analysed, which the server allows
        }
        analysed++;
        if (max <= BLACK_MAX_LUMA) { black++; lastBlack = true; }
    }

    /** Call only when lastBlack is true. */
    void exemptLastBlack() { if (lastBlack && blackExempt < black) blackExempt++; }

    int distinct() { return hashes.size(); }

    void reset() { attempted = succeeded = analysed = black = blackExempt = 0; lastBlack = false; screenOnMs = 0; hashes.clear(); }
}
