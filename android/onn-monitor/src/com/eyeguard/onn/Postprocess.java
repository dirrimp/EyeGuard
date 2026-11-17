package com.eyeguard.onn;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Turns NudeNet 320n's raw output into the Mac's flag decision, step for step like nudenet's _postprocess + eyeguard/detector.py:
 *   1. per anchor: the highest-scoring class of all 18 (first one wins a tie); keep the anchor if that score is >= 0.2;
 *   2. its box is scaled back to the screenshot (letterboxed to a square of max(w,h)) and clipped to the image;
 *   3. class-agnostic non-max suppression, exactly cv2.dnn.NMSBoxes(boxes, scores, 0.25, 0.45): only scores > 0.25 take part,
 *      candidates in descending score order (stable), one is dropped if its IoU with an already kept box is > 0.45;
 *   4. of the survivors, the best one whose class is one of the four explicit labels is the frame's hit;
 *   5. it is a flag when that score is >= 0.80 (config.yaml detection.flag_threshold).
 *  A higher-scoring non-explicit box (e.g. FEMALE_BREAST_COVERED) can therefore suppress an overlapping explicit one: that is the Mac's
 *  behaviour and is kept on purpose, so "0.80" means the same thing on both devices.
 *  Output layout: [1, 22, anchors] flattened, channel-major (4 box values, then 18 class scores). Pure JDK: tested on a plain JVM. */
final class Postprocess {
    private Postprocess() {}

    static final String[] LABELS = {
        "FEMALE_GENITALIA_COVERED", "FACE_FEMALE", "BUTTOCKS_EXPOSED", "FEMALE_BREAST_EXPOSED", "FEMALE_GENITALIA_EXPOSED",
        "MALE_BREAST_EXPOSED", "ANUS_EXPOSED", "FEET_EXPOSED", "BELLY_COVERED", "FEET_COVERED", "ARMPITS_COVERED", "ARMPITS_EXPOSED",
        "FACE_MALE", "BELLY_EXPOSED", "MALE_GENITALIA_EXPOSED", "ANUS_COVERED", "FEMALE_BREAST_COVERED", "BUTTOCKS_COVERED"};
    static final int CLASSES = 18, CHANNELS = 22, MODEL_SIDE = 320;
    /** BUTTOCKS_EXPOSED, FEMALE_BREAST_EXPOSED, FEMALE_GENITALIA_EXPOSED, ANUS_EXPOSED (male genitalia is deliberately not flagged). */
    static final int[] EXPLICIT = {2, 3, 4, 6};
    static final float MIN_ANCHOR_SCORE = 0.2f;
    static final double NMS_SCORE = 0.25, NMS_IOU = 0.45;
    static final float FLAG_THRESHOLD = 0.80f;

    /** Best surviving explicit detection; label is -1 and score 0 when there is none. */
    static final class Hit {
        final int label;
        final float score;
        Hit(int label, float score) { this.label = label; this.score = score; }
        boolean isFlag() { return label >= 0 && score >= FLAG_THRESHOLD; }
        String labelName() { return label >= 0 ? LABELS[label] : "NONE"; }
    }

    private static final class Cand {
        final int cls; final float score; final double x, y, w, h;
        Cand(int cls, float score, double x, double y, double w, double h) { this.cls = cls; this.score = score; this.x = x; this.y = y; this.w = w; this.h = h; }
    }

    static boolean isExplicit(int c) {
        for (int e : EXPLICIT) if (e == c) return true;
        return false;
    }

    /** OpenCV's rectOverlap (1 - jaccardDistance): intersection over union, EXCEPT that two boxes whose areas sum to ~0 (both clipped to
     *  zero height or width at the image edge) count as identical, overlap 1, so one of them is suppressed. Found by checking this port
     *  against the Mac's real output (tests/test_onn_frameprep_static.py, case 18). */
    private static double overlap(Cand a, Cand b) {
        double aa = a.w * a.h, ab = b.w * b.h;
        if (aa + ab <= Math.ulp(1.0)) return 1.0;
        double iw = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
        double ih = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
        double inter = (iw > 0 && ih > 0) ? iw * ih : 0.0;
        return inter / (aa + ab - inter);
    }

    /** @param origW,origH size of the screenshot the 320x320 input was made from (letterboxed to max(w,h)). */
    static Hit analyze(float[] out, int anchors, int origW, int origH) {
        if (anchors < 1 || out.length != CHANNELS * anchors || origW < 1 || origH < 1) throw new IllegalArgumentException("unexpected output");
        double pad = Math.max(origW, origH);                    // W + x_pad == H + y_pad == max(W, H)
        List<Cand> cands = new ArrayList<>();
        for (int i = 0; i < anchors; i++) {
            int cls = 0;
            float s = out[4 * anchors + i];
            for (int k = 1; k < CLASSES; k++) {
                float v = out[(4 + k) * anchors + i];
                if (v > s) { s = v; cls = k; }
            }
            if (s < MIN_ANCHOR_SCORE) continue;
            double cx = out[i], cy = out[anchors + i], bw = out[2 * anchors + i], bh = out[3 * anchors + i];
            double x = (cx - bw / 2) * pad / MODEL_SIDE, y = (cy - bh / 2) * pad / MODEL_SIDE;
            double w = bw * pad / MODEL_SIDE, h = bh * pad / MODEL_SIDE;
            x = Math.max(0, Math.min(x, origW));
            y = Math.max(0, Math.min(y, origH));
            w = Math.min(w, origW - x);
            h = Math.min(h, origH - y);
            cands.add(new Cand(cls, s, x, y, w, h));
        }
        List<Cand> pool = new ArrayList<>();
        for (Cand c : cands) if (c.score > NMS_SCORE) pool.add(c);
        Collections.sort(pool, (a, b) -> Float.compare(b.score, a.score));      // List.sort is stable: ties keep anchor order, like std::stable_sort
        List<Cand> kept = new ArrayList<>();
        for (Cand c : pool) {
            boolean keep = true;
            for (Cand k : kept) {
                if (overlap(c, k) > NMS_IOU) { keep = false; break; }
            }
            if (keep) kept.add(c);
        }
        int bestLabel = -1;
        float best = 0f;
        for (Cand c : kept) if (isExplicit(c.cls) && c.score > best) { best = c.score; bestLabel = c.cls; }
        return new Hit(bestLabel, best);
    }
}
