package com.eyeguard.onn;

/** Gaussian-like blur for a flagged frame BEFORE it is encoded, encrypted or leaves memory, matching the Mac's FlagLogger
 *  (PIL GaussianBlur(radius) with radius = max(6, width // blur_strength), blur_strength 75 in config.yaml), so partners see
 *  no more from the Onn than from the Mac. Three clamp-to-edge box blurs sized by the standard "boxes for Gauss" method; on a
 *  1280x720 test frame it differs from PIL by a mean of 0.2 of 255 (tools/onn_frameprep_vectors.py measures this).
 *  Pure JDK (no Android classes): tested on a plain JVM. */
final class Blur {
    private Blur() {}

    static final int BLUR_STRENGTH = 75;      // config.yaml logging.blur_strength

    /** The Mac's radius for an image of this width. */
    static int radiusFor(int width) { return Math.max(6, width / BLUR_STRENGTH); }

    /** Blur ARGB pixels in place. Alpha is kept as is. */
    static void gaussian(int[] px, int w, int h, int sigma) {
        if (px.length != w * h || w < 1 || h < 1 || sigma < 1) throw new IllegalArgumentException("bad blur arguments");
        int[] sizes = boxSizes(sigma);
        int[] tmp = new int[px.length];
        for (int size : sizes) {
            int r = (size - 1) / 2;
            boxH(px, tmp, w, h, r);
            boxV(tmp, px, w, h, r);
        }
    }

    /** Three odd box sizes whose combined blur approximates a Gaussian of the given sigma. */
    static int[] boxSizes(int sigma) {
        int n = 3;
        double wIdeal = Math.sqrt(12.0 * sigma * sigma / n + 1);
        int wl = (int) Math.floor(wIdeal);
        if (wl % 2 == 0) wl--;
        int wu = wl + 2;
        int m = (int) Math.round((12.0 * sigma * sigma - n * wl * wl - 4.0 * n * wl - 3.0 * n) / (-4.0 * wl - 4.0));
        int[] sizes = new int[n];
        for (int i = 0; i < n; i++) sizes[i] = i < m ? wl : wu;
        return sizes;
    }

    private static void boxH(int[] src, int[] dst, int w, int h, int r) {
        int win = 2 * r + 1;
        for (int y = 0; y < h; y++) {
            int row = y * w;
            long sa = 0, sr = 0, sg = 0, sb = 0;
            for (int k = -r; k <= r; k++) {                      // window centred on x = 0, clamped to the edge
                int p = src[row + clamp(k, w)];
                sa += p >>> 24; sr += (p >> 16) & 0xff; sg += (p >> 8) & 0xff; sb += p & 0xff;
            }
            for (int x = 0; x < w; x++) {
                dst[row + x] = ((int) ((sa + win / 2) / win) << 24) | ((int) ((sr + win / 2) / win) << 16)
                             | ((int) ((sg + win / 2) / win) << 8) | (int) ((sb + win / 2) / win);
                int out = src[row + clamp(x - r, w)], in = src[row + clamp(x + r + 1, w)];
                sa += (in >>> 24) - (out >>> 24);
                sr += ((in >> 16) & 0xff) - ((out >> 16) & 0xff);
                sg += ((in >> 8) & 0xff) - ((out >> 8) & 0xff);
                sb += (in & 0xff) - (out & 0xff);
            }
        }
    }

    private static void boxV(int[] src, int[] dst, int w, int h, int r) {
        int win = 2 * r + 1;
        for (int x = 0; x < w; x++) {
            long sa = 0, sr = 0, sg = 0, sb = 0;
            for (int k = -r; k <= r; k++) {
                int p = src[clamp(k, h) * w + x];
                sa += p >>> 24; sr += (p >> 16) & 0xff; sg += (p >> 8) & 0xff; sb += p & 0xff;
            }
            for (int y = 0; y < h; y++) {
                dst[y * w + x] = ((int) ((sa + win / 2) / win) << 24) | ((int) ((sr + win / 2) / win) << 16)
                               | ((int) ((sg + win / 2) / win) << 8) | (int) ((sb + win / 2) / win);
                int out = src[clamp(y - r, h) * w + x], in = src[clamp(y + r + 1, h) * w + x];
                sa += (in >>> 24) - (out >>> 24);
                sr += ((in >> 16) & 0xff) - ((out >> 16) & 0xff);
                sg += ((in >> 8) & 0xff) - ((out >> 8) & 0xff);
                sb += (in & 0xff) - (out & 0xff);
            }
        }
    }

    private static int clamp(int i, int n) { return i < 0 ? 0 : (i >= n ? n - 1 : i); }
}
