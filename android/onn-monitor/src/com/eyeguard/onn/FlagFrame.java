package com.eyeguard.onn;

import android.graphics.Bitmap;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/** Builds the picture that is kept for a flag: scaled to at most 1280 wide (the Mac captures at max_width 1280), BLURRED like the Mac's
 *  RED frames (Blur: radius width/75), and only then JPEG-encoded at quality 80 (the Mac's setting). The un-blurred pixels exist only inside
 *  this method; nothing else ever receives them. Takes a SOFTWARE ARGB bitmap (a hardware bitmap cannot be read). */
final class FlagFrame {
    private FlagFrame() {}

    static final int MAX_WIDTH = 1280;
    static final int JPEG_QUALITY = 80;

    static byte[] blurredJpeg(Bitmap sw) {
        int w = sw.getWidth(), h = sw.getHeight();
        int tw = Math.min(w, MAX_WIDTH), th = Math.max(1, Math.round(h * (float) tw / w));
        Bitmap scaled = tw == w ? sw : Bitmap.createScaledBitmap(sw, tw, th, true);
        int[] px = new int[tw * th];
        scaled.getPixels(px, 0, tw, 0, 0, tw, th);
        if (scaled != sw) scaled.recycle();
        Blur.gaussian(px, tw, th, Blur.radiusFor(tw));                         // blur FIRST
        Bitmap out = Bitmap.createBitmap(px, tw, th, Bitmap.Config.ARGB_8888);
        Arrays.fill(px, 0);
        ByteArrayOutputStream bo = new ByteArrayOutputStream(160_000);
        out.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, bo);             // encode only the blurred pixels
        out.recycle();
        return bo.toByteArray();
    }
}
