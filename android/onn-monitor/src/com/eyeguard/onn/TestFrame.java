package com.eyeguard.onn;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Shader;

/** The picture used by the end-to-end self-test: a SYNTHETIC gradient with plain text. It is drawn here from code; it is never a screenshot
 *  and never depicts anything. It goes through exactly the same path as a real flagged frame (blur, JPEG, encrypt, upload, record) so the whole
 *  path can be proven on the box without any real content. */
final class TestFrame {
    private TestFrame() {}

    static Bitmap create() {
        Bitmap b = Bitmap.createBitmap(1280, 720, Bitmap.Config.ARGB_8888);
        Canvas c = new Canvas(b);
        Paint bg = new Paint();
        bg.setShader(new LinearGradient(0, 0, 1280, 720, Color.rgb(20, 60, 140), Color.rgb(230, 190, 60), Shader.TileMode.CLAMP));
        c.drawRect(0, 0, 1280, 720, bg);
        Paint t = new Paint(Paint.ANTI_ALIAS_FLAG);
        t.setColor(Color.WHITE);
        t.setTextSize(72);
        c.drawText("EYEGUARD ONN", 80, 260, t);
        c.drawText("END-TO-END TEST FRAME", 80, 360, t);
        t.setTextSize(54);
        c.drawText("SYNTHETIC - NOT A DETECTION", 80, 450, t);
        return b;
    }
}
