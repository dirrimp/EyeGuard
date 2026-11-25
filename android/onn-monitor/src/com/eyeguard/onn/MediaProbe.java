package com.eyeguard.onn;

import android.content.ComponentName;
import android.content.Context;
import android.media.MediaMetadata;
import android.media.session.MediaController;
import android.media.session.MediaSessionManager;
import android.media.session.PlaybackState;
import java.util.List;

/** Reads ONLY YouTube TV's media session: whether it is playing and, when it is, the title. Every other session is skipped by package
 *  name before anything about it is read (no state, no metadata). Blocking binder calls: io thread only. */
final class MediaProbe {
    private MediaProbe() {}

    static final class Reading {
        final boolean ok;        // false when the listener is not enabled (nothing could be read)
        final boolean playing;   // YouTube TV's session exists and its state is PLAYING
        final String title;      // cleaned title when playing, else null
        Reading(boolean ok, boolean playing, String title) { this.ok = ok; this.playing = playing; this.title = title; }
    }

    static Reading youtubeTv(Context c) {
        try {
            MediaSessionManager m = (MediaSessionManager) c.getSystemService(Context.MEDIA_SESSION_SERVICE);
            if (m == null) return new Reading(false, false, null);
            List<MediaController> list = m.getActiveSessions(new ComponentName(c, MediaListener.class));
            for (MediaController mc : list) {
                if (!MediaFacts.YOUTUBE_TV.equals(mc.getPackageName())) continue;     // nothing else is ever read
                PlaybackState st = mc.getPlaybackState();
                boolean playing = st != null && st.getState() == PlaybackState.STATE_PLAYING;
                String title = null;
                if (playing) {
                    MediaMetadata md = mc.getMetadata();
                    if (md != null) title = MediaFacts.cleanTitle(md.getString(MediaMetadata.METADATA_KEY_TITLE));
                }
                return new Reading(true, playing, title);
            }
            return new Reading(true, false, null);
        } catch (SecurityException e) {
            return new Reading(false, false, null);       // listener access not granted
        } catch (Throwable t) {
            return new Reading(false, false, null);
        }
    }
}
