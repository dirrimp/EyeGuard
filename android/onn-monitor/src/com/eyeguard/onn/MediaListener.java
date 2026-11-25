package com.eyeguard.onn;

import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.service.notification.NotificationListenerService;

/** Android only lets an app read media sessions if it holds a notification-listener component. This is that component and NOTHING more:
 *  it overrides no callback, so it never receives, reads, stores or sends a notification (tests/test_onn_app_static.py fails the build if
 *  this class ever references a notification). It exists so MediaProbe may call MediaSessionManager.getActiveSessions.
 *  It is switched on only by the ADB install step (cmd notification allow_listener); the app cannot enable it itself. */
public class MediaListener extends NotificationListenerService {

    /** true when the system has granted this app listener access: reported to the server as listener_ok. */
    static boolean granted(Context c) {
        try {
            NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
            return nm != null && nm.isNotificationListenerAccessGranted(new ComponentName(c, MediaListener.class));
        } catch (Throwable t) {
            return false;
        }
    }
}
