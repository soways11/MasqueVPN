package android.app;
import android.content.Intent;
public abstract class Service extends android.content.ContextWrapper {
    public static final int START_NOT_STICKY = 2;
    public static final int STOP_FOREGROUND_REMOVE = 1;
    public int onStartCommand(Intent intent, int flags, int startId) { return 0; }
    public void onDestroy() {}
    public final void startForeground(int id, Notification n) {}
    public final void stopForeground(int flags) {}
    public final void stopSelf() {}
}
