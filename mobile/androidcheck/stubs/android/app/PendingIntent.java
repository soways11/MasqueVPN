package android.app;
import android.content.Context;
import android.content.Intent;
public final class PendingIntent {
    public static final int FLAG_UPDATE_CURRENT = 1 << 27;
    public static final int FLAG_IMMUTABLE = 1 << 26;
    public static PendingIntent getActivity(Context c, int req, Intent i, int flags) { return null; }
    public static PendingIntent getService(Context c, int req, Intent i, int flags) { return null; }
}
