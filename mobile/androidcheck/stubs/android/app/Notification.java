package android.app;
import android.content.Context;
public class Notification {
    public static class Builder {
        public Builder(Context c, String channel) {}
        public Builder setContentTitle(CharSequence t) { return this; }
        public Builder setContentText(CharSequence t) { return this; }
        public Builder setSmallIcon(int icon) { return this; }
        public Builder setColor(int c) { return this; }
        public Builder setContentIntent(PendingIntent i) { return this; }
        public Builder addAction(Action a) { return this; }
        public Builder setOngoing(boolean on) { return this; }
        public Notification build() { return null; }
    }
    public static class Action {
        public static final class Builder {
            public Builder(android.graphics.drawable.Icon icon, CharSequence title, PendingIntent intent) {}
            @Deprecated public Builder(int icon, CharSequence title, PendingIntent intent) {}
            public Action build() { return null; }
        }
    }
}
