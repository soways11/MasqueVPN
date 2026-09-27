package android.util;
public final class Log {
    public static final int DEBUG = 3, INFO = 4, WARN = 5, ERROR = 6;
    public static int println(int priority, String tag, String msg) { return 0; }
    public static int e(String tag, String msg, Throwable tr) { return 0; }
}
