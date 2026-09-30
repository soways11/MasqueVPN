package android.content;
public abstract class Context {
    public static final int MODE_PRIVATE = 0;
    public abstract SharedPreferences getSharedPreferences(String name, int mode);
    public final <T> T getSystemService(Class<T> c) { return null; }
    public final String getString(int id) { return null; }
    public final String getString(int id, Object... args) { return null; }
    public final int getColor(int id) { return 0; }
    public abstract String getPackageName();
    public abstract android.content.pm.PackageManager getPackageManager();
    public abstract android.content.res.Resources getResources();
    public abstract java.io.File getFilesDir();
    public abstract void startActivity(Intent i);
    public abstract ComponentName startService(Intent i);
    public abstract ComponentName startForegroundService(Intent i);
    public int checkSelfPermission(String p) { return 0; }
}
