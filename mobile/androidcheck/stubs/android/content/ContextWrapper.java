package android.content;
public class ContextWrapper extends Context {
    public SharedPreferences getSharedPreferences(String name, int mode) { return null; }
    public String getPackageName() { return null; }
    public android.content.pm.PackageManager getPackageManager() { return null; }
    public android.content.res.Resources getResources() { return null; }
    public void startActivity(Intent i) {}
    public ComponentName startService(Intent i) { return null; }
    public ComponentName startForegroundService(Intent i) { return null; }
}
