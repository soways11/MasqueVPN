package android.content.pm;
public abstract class PackageManager {
    public static final int PERMISSION_GRANTED = 0;
    public abstract PackageInfo getPackageInfo(String p, int flags) throws NameNotFoundException;
    public static class NameNotFoundException extends Exception {}
}
