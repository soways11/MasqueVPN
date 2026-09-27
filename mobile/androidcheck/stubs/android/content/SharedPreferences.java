package android.content;
public interface SharedPreferences {
    String getString(String key, String def);
    Editor edit();
    interface Editor {
        Editor putString(String key, String value);
        Editor remove(String key);
        void apply();
    }
}
