package android.content;
public class Intent {
    public Intent(Context c, Class<?> cls) {}
    public Intent(String action) {}
    public Intent setAction(String a) { return this; }
    public String getAction() { return null; }
    public Intent putExtra(String k, String v) { return this; }
    public String getStringExtra(String k) { return null; }
    public android.net.Uri getData() { return null; }
}
