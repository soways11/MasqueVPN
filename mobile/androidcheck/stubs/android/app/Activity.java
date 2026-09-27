package android.app;
import android.content.Intent;
public class Activity extends android.content.ContextWrapper {
    public static final int RESULT_OK = -1;
    protected void onCreate(android.os.Bundle b) {}
    protected void onSaveInstanceState(android.os.Bundle b) {}
    protected void onResume() {}
    protected void onPause() {}
    protected void onNewIntent(Intent i) {}
    @Deprecated protected void onActivityResult(int req, int res, Intent data) {}
    public void setContentView(int layout) {}
    public <T extends android.view.View> T findViewById(int id) { return null; }
    public Intent getIntent() { return null; }
    public void finish() {}
    @Deprecated public void startActivityForResult(Intent i, int code) {}
    public final void requestPermissions(String[] p, int code) {}
}
