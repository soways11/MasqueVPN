package android.app;
import android.content.Context;
import android.content.DialogInterface;
public class AlertDialog {
    public static class Builder {
        public Builder(Context c) {}
        public Builder setTitle(int id) { return this; }
        public Builder setTitle(CharSequence t) { return this; }
        public Builder setMessage(int id) { return this; }
        public Builder setView(android.view.View v) { return this; }
        public Builder setPositiveButton(int id, DialogInterface.OnClickListener l) { return this; }
        public Builder setNegativeButton(int id, DialogInterface.OnClickListener l) { return this; }
        public AlertDialog show() { return null; }
    }
}
