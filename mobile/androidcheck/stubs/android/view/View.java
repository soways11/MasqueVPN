package android.view;
public class View {
    public static final int VISIBLE = 0, INVISIBLE = 4, GONE = 8;
    public static final int FOCUS_DOWN = 130;
    public boolean post(Runnable action) { return true; }
    public boolean canScrollVertically(int direction) { return false; }
    public interface OnClickListener { void onClick(View v); }
    public void setOnClickListener(OnClickListener l) {}
    public int getVisibility() { return 0; }
    public void setVisibility(int v) {}
    public void setBackgroundResource(int id) {}
    public void setBackgroundTintList(android.content.res.ColorStateList t) {}
    public android.content.res.ColorStateList getBackgroundTintList() { return null; }
    public boolean isEnabled() { return true; }
    public void setEnabled(boolean e) {}
    public CharSequence getContentDescription() { return null; }
    public void setContentDescription(CharSequence d) {}
    public float getRotation() { return 0; }
    public void setRotation(float r) {}
    public final boolean requestFocus() { return true; }
    public void setPadding(int l, int t, int r, int b) {}
    public <T extends View> T findViewById(int id) { return null; }
}
