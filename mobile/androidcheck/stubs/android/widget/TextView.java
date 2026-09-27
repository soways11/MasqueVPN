package android.widget;
public class TextView extends android.view.View {
    public interface OnEditorActionListener { boolean onEditorAction(TextView v, int actionId, android.view.KeyEvent event); }
    public CharSequence getText() { return null; }
    public final void setText(CharSequence t) {}
    public final void setText(int resid) {}
    public void setTextColor(int c) {}
    public void setTextAppearance(int resId) {}
    public void setSingleLine() {}
    public void addTextChangedListener(android.text.TextWatcher w) {}
    public void setOnEditorActionListener(OnEditorActionListener l) {}
}
