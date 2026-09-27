package android.content;
public class ClipData {
    public static ClipData newPlainText(CharSequence label, CharSequence text) { return null; }
    public int getItemCount() { return 0; }
    public Item getItemAt(int i) { return null; }
    public ClipDescription getDescription() { return null; }
    public static class Item { public CharSequence coerceToText(Context c) { return null; } }
}
