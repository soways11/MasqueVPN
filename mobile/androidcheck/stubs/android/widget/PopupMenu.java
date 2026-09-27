package android.widget;
public class PopupMenu {
    public interface OnMenuItemClickListener { boolean onMenuItemClick(android.view.MenuItem item); }
    public PopupMenu(android.content.Context c, android.view.View anchor) {}
    public android.view.Menu getMenu() { return null; }
    public void setOnMenuItemClickListener(OnMenuItemClickListener l) {}
    public void show() {}
}
