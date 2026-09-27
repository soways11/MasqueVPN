package android.view;
public interface Menu {
    MenuItem add(int group, int id, int order, int titleRes);
    MenuItem add(int group, int id, int order, CharSequence title);
    void setGroupDividerEnabled(boolean enabled);
}
