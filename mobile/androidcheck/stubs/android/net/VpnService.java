package android.net;
import android.content.Context;
import android.content.Intent;
public class VpnService extends android.app.Service {
    public static Intent prepare(Context c) { return null; }
    public boolean protect(int socket) { return true; }
    public void onRevoke() {}
    public class Builder {
        public Builder() {}
        public Builder setSession(String s) { return this; }
        public Builder setMtu(int mtu) { return this; }
        public Builder addAddress(String a, int prefix) { return this; }
        public Builder addRoute(String a, int prefix) { return this; }
        public Builder addDnsServer(String a) { return this; }
        public Builder addDisallowedApplication(String p) throws android.content.pm.PackageManager.NameNotFoundException { return this; }
        public Builder setConfigureIntent(android.app.PendingIntent i) { return this; }
        public android.os.ParcelFileDescriptor establish() { return null; }
    }
}
