package org.json;
public class JSONObject {
    public JSONObject() {}
    public JSONObject(String json) throws JSONException {}
    public String optString(String k) { return ""; }
    public String optString(String k, String def) { return def; }
    public int optInt(String k) { return 0; }
    public int optInt(String k, int def) { return def; }
    public boolean optBoolean(String k) { return false; }
    public boolean optBoolean(String k, boolean def) { return def; }
    public JSONObject optJSONObject(String k) { return null; }
    public JSONArray optJSONArray(String k) { return null; }
    public String getString(String k) throws JSONException { return ""; }
    public JSONObject put(String k, Object v) throws JSONException { return this; }
    public String toString() { return "{}"; }
}
