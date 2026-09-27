package org.json;
public class JSONArray {
    public JSONArray() {}
    public JSONArray(String json) throws JSONException {}
    public int length() { return 0; }
    public String getString(int i) throws JSONException { return ""; }
    public JSONObject getJSONObject(int i) throws JSONException { return null; }
    public JSONArray put(Object v) { return this; }
}
