package com.ninebotsign.lsp;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;

import java.util.LinkedHashMap;
import java.util.Map;

public class ConfProvider extends ContentProvider {

    public static final String AUTHORITY = "com.ninebotsign.lsp.conf";

    public static final String VEHICLE_SEGMENT = "vehicle";

    private static final String[] KEYS = {
            "vehicleImage", "vehicleImagePath", "vehicleImageStamp", "bgImage", "bgImagePath", "autoCheck",

            "showNitro",

            "fakeExpiry",

            "autoShare", "fakeShare", "postId", "apiLog"};

    public boolean onCreate() {
        return true;
    }

    public static String confText(Context ctx) {
        if (ctx == null) {
            return null;
        }
        try {
            SharedPreferences p = ctx.getSharedPreferences(SettingsActivity.PREF, Context.MODE_PRIVATE);
            if (!"1".equals(p.getString("ui", ""))) {
                return null;
            }
            Map<String, String> m = new LinkedHashMap<String, String>();
            for (int i = 0; i < KEYS.length; i++) {
                String v = p.getString(KEYS[i], "");
                m.put(KEYS[i], v == null ? "" : v);
            }
            return ConfText.build(m);
        } catch (Throwable t) {
            return null;
        }
    }

    public Bundle call(String method, String arg, Bundle extras) {
        Bundle b = new Bundle();
        b.putString("conf", confText(getContext()));
        return b;
    }

    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        return null;
    }

    public android.os.ParcelFileDescriptor openFile(Uri uri, String mode) {
        try {
            if (uri == null || !VEHICLE_SEGMENT.equals(uri.getLastPathSegment())) {
                return null;
            }
            java.io.File f = new java.io.File(getContext().getFilesDir(),
                    SettingsActivity.VEHICLE_SRC);
            if (!f.exists() || f.length() <= 0L) {
                return null;
            }
            return android.os.ParcelFileDescriptor.open(f,
                    android.os.ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (Throwable t) {
            return null;
        }
    }

    public String getType(Uri uri) {
        if (uri != null && VEHICLE_SEGMENT.equals(uri.getLastPathSegment())) {
            return "image/png";
        }
        return null;
    }

    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    public int delete(Uri uri, String selection, String[] args) {
        return 0;
    }

    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        return 0;
    }
}
