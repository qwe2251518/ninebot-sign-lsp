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

/**
 * 给注入进九号进程的模块读设置用的一条通道。
 *
 * <p>为什么不只靠 {@code XSharedPreferences}：真机日志（2026-10-15）里模块打出来的是
 * 「配置读到的 xxx=(没有这个键)」——它读不到设置界面写下的 SharedPreferences
 * （Android 11+ 上模块自己的 shared_prefs 在别的进程里常常读不到），于是配置永远不更新。
 * 这里再开一条内容提供者通道：注入进程用 ContentResolver.call() 拿配置全文，比跨进程读
 * 私有目录可靠得多（任何应用都能调 exported 的 provider）。
 *
 * <p>纯文本拼装复用 {@link ConfText}（和设置界面用的是同一份代码，注入进程里没有 Xposed
 * API 也能跑）。
 */
public class ConfProvider extends ContentProvider {

    /** 和 AndroidManifest 里的 android:authorities 保持一致 */
    public static final String AUTHORITY = "com.ninebotsign.lsp.conf";

    /** 相册选的那张图：注入进程用 openInputStream 从这里取（跨进程、零存储权限） */
    public static final String VEHICLE_SEGMENT = "vehicle";

    private static final String[] KEYS = {
            "vehicleImage", "vehicleImagePath", "vehicleImageStamp", "venergy"};

    public boolean onCreate() {
        return true;
    }

    /** 把界面的设置拼成 ninebot-sign.conf 全文；没在界面上保存过就返回 null */
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

    /**
     * 把相册选的那张图给注入进程读。
     *
     * <p>为什么非得走这里：注入进程跑在九号的身份下，公共相册/别的应用的私有目录它都读不到
     * （Android 11+ 的分区存储），而 {@code Android/data/cn.ninebot.ninebot/files/} 真机上连
     * 宿主 App 自己写都会 EACCES（2026-10-15 19:29 日志）。内容提供者不需要任何权限。
     */
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
