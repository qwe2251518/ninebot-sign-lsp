package com.ninebotsign.lsp;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.provider.Settings;
import android.text.InputType;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.LinkedHashMap;
import java.util.Map;

public class SettingsActivity extends Activity {

    public static final String PREF = "ninebot_sign";

    private static final String NINEBOT_DIR = "/sdcard/Android/data/cn.ninebot.ninebot/files";

    private static final int BG = 0xFFF5F5F7;
    private static final int CARD = 0xFFFFFFFF;
    private static final int TEXT = 0xFF191919;
    private static final int SUB = 0xFF8C8C8C;
    private static final int ACCENT = 0xFF3482FF;
    private static final int DIVIDER = 0xFFEDEDED;
    private static final int FIELD_BG = 0xFFF2F3F5;

    private static final int TINT = 0x1F3482FF;

    private static final int RED_TINT = 0x1FE64340;
    private static final int RED = 0xFFE64340;

    private static final String VER = "3.0";

    private static final String REPO = "https://github.com/qwe2251518/ninebot-sign-lsp";

    private static final String HOME = "https://www.coolapk.com/u/3345275";

    private Switch signOn, vehOn;

    private Switch dashOn;

    private Switch energyOn;

    private Switch nitroOn;

    private Switch fakeExpiryOn;
    private Switch bgOn;
    private Switch autoCheckOn;
    private Switch autoShareSw;
    private Switch fakeShareSw;
    private android.widget.EditText postIdIn;

    private boolean energyTouched = false;
    private boolean nitroTouched = false;
    private EditText vehPath;
    private TextView vehStatus;
    private TextView confStatus;

    private boolean loading = false;
    private static final int REQ_PICK = 1001;
    private static final int REQ_BG = 1002;

    public static final String VEHICLE_SRC = "vehicle-src.png";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setTitle("九号自动签到");
        try {
            getWindow().setStatusBarColor(BG);
            getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
            getWindow().setNavigationBarColor(CARD);
        } catch (Throwable t) {
        }
        setContentView(buildUi());
        try {
            final String bgp0 = sp().getString("bgImagePath", "");
            if (bgp0 != null && bgp0.length() > 0) {
                new Thread(new Runnable() {
                    public void run() {
                        try {
                            String r = copyToNinebotByRoot(bgp0);
                            Log.i("NinebotSign", "\u80cc\u666f\u56fe\uff1a\u542f\u52a8\u91cd\u5efa\u526f\u672c -> " + r);
                        } catch (Throwable t) {
                        }
                    }
                }).start();
            }
        } catch (Throwable t) {
        }
        load();
    }

    private int dp(float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics());
    }

    private GradientDrawable round(int color, float radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.RECTANGLE);
        g.setColor(color);
        g.setCornerRadius(dp(radiusDp));
        return g;
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setBackground(round(CARD, 18));

        c.setPadding(0, 0, 0, dp(10));
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.leftMargin = dp(16);
        p.rightMargin = dp(16);
        p.topMargin = dp(8);
        p.bottomMargin = dp(8);
        c.setLayoutParams(p);
        return c;
    }

    private TextView sectionLabel(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(13);
        t.setTextColor(SUB);
        t.setPadding(dp(30), dp(18), dp(30), dp(6));
        return t;
    }

    private View divider() {
        View v = new View(this);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, dp(0.5f)));
        p.leftMargin = dp(16);
        p.rightMargin = dp(16);
        v.setLayoutParams(p);
        v.setBackgroundColor(DIVIDER);
        return v;
    }

    private TextView label(String text, int size, int color) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextSize(size);
        t.setTextColor(color);
        return t;
    }

    private TextView bgStatus;

    private Switch mkSwitch() {
        Switch s = new MiuiSwitch(this);
        return s;
    }

    static final class MiuiSwitch extends Switch {
        MiuiSwitch(android.content.Context c) {
            super(c);
            setShowText(false);
            setBackground(null);
        }

        private int dpx(float v) {
            return Math.round(v * getResources().getDisplayMetrics().density);
        }

        @Override
        public void onMeasure(int w, int h) {
            super.onMeasure(w, h);
            setMeasuredDimension(dpx(46), dpx(27));
        }

        @Override
        public void setChecked(boolean b) {
            super.setChecked(b);
            invalidate();
        }

        @Override
        protected void drawableStateChanged() {
            super.drawableStateChanged();
            invalidate();
        }

        @Override
        protected void onDraw(android.graphics.Canvas c) {
            android.graphics.Paint pt = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
            float w = getWidth();
            float h = getHeight();
            float r = h / 2f;
            pt.setColor(isChecked() ? 0xFF3482FF : 0xFFDFE0E4);
            c.drawRoundRect(new android.graphics.RectF(0, 0, w, h), r, r, pt);
            float d = h - dpx(3);
            float cx = isChecked() ? (w - dpx(1.5f) - d / 2f) : (dpx(1.5f) + d / 2f);
            pt.setColor(0xFFFFFFFF);
            c.drawCircle(cx, h / 2f, d / 2f, pt);
        }
    }

    private android.view.View noteRow(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(SUB);
        t.setTextSize(13);
        t.setPadding(dp(4), dp(12), dp(4), dp(2));
        return t;
    }

    private LinearLayout row(int glyph, String title, String sub, View control) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setGravity(Gravity.CENTER_VERTICAL);
        r.setPadding(dp(16), dp(12), dp(16), dp(12));
        r.setMinimumHeight(dp(56));

        if (glyph >= 0) {
            LinearLayout.LayoutParams ip = new LinearLayout.LayoutParams(dp(24), dp(24));
            ip.rightMargin = dp(14);
            r.addView(new Glyph(this, glyph), ip);
        }

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        col.addView(label(title, 15, TEXT));
        if (sub != null && sub.length() > 0) {
            TextView s = label(sub, 12, SUB);
            s.setPadding(0, dp(2), 0, 0);
            col.addView(s);
        }
        r.addView(col);
        if (control != null) {
            LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            cp.leftMargin = dp(12);
            control.setLayoutParams(cp);
            r.addView(control);
        }
        return r;
    }

    static final class Glyph extends View {
        static final int CHECK = 1, IMAGE = 2, INFO = 5;
        private final int kind;
        private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);

        Glyph(Context c, int kind) {
            super(c);
            this.kind = kind;
            p.setStyle(Paint.Style.STROKE);
            p.setStrokeCap(Paint.Cap.ROUND);
            p.setStrokeJoin(Paint.Join.ROUND);
            p.setStrokeWidth(1.7f * c.getResources().getDisplayMetrics().density);
            p.setColor(SUB);
        }

        protected void onDraw(Canvas cv) {
            int w = getWidth(), h = getHeight();
            float s = Math.min(w, h);
            float l = (w - s) / 2f, t = (h - s) / 2f;
            float u = s / 24f;
            if (kind == CHECK) {
                cv.drawCircle(l + 12 * u, t + 12 * u, 8.5f * u, p);
                Path path = new Path();
                path.moveTo(l + 7.5f * u, t + 12.2f * u);
                path.lineTo(l + 10.8f * u, t + 15.5f * u);
                path.lineTo(l + 16.5f * u, t + 9 * u);
                cv.drawPath(path, p);
            } else if (kind == IMAGE) {
                cv.drawRoundRect(l + 3 * u, t + 4.5f * u, l + 21 * u, t + 19.5f * u,
                        2.5f * u, 2.5f * u, p);
                cv.drawCircle(l + 8 * u, t + 9 * u, 1.5f * u, p);
                Path path = new Path();
                path.moveTo(l + 4.5f * u, t + 17.5f * u);
                path.lineTo(l + 10.5f * u, t + 12.5f * u);
                path.lineTo(l + 15 * u, t + 17.5f * u);
                cv.drawPath(path, p);
            } else {
                cv.drawCircle(l + 12 * u, t + 12 * u, 8.5f * u, p);
                cv.drawLine(l + 12 * u, t + 11 * u, l + 12 * u, t + 16.5f * u, p);
                cv.drawPoint(l + 12 * u, t + 7.6f * u, p);
            }
        }
    }

    private EditText field(String hint) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setHintTextColor(SUB);
        e.setTextColor(TEXT);
        e.setTextSize(14);
        e.setSingleLine(true);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        e.setBackground(round(FIELD_BG, 12));
        e.setPadding(dp(14), dp(11), dp(14), dp(11));
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.leftMargin = dp(16);
        p.rightMargin = dp(16);
        p.topMargin = dp(2);
        p.bottomMargin = dp(10);
        e.setLayoutParams(p);
        return e;
    }

    private TextView note(String text) {
        TextView t = label(text, 12, SUB);
        t.setPadding(dp(16), dp(2), dp(16), dp(12));
        return t;
    }

    private TextView mkButton(String text, int bgColor, int textColor, boolean bold) {
        TextView b = new TextView(this);
        b.setText(text);
        b.setTextSize(15);
        b.setTextColor(textColor);
        b.setGravity(Gravity.CENTER);
        b.setBackground(round(bgColor, 22));
        b.setPadding(dp(16), dp(13), dp(16), dp(13));
        if (bold) {
            b.setTypeface(b.getTypeface(), android.graphics.Typeface.BOLD);
        }
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.leftMargin = dp(16);
        p.rightMargin = dp(16);
        p.topMargin = dp(10);
        b.setLayoutParams(p);
        return b;
    }

    private View buildUi() {
        ScrollView sc = page("九号自动签到", "v" + VER + " · 自动签到 · 换主页图");
        LinearLayout root = rootOf(sc);

        LinearLayout c1 = section(root, "签到");
        signOn = mkSwitch();
        signOn.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                if (!loading) {
                    save(true);
                }
            }
        });
        c1.addView(row(Glyph.CHECK, "自动签到", null, signOn));

        LinearLayout c2 = section(root, "主页图片");
        vehOn = mkSwitch();
        vehOn.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                if (!loading) {
                    save(true);
                }
            }
        });
        c2.addView(row(Glyph.IMAGE, "替换电动车图片", null, vehOn));
        c2.addView(divider());
        TextView pick = mkButton("从相册选择图片", TINT, ACCENT, true);
        pick.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                pickImage();
            }
        });
        LinearLayout.LayoutParams pp = (LinearLayout.LayoutParams) pick.getLayoutParams();
        pp.topMargin = dp(12);
        pp.bottomMargin = dp(2);
        c2.addView(pick);
        bgOn = mkSwitch();
        boolean bgv = false;
        try {
            bgv = sp().getBoolean("bgEnabled", false);
        } catch (Throwable t) {
            try {
                bgv = "1".equals(sp().getString("bgEnabled", ""));
            } catch (Throwable t2) {
            }
        }
        bgOn.setChecked(bgv);
        bgOn.setOnCheckedChangeListener(new android.widget.CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(android.widget.CompoundButton b, boolean c) {
                sp().edit().putBoolean("bgEnabled", c).commit();
                save(true);
            }
        });
        c2.addView(row(Glyph.IMAGE, "替换主页背景图（测试版）", "仅支持 root；图会被推到九号自己的目录。测试版：效果可能不稳", bgOn));
        c2.addView(divider());
        TextView bgPick = mkButton("从相册选择背景图", TINT, ACCENT, true);
        bgPick.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                pickBg();
            }
        });
        LinearLayout.LayoutParams bpp = (LinearLayout.LayoutParams) bgPick.getLayoutParams();
        bpp.topMargin = dp(12);
        bpp.bottomMargin = dp(2);
        c2.addView(bgPick);
        bgStatus = note("");
        c2.addView(bgStatus);
        vehStatus = note("");
        c2.addView(vehStatus);
        vehPath = field("手工指定图片路径（一般不用填）");
        vehPath.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            public void onFocusChange(View v, boolean has) {
                if (!has && !loading) {
                    save(true);
                }
            }
        });
        c2.addView(vehPath);

        LinearLayout c3 = section(root, "配置通道");
        confStatus = note("配置通道：检查中…");
        confStatus.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (!Environment.isExternalStorageManager()) {
                    openAllFilesPage();
                }
            }
        });
        c3.addView(confStatus);
        c3.addView(note("改完不用强停九号：注入进程每秒复查一次配置。"));

        LinearLayout expC = section(root, "界面文字");
        fakeExpiryOn = mkSwitch();
        fakeExpiryOn.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                if (!loading) {
                    save(true);
                }
            }
        });
        expC.addView(row(Glyph.INFO, "有效期显示为 9999.12.31",
                "只看样子：九号里「服务有效期：2027.02.22」这类文字，整串日期统一显示成 9999.12.31；"
                        + "不改任何真实数据，也不影响能不能用。",
                fakeExpiryOn));

        LinearLayout nC = c1;
        autoShareSw = mkSwitch();
        autoShareSw.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                if (!loading) {
                    save(true);
                }
            }
        });
        nC.addView(noteRow("自动领 N币"));
        nC.addView(row(Glyph.INFO, "自动分享并领取", "打开九号后自己走一遍「分享到微信」并领取当天的 N 币；微信不会真的弹出来。", autoShareSw));
        fakeShareSw = mkSwitch();
        fakeShareSw.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                if (!loading) {
                    save(true);
                }
            }
        });
        nC.addView(row(Glyph.INFO, "伪造分享（不打开微信）", "点分享后直接算成功，不拉起微信、也不会真的发出去。", fakeShareSw));
        postIdIn = new android.widget.EditText(this);
        postIdIn.setHint("自定义帖子 ID（默认 22716571）");
        postIdIn.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        postIdIn.setOnFocusChangeListener(new android.view.View.OnFocusChangeListener() {
            public void onFocusChange(android.view.View v, boolean hasFocus) {
                if (!hasFocus && !loading) {
                    save(true);
                }
            }
        });
        nC.addView(postIdIn, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        LinearLayout c4 = section(root, "关于");
        c4.addView(row(Glyph.INFO, "项目主页", REPO, null));
        TextView gh = mkButton("打开 GitHub 项目页", TINT, ACCENT, false);
        gh.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                openUrl(REPO);
            }
        });
        c4.addView(gh);
        c4.addView(row(Glyph.INFO, "酷安主页", HOME, null));
        TextView me = mkButton("打开酷安主页", TINT, ACCENT, false);
        me.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                openUrl(HOME);
            }
        });
        c4.addView(me);
        autoCheckOn = mkSwitch();
        boolean acv = false;
        try {
            acv = sp().getBoolean("autoCheck", false);
        } catch (Throwable t) {
            try {
                acv = "1".equals(sp().getString("autoCheck", ""));
            } catch (Throwable t2) {
            }
        }
        autoCheckOn.setChecked(acv);
        autoCheckOn.setOnCheckedChangeListener(new android.widget.CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(android.widget.CompoundButton b, boolean c) {
                sp().edit().putString("autoCheck", c ? "1" : "0").commit();
                save(true);
            }
        });
        c4.addView(row(Glyph.INFO, "自动检测新版本", "每次打开九号时查一次 GitHub，有新版本就提一下", autoCheckOn));
        final TextView updNote = note("\u5f53\u524d\u7248\u672c " + VER);
        c4.addView(updNote);
        final TextView updBtn = mkButton("\u68c0\u6d4b\u66f4\u65b0", TINT, ACCENT, false);
        final boolean[] updBusy = new boolean[] { false };
        final String[] updFound = new String[] { null };
        updBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (updFound[0] != null) {
                    openUrl(updFound[0]);
                    return;
                }
                if (updBusy[0]) {
                    return;
                }
                updBusy[0] = true;
                updBtn.setText("\u6b63\u5728\u68c0\u6d4b\u2026");
                new Thread(new Runnable() {
                    public void run() {
                        String okv = null;
                        String err = null;
                        try {
                            okv = checkUpdate();
                        } catch (Throwable t) {
                            err = String.valueOf(t);
                        }
                        final String fOk = okv;
                        final String fErr = err;
                        runOnUiThread(new Runnable() {
                            public void run() {
                                updBusy[0] = false;
                                if (fOk != null) {
                                    String[] p = fOk.split("\\|");
                                    updNote.setText("\u53d1\u73b0\u65b0\u7248\u672c " + p[0] + "\uff08" + p[2] + " \u5b57\u8282\uff09");
                                    updFound[0] = p[1];
                                    updBtn.setText("\u4e0b\u8f7d " + p[0]);
                                } else if (fErr != null) {
                                    updNote.setText("\u68c0\u6d4b\u5931\u8d25\uff1a" + fErr);
                                    updBtn.setText("\u68c0\u6d4b\u66f4\u65b0");
                                } else {
                                    updNote.setText("\u5df2\u662f\u6700\u65b0\u7248\u672c");
                                    updBtn.setText("\u68c0\u6d4b\u66f4\u65b0");
                                }
                            }
                        });
                    }
                }).start();
            }
        });
        c4.addView(updBtn);
        TextView reset = mkButton("清空所有配置", RED_TINT, RED, false);
        reset.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                clear();
            }
        });
        c4.addView(reset);

        return sc;
    }


    static int[] verParts(String v) {
        java.util.ArrayList<Integer> out = new java.util.ArrayList<Integer>();
        if (v == null) {
            return new int[0];
        }
        String cur = "";
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c >= '0' && c <= '9') {
                cur = cur + c;
            } else if (cur.length() > 0) {
                out.add(Integer.valueOf(Integer.parseInt(cur)));
                cur = "";
            }
        }
        if (cur.length() > 0) {
            out.add(Integer.valueOf(Integer.parseInt(cur)));
        }
        int[] a = new int[out.size()];
        for (int i = 0; i < a.length; i++) {
            a[i] = out.get(i).intValue();
        }
        return a;
    }

    static int verCmp(String a, String b) {
        int[] x = verParts(a);
        int[] y = verParts(b);
        int n = Math.max(x.length, y.length);
        for (int i = 0; i < n; i++) {
            int p = i < x.length ? x[i] : 0;
            int q = i < y.length ? y[i] : 0;
            if (p != q) {
                return p > q ? 1 : -1;
            }
        }
        return 0;
    }

    static String checkUpdate() throws Exception {
        java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL("https://api.github.com/repos/qwe2251518/ninebot-sign-lsp/releases/latest").openConnection();
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        c.setRequestProperty("Accept", "application/vnd.github+json");
        c.setRequestProperty("User-Agent", "ninebot-sign-lsp");
        int code = c.getResponseCode();
        if (code != 200) {
            throw new Exception("HTTP " + code);
        }
        java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(c.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String ln;
        while ((ln = r.readLine()) != null) {
            sb.append(ln);
        }
        r.close();
        org.json.JSONObject o = new org.json.JSONObject(sb.toString());
        String tag = o.optString("tag_name", "");
        if (tag.startsWith("v")) {
            tag = tag.substring(1);
        }
        org.json.JSONArray as = o.optJSONArray("assets");
        String url = null;
        long size = 0;
        if (as != null && as.length() > 0) {
            url = as.getJSONObject(0).optString("browser_download_url", null);
            size = as.getJSONObject(0).optLong("size", 0);
        }
        if (url == null) {
            throw new Exception("no apk asset");
        }
        if (verCmp(tag, VER) <= 0) {
            return null;
        }
        return tag + "|" + url + "|" + size;
    }
    private ScrollView page(String title, String sub) {
        ScrollView sc = new ScrollView(this);
        sc.setBackgroundColor(BG);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(0, dp(16), 0, dp(24));
        sc.addView(root);

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.VERTICAL);
        head.setPadding(dp(28), dp(8), dp(28), dp(6));
        head.addView(label(title, 26, TEXT));
        TextView hs = label(sub, 13, SUB);
        hs.setPadding(0, dp(6), 0, 0);
        head.addView(hs);
        root.addView(head);
        sc.setTag(root);
        return sc;
    }

    private static LinearLayout rootOf(ScrollView sc) {
        return (LinearLayout) sc.getTag();
    }

    private LinearLayout section(LinearLayout root, String title) {
        root.addView(sectionLabel(title));
        LinearLayout c = card();
        root.addView(c);
        return c;
    }

    private SharedPreferences sp() {
        return getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private void load() {
        loading = true;
        SharedPreferences p = sp();
        signOn.setChecked(!"0".equals(p.getString("signEnabled", "1")));
        vehOn.setChecked("1".equals(p.getString("vehicleImage", "0")));
        vehPath.setText(p.getString("vehicleImagePath", "vehicle.png"));
        updateBgStatus();

        if (dashOn != null) {
            dashOn.setChecked("1".equals(p.getString("dashFix", "0")));
        }

        if (energyOn != null) {
            energyOn.setChecked("1".equals(p.getString("showEnergyOff", "0")));
        }
        energyTouched = false;
        if (nitroOn != null) {
            nitroOn.setChecked("1".equals(p.getString("showNitro", "0")));
        }
        nitroTouched = false;

        if (autoShareSw != null) {
            autoShareSw.setChecked("1".equals(p.getString("autoShare", "0")));
        }
        if (fakeShareSw != null) {
            fakeShareSw.setChecked("1".equals(p.getString("fakeShare", "0")));
        }
        if (postIdIn != null) {
            postIdIn.setText(p.getString("postId", "22716571"));
        }
        if (fakeExpiryOn != null) {
            fakeExpiryOn.setChecked("1".equals(p.getString("fakeExpiry", "0")));
        }
        loading = false;
        updateVehStatus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateConfStatus();

        if ("1".equals(sp().getString("ui", ""))) {
            pushConfAsync();
        }
    }

    private void updateConfStatus() {
        if (confStatus == null) {
            return;
        }
        boolean ok = Environment.isExternalStorageManager();
        if (ok) {
            confStatus.setText("配置通道：已拿到「所有文件访问」，每次保存都会直接写进九号目录 ✓");
            confStatus.setTextColor(0xFF6B6B6B);
        } else {
            confStatus.setText("配置通道：保存时会把配置直接写进九号目录；如果提示失败，"
                    + "请在 root 管理器里允许本模块（LSPosed 的 prefs 通道在模块更新后常常读不到）");
            confStatus.setTextColor(ACCENT);
        }
    }

    private void openAllFilesPage() {
        try {
            startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + getPackageName())));
        } catch (Throwable t) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            } catch (Throwable t2) {
                toast("这台机器打不开「所有文件访问」页面，可以用 root 或手动放配置");
            }
        }
    }

    private void save(boolean quiet) {
        Map<String, String> m = currentMap();
        SharedPreferences.Editor e = sp().edit();
        for (Map.Entry<String, String> en : m.entrySet()) {
            e.putString(en.getKey(), en.getValue());
        }
        e.commit();

        String direct = null;
        try {
            direct = writeConfDirectly(ConfText.build(m));
        } catch (Throwable t) {
            direct = null;
        }
        if (direct == null) {

            pushConfViaRoot(ConfText.build(m));
        }
        if (quiet) {
            return;
        }
        toast("已保存，打开九号出行时自动写入");
    }

    private Map<String, String> currentMap() {
        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("ui", "1");
        m.put("signEnabled", signOn.isChecked() ? "1" : "0");
        m.put("vehicleImage", vehOn.isChecked() ? "1" : "0");
        m.put("vehicleImagePath", or(vehPath.getText().toString().trim(), "vehicle.png"));

        m.put("vehicleImageStamp", sp().getString("vehicleImageStamp", ""));
        String bgp = sp().getString("bgImagePath", "");
        m.put("bgImage", (bgOn != null && bgOn.isChecked()) ? "1" : "0");
        m.put("bgImagePath", bgp);

        String se = sp().getString("showEnergyOff", "");
        if (energyTouched && energyOn != null) {
            se = energyOn.isChecked() ? "1" : "0";
        }
        if (se != null && se.length() > 0) {
        }
        String sn = sp().getString("showNitro", "");
        if (nitroTouched && nitroOn != null) {
            sn = nitroOn.isChecked() ? "1" : "0";
        }
        if (sn != null && sn.length() > 0) {
        }

        String nVal = sp().getString("vnitro", "");
        m.put("vnitro", nVal == null ? "" : nVal);


        m.put("autoShare", autoShareSw != null && autoShareSw.isChecked() ? "1" : "0");
        m.put("fakeShare", fakeShareSw != null && fakeShareSw.isChecked() ? "1" : "0");
        m.put("postId", postIdIn != null && postIdIn.getText().toString().trim().length() > 0 ? postIdIn.getText().toString().trim() : "22716571");
        m.put("fakeExpiry", fakeExpiryOn != null && fakeExpiryOn.isChecked() ? "1" : "0");

        String req = sp().getString("openDash", "");
        if (req != null && req.length() > 0) {
            boolean fresh = false;
            try {
                long age = System.currentTimeMillis() - Long.parseLong(req);
                fresh = age >= 0L && age < 60000L;
            } catch (Throwable t) {
                fresh = false;
            }
            if (fresh) {
            } else {
                sp().edit().remove("openDash").commit();
            }
        }
        return m;
    }

    private void openDashboardOnce() {

        try {
            sp().edit().putString("openDash", String.valueOf(System.currentTimeMillis())).commit();
        } catch (Throwable t) {
            Log.w("NinebotSign", "写「打开仪表盘」请求失败: " + t);
        }
        save(true);
        launchNinebot();
        toast("已发送：正在把九号拉到前台，几秒内自动打开仪表盘");
    }

    private void launchNinebot() {
        try {
            Intent it = getPackageManager().getLaunchIntentForPackage("cn.ninebot.ninebot");
            if (it == null) {

                it = new Intent(Intent.ACTION_MAIN);
                it.setClassName("cn.ninebot.ninebot", "cn.ninebot.ninebot.mainshell.SplashActivity");
            }
            it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(it);
            Log.i("NinebotSign", "已把九号拉到前台: " + it.getComponent());
        } catch (Throwable t) {
            Log.w("NinebotSign", "拉起九号失败: " + t);
        }
    }

    private void pushConfAsync() {
        final String text = ConfText.build(currentMap());
        Thread t = new Thread(new Runnable() {
            public void run() {
                if (writeConfDirectly(text) == null) {
                    pushConfViaRoot(text);
                }
            }
        }, "ninebot-conf-push");
        t.setDaemon(true);
        t.start();
    }

    private void pushConfViaRoot(String text) {
        try {
            File tmp = new File(getCacheDir(), "conf.push");
            FileOutputStream fo = new FileOutputStream(tmp, false);
            fo.write(text.getBytes("UTF-8"));
            fo.close();
            String target = NINEBOT_DIR + "/ninebot-sign.conf";
            String cmd = "mkdir -p '" + NINEBOT_DIR + "'; cp '" + tmp.getAbsolutePath()
                    + "' '" + target + "'; chmod 644 '" + target + "'";
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            int code = p.waitFor();
            Log.i("NinebotSign", "设置界面：root 推送配置 exit=" + code + " → " + target);
        } catch (Throwable t) {
            Log.i("NinebotSign", "设置界面：root 推送配置失败 " + t);
        }
    }

    private static String or(String v, String def) {
        return v == null || v.isEmpty() ? def : v;
    }

    private void updateVehStatus() {
        if (vehStatus == null) {
            return;
        }
        String st = sp().getString("vehicleImageStamp", "");
        vehStatus.setText(st.length() == 0
                ? "还没从相册选过图；也可以手工填一个路径（如 /sdcard/Pictures/x.png）"
                : "已从相册选好图片（存在模块里，换图再点一次「从相册选择图片」）");
    }

    private void clear() {
        SharedPreferences.Editor e = sp().edit();
        e.clear();
        e.commit();
        load();
        toast("已清空（九号那边下次启动会把配置覆盖掉）");
    }

    private String writeConfDirectly(String text) {
        try {
            File f = new File(NINEBOT_DIR, "ninebot-sign.conf");
            FileOutputStream fo = new FileOutputStream(f, false);
            try {
                fo.write(text.getBytes("UTF-8"));
                fo.flush();
            } finally {

                try {
                    fo.close();
                } catch (Throwable ignored) {
                }
            }
            return f.getAbsolutePath();
        } catch (Throwable t) {
            Log.i("NinebotSign", "设置界面：直写配置失败 " + t);
            return null;
        }
    }

    private void pickBg() {
        try {
            Intent i = new Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
            i.setType("image/*");
            startActivityForResult(i, REQ_BG);
        } catch (Throwable t) {
            try {
                Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("image/*");
                startActivityForResult(i, REQ_BG);
            } catch (Throwable t2) {
                toast("打不开相册");
            }
        }
    }

    private void updateBgStatus() {
        if (bgStatus == null) {
            return;
        }
        String p = sp().getString("bgImagePath", "");
        bgStatus.setText(p.length() == 0
                ? "还没选背景图（留空 = 不换）"
                : "已选：" + p);
    }

    private String saveBgSource(Uri src) {
        InputStream in = null;
        OutputStream out = null;
        try {
            in = getContentResolver().openInputStream(src);
            if (in == null) {
                Log.i("NinebotSign", "背景图：openInputStream 返回 null，uri=" + src);
                return null;
            }
            File dir = new File(NINEBOT_DIR);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File f = new File(dir, "bg-custom.png");
            out = new FileOutputStream(f, false);
            pipe(in, out);
            close(out);
            out = null;
            close(in);
            in = null;
            if (f.length() <= 0L) {
                Log.i("NinebotSign", "背景图：写完为空 " + f.getAbsolutePath());
                return null;
            }
            String path = f.getAbsolutePath();
            Log.i("NinebotSign", "背景图：已保存 " + path + " (" + f.length() + " 字节)");
            sp().edit().putString("bgImagePath", path).commit();
            try {
                java.io.File pf0 = new java.io.File(path);
                pf0.setReadable(true, false);
                pf0.setWritable(true, false);
            } catch (Throwable t0) {
            }
            return path;
        } catch (Throwable t) {
            Log.i("NinebotSign", "背景图：主路径失败 " + t);
            return saveBgFallback(src);
        } finally {
            close(in);
            close(out);
        }
    }

    private String copyToNinebotByRoot(String src) {
        try {
            String dst = NINEBOT_DIR + "/bg-custom.png";
            String cmd = "cp '" + src + "' '" + dst + "' && chmod 666 '" + dst + "' && mkdir -p /data/user/0/cn.ninebot.ninebot/files && cp '" + src + "' /data/user/0/cn.ninebot.ninebot/files/bg-custom.png && chmod 644 /data/user/0/cn.ninebot.ninebot/files/bg-custom.png";
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            int rc = p.waitFor();
            File d = new File(dst);
            Log.i("NinebotSign", "背景图：root 拷贝 rc=" + rc + " exists=" + d.exists() + " len=" + d.length());
            if (rc == 0) {
                Thread.sleep(200L);
                return dst;
            }
            return null;
        } catch (Throwable t) {
            Log.i("NinebotSign", "背景图：root 拷贝不可用 " + t);
            return null;
        }
    }

    private String saveBgFallback(Uri src) {
        InputStream in = null;
        try {
            in = getContentResolver().openInputStream(src);
            if (in == null) {
                return null;
            }
            File dir = new File(Environment.getExternalStorageDirectory(), "Pictures");
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File f = new File(dir, "ninebot-bg.png");
            FileOutputStream fo = new FileOutputStream(f, false);
            try {
                byte[] buf = new byte[16384];
                int n;
                while ((n = in.read(buf)) > 0) {
                    fo.write(buf, 0, n);
                }
                fo.flush();
            } finally {
                close(fo);
            }
            if (f.length() <= 0L) {
                return null;
            }
            String path = f.getAbsolutePath();
            String viaRoot = copyToNinebotByRoot(path);
            if (viaRoot != null) {
                path = viaRoot;
            }
            Log.i("NinebotSign", "背景图：备用路径成功 " + path + " (" + f.length() + " 字节)");
            sp().edit().putString("bgImagePath", path).commit();
            try {
                java.io.File pf0 = new java.io.File(path);
                pf0.setReadable(true, false);
                pf0.setWritable(true, false);
            } catch (Throwable t0) {
            }
            return path;
        } catch (Throwable t) {
            Log.i("NinebotSign", "背景图：备用路径也失败 " + t);
            return null;
        } finally {
            close(in);
        }
    }

    private void pickImage() {
        try {

            Intent i = new Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
            i.setType("image/*");
            startActivityForResult(i, REQ_PICK);
        } catch (Throwable t) {

            try {
                Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("image/*");
                startActivityForResult(i, REQ_PICK);
            } catch (Throwable t2) {
                toast("打不开相册");
            }
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (res != RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        if (req == REQ_BG) {
            if (saveBgSource(data.getData()) == null) {
                toast("?    读不出这张图，换一张？");
                return;
            }
            save(false);
            updateBgStatus();
            toast("背景图已存好，重进九号车控页生效");
            return;
        }
        if (req != REQ_PICK) {
            return;
        }
        if (saveVehicleSource(data.getData()) == null) {
            toast("没读出这张图，换一张试试");
            return;
        }
        loading = true;
        vehOn.setChecked(true);
        loading = false;
        save(false);
        updateVehStatus();
        toast("图片已存好，打开九号出行就换图");
    }

    private String saveVehicleSource(Uri src) {
        InputStream in = null;
        OutputStream out = null;
        try {
            in = getContentResolver().openInputStream(src);
            if (in == null) {
                return null;
            }
            File f = new File(getFilesDir(), VEHICLE_SRC);
            out = new FileOutputStream(f, false);
            pipe(in, out);
            close(out);
            out = null;
            close(in);
            in = null;
            if (f.length() <= 0L) {
                return null;
            }
            String stamp = f.length() + "-" + f.lastModified();
            sp().edit().putString("vehicleImageStamp", stamp).commit();
            return stamp;
        } catch (Throwable t) {
            return null;
        } finally {
            close(in);
            close(out);
        }
    }

    private static void pipe(InputStream in, OutputStream out) throws Exception {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        out.flush();
    }

    private static void close(Object o) {
        try {
            if (o instanceof InputStream) {
                ((InputStream) o).close();
            } else if (o instanceof OutputStream) {
                ((OutputStream) o).close();
            }
        } catch (Throwable t) {
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Throwable t) {
            toast("没有可用的浏览器");
        }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }
}
