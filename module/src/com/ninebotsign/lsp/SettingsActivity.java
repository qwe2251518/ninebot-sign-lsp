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
import android.widget.RadioButton;
import android.widget.RadioGroup;
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

/**
 * 模块的设置界面（桌面图标「九号自动签到」）。界面只做一件事：把配置写进自己的
 * SharedPreferences（name = PREF），九号出行启动时由注入的模块把这份配置落地。
 * 不在这里直接改九号的配置文件：Android 11+ 一个应用写不了别的应用的 Android/data，
 * 只能由注入到九号进程里的代码去写。
 *
 * 界面风格照着 MIUI 走：浅灰底、白色圆角卡片、列表行 + 右侧开关、灰底输入框、蓝色主按钮。
 */
public class SettingsActivity extends Activity {

    /** 与 SignHook.PREF 保持一致 */
    public static final String PREF = "ninebot_sign";

    /** 九号出行的数据目录（注入后模块真正写的地方） */
    private static final String NINEBOT_DIR = "/sdcard/Android/data/cn.ninebot.ninebot/files";

    private static final int BG = 0xFFF5F5F7;
    private static final int CARD = 0xFFFFFFFF;
    private static final int TEXT = 0xFF191919;
    private static final int SUB = 0xFF8C8C8C;
    private static final int ACCENT = 0xFF3482FF;
    private static final int DIVIDER = 0xFFEDEDED;
    private static final int FIELD_BG = 0xFFF2F3F5;
    /** 浅蓝底按钮 */
    private static final int TINT = 0x1F3482FF;
    /** 浅红底按钮 */
    private static final int RED_TINT = 0x1FE64340;
    private static final int RED = 0xFFE64340;

    /** 版本号（与 AndroidManifest 的 versionName 保持一致） */
    private static final String VER = "2.0";

    /** 项目主页 */
    private static final String REPO = "https://github.com/qwe2251518/ninebot-sign-lsp";
    /** 我的酷安主页 */
    private static final String HOME = "https://www.coolapk.com/u/3345275";

    private Switch signOn, vehOn;
    /** 车控：动能回收三选一（关闭 off / 弱 weak / 标准 standard） */
    private RadioGroup energyGroup;
    private EditText vehPath;
    private TextView vehStatus;
    private TextView confStatus;
    /** 载入配置时不要触发开关的自动保存 */
    private boolean loading = false;
    private static final int REQ_PICK = 1001;
    /** 相册里选的那张图，存在本应用私有目录里的文件名（注入进程走 ConfProvider 来取） */
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
        load();
    }

    // ---------------------------------------------------------------- 基础件

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

    private Switch mkSwitch() {
        Switch s = new Switch(this);
        s.setShowText(false);
        ColorStateList track = new ColorStateList(
                new int[][]{new int[]{android.R.attr.state_checked}, new int[]{}},
                new int[]{ACCENT, 0xFFDFE0E4});
        ColorStateList thumb = new ColorStateList(
                new int[][]{new int[]{android.R.attr.state_checked}, new int[]{}},
                new int[]{0xFFFFFFFF, 0xFFFFFFFF});
        s.setTrackTintList(track);
        s.setThumbTintList(thumb);
        return s;
    }

    /** 一行：左边图标 + 标题（可选一行副标题），右边控件 */
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

    /** 手画的小图标（24dp 栅格） */
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

    // ---------------------------------------------------------------- UI

    private View buildUi() {
        ScrollView sc = page("九号自动签到", "v" + VER + " · 自动签到 · 换主页图");
        LinearLayout root = rootOf(sc);

        // 签到
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

        // 主页图片
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

        // 配置通道
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

        // 车控（2026-10-15 22:3x 用户：「做一个关闭动能回收」）
        // 云配置里动能回收就是 rFunBool 的低 2 位（0=关闭 1=弱 2=标准），所以这里三选一，
        // 注入端读 venergy 后「读 rFunBool → 改低 2 位 → 写回」。
        LinearLayout carC = section(root, "车控");
        LinearLayout ebox = new LinearLayout(this);
        ebox.setOrientation(LinearLayout.VERTICAL);
        ebox.setPadding(dp(16), dp(12), dp(16), dp(12));
        ebox.addView(label("动能回收", 15, TEXT));
        TextView etip = label("选「关闭」＝把车上的 rFunBool 低 2 位清零写回（关闭 0 / 弱 1 / 标准 2）。"
                + "改完点保存才下发，且车得连着蓝牙。", 12, SUB);
        etip.setPadding(0, dp(2), 0, dp(6));
        ebox.addView(etip);
        TextView ewarn = label("不保证能用", 12, SUB);
        ewarn.setPadding(0, dp(2), 0, dp(6));
        ebox.addView(ewarn);
        energyGroup = new RadioGroup(this);
        energyGroup.setOrientation(RadioGroup.HORIZONTAL);
        String[] etext = {"关闭", "弱", "标准", "不管"};
        String[] eval = {"off", "weak", "standard", ""};
        for (int i = 0; i < etext.length; i++) {
            RadioButton rb = new RadioButton(this);
            rb.setId(View.generateViewId());
            rb.setText(etext[i]);
            rb.setTag(eval[i]);
            rb.setTextColor(TEXT);
            energyGroup.addView(rb);
        }
        energyGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            public void onCheckedChanged(RadioGroup g, int id) {
                if (!loading) {
                    save(true);
                }
            }
        });
        ebox.addView(energyGroup);
        carC.addView(ebox);
        carC.addView(note("车控命令只在车连着蓝牙时才发得出去；日志里找「车控：动能回收」。"));

        // 关于
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
        TextView reset = mkButton("清空所有配置", RED_TINT, RED, false);
        reset.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                clear();
            }
        });
        c4.addView(reset);

        return sc;
    }

    /** 一个页面：整页可滚动，顶上是大标题 + 一行说明 */
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

    /** 一节：小标题 + 一张卡片，返回卡片 */
    private LinearLayout section(LinearLayout root, String title) {
        root.addView(sectionLabel(title));
        LinearLayout c = card();
        root.addView(c);
        return c;
    }

    // ---------------------------------------------------------------- 读写

    private SharedPreferences sp() {
        return getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private void load() {
        loading = true;
        SharedPreferences p = sp();
        signOn.setChecked(!"0".equals(p.getString("signEnabled", "1")));
        vehOn.setChecked("1".equals(p.getString("vehicleImage", "0")));
        vehPath.setText(p.getString("vehicleImagePath", "vehicle.png"));
        // 动能回收：把存的那档勾回来（默认「不管」）
        String ev = p.getString("venergy", "");
        for (int i = 0; i < energyGroup.getChildCount(); i++) {
            View v = energyGroup.getChildAt(i);
            if (ev.equals(String.valueOf(v.getTag()))) {
                ((RadioButton) v).setChecked(true);
            }
        }
        loading = false;
        updateVehStatus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateConfStatus();
        // 用过界面（ui=1）的人：回到界面就把当前配置推一次。真机上 LSPosed 的 prefs 通道
        // 在模块重装后会读不到（日志「两条通道都没读到界面设置」），打开一次设置界面
        // 就等于把配置重新喂给注入进程；从系统设置授权「所有文件访问」回来也会走这里。
        if ("1".equals(sp().getString("ui", ""))) {
            pushConfAsync();
        }
    }

    /** 配置到底送不送得到九号 —— 这一行就是答案，点它去授权 */
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

    /** 打开系统设置里的「所有文件访问」页 */
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
        // 注意：这里不能用 SignHook.xxx —— 本进程里没有 Xposed API，会 NoClassDefFoundError 闪退。
        // 纯文本拼装逻辑在 ConfText 里（与注入进程共用）。
        String direct = null;
        try {
            direct = writeConfDirectly(ConfText.build(m));
        } catch (Throwable t) {
            direct = null;
        }
        if (direct == null) {
            // 直写不行（Android 11+ 的 scoped storage）就走 root 那一手
            pushConfViaRoot(ConfText.build(m));
        }
        if (quiet) {
            return;
        }
        toast("已保存，打开九号出行时自动写入");
    }

    /** 界面上的配置 → 键值表（保存、以及「打开界面就推送」共用） */
    private Map<String, String> currentMap() {
        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("ui", "1");
        m.put("signEnabled", signOn.isChecked() ? "1" : "0");
        m.put("vehicleImage", vehOn.isChecked() ? "1" : "0");
        m.put("vehicleImagePath", or(vehPath.getText().toString().trim(), "vehicle.png"));
        // 相册选过的图：戳（长度-修改时间）存在 prefs 里，每次保存原样带上，注入进程按戳取图
        m.put("vehicleImageStamp", sp().getString("vehicleImageStamp", ""));
        // 动能回收：只有选了「关闭/弱/标准」才带这一项，选「不管」时配置里不出现 venergy
        String eVal = "";
        if (energyGroup != null) {
            int cid = energyGroup.getCheckedRadioButtonId();
            View cv = cid < 0 ? null : energyGroup.findViewById(cid);
            if (cv != null) {
                eVal = String.valueOf(cv.getTag());
            }
        }
        if (eVal.length() > 0) {
            m.put("venergy", eVal);
        } else {
            // 选「不管」时也写空值：把上次存的档清掉，免得注入端还按旧档下发
            m.put("venergy", "");
        }
        return m;
    }

    /** 后台把配置推一次（直写 → 不行就 root），别卡界面 */
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

    /**
     * 用 root 把 conf 写进九号的文件目录。
     *
     * <p>为什么需要这一手：Android 11+ 上九号（targetSdk 34）看不见我们模块 App 的包，
     * 内容提供者调用被 AMS 直接拒掉（Unknown authority）；XSharedPreferences 在模块 App
     * 重新安装之后也会读不到（真机日志「两条通道都没读到界面设置」）。两条都不通时，
     * 注入进程里的开关永远是「关」，用户看到的就是「开了没效果」。
     * LSPosed 用户的机器一般都有 root，代价是第一次会弹一次授权。
     */
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

    /** 「从相册选好了吗」那一行小字 */
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

    /** 九号的数据目录能写就直接写（给了「所有文件访问」权限时能成） */
    private String writeConfDirectly(String text) {
        try {
            File f = new File(NINEBOT_DIR, "ninebot-sign.conf");
            FileOutputStream fo = new FileOutputStream(f, false);
            try {
                fo.write(text.getBytes("UTF-8"));
                fo.flush();
            } finally {
                // FUSE 层上 close 偶发失败，但内容已经落盘了，别当成整体失败去做 root 兜底
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

    // ---------------------------------------------------------------- 相册选图

    private void pickImage() {
        try {
            // 用系统相册（ACTION_PICK + 图库 Uri），不是文档选择器
            Intent i = new Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
            i.setType("image/*");
            startActivityForResult(i, REQ_PICK);
        } catch (Throwable t) {
            // 个别设备 ACTION_PICK 打不开，退回文档选择器兜底
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
        if (req != REQ_PICK || res != RESULT_OK || data == null || data.getData() == null) {
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

    /**
     * 相册里选的图 → 存进本应用私有目录，返回「戳」（长度-修改时间）。
     *
     * <p>为什么不拷到公共相册：注入进程跑在九号的身份下，Android 11+ 读别的应用的媒体
     * 文件要权限、读 `Android/data/…` 又被 FUSE 拦掉（真机上连九号自己写自己那个目录都会
     * EACCES）。存自己私有目录 + 走 {@link ConfProvider} 交给注入进程，是唯一不依赖权限的路。
     */
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

    /** 用浏览器打开一个网址 */
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
