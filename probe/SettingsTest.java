package com.ninebotsign.lsp;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 设置界面 → 配置文件 这条链路的离线验证。
 *
 * 编译的是模块真源码（同包直接调 static 成员），只测纯函数 uiConfText()/uiOn()/uiNz()：
 * 它们决定 SignHook 会往 ninebot-sign.conf 里写什么，而注入端又按
 * 「key=value 一行、# 注释、按第一个 = 切分」读回同一个文件，所以这里既断言生成
 * 文本的逐行内容，也用同样的规则把它读回来做一次往返核对。
 *
 * 报告写 probe/settings_report.txt。不联网、不碰设备。
 */
public class SettingsTest {

    static final StringBuilder REP = new StringBuilder();
    static int pass = 0;
    static int fail = 0;

    static void say(String s) {
        REP.append(s).append('\n');
    }

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            pass++;
        } else {
            fail++;
        }
        say((ok ? "  [PASS] " : "  [FAIL] ") + name
                + (detail == null || detail.isEmpty() ? "" : "   (" + detail + ")"));
    }

    /** 界面「保存」时会写下的那套键（与 SettingsActivity.save() 保持一致） */
    static Map<String, String> conf() {
        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("ui", "1");
        m.put("signEnabled", "1");
        m.put("vehicleImage", "0");
        m.put("vehicleImagePath", "vehicle.png");
        return m;
    }

    /** 按注入端读配置的规则把配置文本读回成 Map（key=value 一行、# 注释、忽略空行） */
    static Map<String, String> parse(String text) {
        Map<String, String> out = new LinkedHashMap<String, String>();
        for (String line : text.split("\n")) {
            String s = line.trim();
            if (s.length() == 0 || s.startsWith("#")) {
                continue;
            }
            int e = s.indexOf('=');
            if (e <= 0) {
                continue;
            }
            out.put(s.substring(0, e).trim().toLowerCase(java.util.Locale.US), s.substring(e + 1).trim());
        }
        return out;
    }

    static int countLines(String s) {
        if (s == null || s.length() == 0) {
            return 0;
        }
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                n++;
            }
        }
        return n;
    }

    /** 读一份源码（探针的工作目录就是仓库根） */
    static String slurp(String path) {
        try {
            java.io.File f = new java.io.File(path);
            if (!f.isFile()) {
                return null;
            }
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            java.io.FileInputStream in = new java.io.FileInputStream(f);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            in.close();
            return new String(bo.toByteArray(), "UTF-8");
        } catch (Throwable t) {
            return null;
        }
    }

    /** 去掉注释行（这个用途按行首判断就够） */
    static String noComments(String src) {
        if (src == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        String[] lines = src.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) {
                continue;
            }
            sb.append(lines[i]).append('\n');
        }
        return sb.toString();
    }

    /** 命中处的上下文，失败时方便看根因 */
    static String ctx(String src, String needle) {
        if (src == null) {
            return "读不到源码";
        }
        int i = src.indexOf(needle);
        if (i < 0) {
            return "";
        }
        int a = Math.max(0, i - 40);
        int b = Math.min(src.length(), i + needle.length() + 40);
        return src.substring(a, b).replace("\n", " ");
    }

    public static void main(String[] args) throws Exception {
        say("九号自动签到 —— 设置界面 → ninebot-sign.conf 离线验证");
        say("");

        // ------------------------------------------------------------------
        say("-- 1. 都关（默认） --");
        String t1 = SignHook.uiConfText(conf());
        say(t1.replace("\n", "\\n"));
        check("第一行是 '#' 表头", t1.startsWith("#"), t1.substring(0, Math.min(24, t1.length())));
        check("关掉车图时写 vehicleImage=0", parse(t1).get("vehicleimage").equals("0"), null);
        check("车图关时不写 vehicleImagePath", !t1.contains("vehicleImagePath"), null);
        check("文本以换行结尾、没有 CR", t1.endsWith("\n") && !t1.contains("\r"), null);
        check("没有多余空行", countLines(t1) == 4, "lines=" + countLines(t1));

        // ------------------------------------------------------------------
        say("");
        say("-- 2. 车图开（含自定义路径） --");
        Map<String, String> m2 = conf();
        m2.put("vehicleImage", "1");
        m2.put("vehicleImagePath", "/sdcard/Pictures/car.png");
        String t2 = SignHook.uiConfText(m2);
        say(t2.replace("\n", "\\n"));
        Map<String, String> p2 = parse(t2);
        check("车图开写成 vehicleImage=1", "1".equals(p2.get("vehicleimage")), p2.get("vehicleimage"));
        check("自定义图片路径写入", "/sdcard/Pictures/car.png".equals(p2.get("vehicleimagepath")), p2.get("vehicleimagepath"));
        check("键名全是小写比较能命中（配置读回时按小写匹配）", p2.containsKey("vehicleimagepath"), null);

        // ------------------------------------------------------------------
        say("");
        say("-- 3. 车图开但用默认文件名 --");
        Map<String, String> m3 = conf();
        m3.put("vehicleImage", "1");
        String t3 = SignHook.uiConfText(m3);
        check("默认 vehicle.png 不写 vehicleImagePath", !t3.contains("vehicleImagePath"), null);
        check("vehicleImage=1 仍在", parse(t3).get("vehicleimage").equals("1"), null);

        // ------------------------------------------------------------------
        say("");
        say("-- 5. 值里的换行 / 首尾空格 --");
        Map<String, String> m5 = conf();
        m5.put("vehicleImage", "1");
        m5.put("vehicleImagePath", "  /sdcard/a\nb.png  ");
        String t5 = SignHook.uiConfText(m5);
        say(t5.replace("\n", "\\n"));
        Map<String, String> p5 = parse(t5);
        check("路径首尾空格被去掉、里头的换行被拍掉",
                "/sdcard/ab.png".equals(p5.get("vehicleimagepath")), p5.get("vehicleimagepath"));
        check("行数没有因为注入的换行变多", countLines(t5) == 5, "lines=" + countLines(t5));

        // ------------------------------------------------------------------
        say("");
        say("-- 6. uiOn / uiNz 的真值判断 --");
        check("uiOn(\"1\")", SignHook.uiOn("1"), null);
        check("uiOn(\" 1 \") 也认", SignHook.uiOn(" 1 "), null);
        check("uiOn(\"true\") / \"TRUE\" / \"ON\"", SignHook.uiOn("true") && SignHook.uiOn("TRUE") && SignHook.uiOn("on"), null);
        check("uiOn(\"0\") 为假", !SignHook.uiOn("0"), null);
        check("uiOn(null) / \"\" 为假", !SignHook.uiOn(null) && !SignHook.uiOn(""), null);
        check("uiOn(\"no\") 为假（不是随便什么非空都算开）", !SignHook.uiOn("no"), null);
        check("uiNz(null) 给空串", "".equals(SignHook.uiNz(null)), null);
        check("uiNz 去首尾空格", "abc".equals(SignHook.uiNz("  abc  ")), null);

        // ------------------------------------------------------------------
        say("");
        say("-- 7. 格式自检：每一行要么是注释要么是 key=value --");
        int bad = 0;
        for (String line : t2.split("\n")) {
            if (line.length() == 0) {
                bad++;
            } else if (line.startsWith("#")) {
                continue;
            } else if (line.indexOf('=') <= 0) {
                bad++;
            }
        }
        check("没有空行 / 没有缺 '=' 的行", bad == 0, "bad=" + bad);

        say("-- 8. 自动签到总开关 signEnabled --");
        Map<String, String> ms1 = conf();
        ms1.put("signEnabled", "1");
        String ts1 = SignHook.uiConfText(ms1);
        check("开着时写 signEnabled=1", "1".equals(parse(ts1).get("signenabled")), parse(ts1).get("signenabled"));
        check("signEnabled 是文件里的第一个键（读配置时最先看到）",
                ts1.split("\n")[1].startsWith("signEnabled="), ts1.split("\n")[1]);

        Map<String, String> ms0 = conf();
        ms0.put("signEnabled", "0");
        String ts0 = SignHook.uiConfText(ms0);
        check("关掉时写 signEnabled=0", "0".equals(parse(ts0).get("signenabled")), parse(ts0).get("signenabled"));
        check("关掉签到不影响其它键（车图仍会写）", ts0.contains("vehicleImage="), ts0);
        check("confOn 的真值判断认得 0/false/off", !SignHook.uiOn("0") && !SignHook.uiOn("off") && !SignHook.uiOn("false"), null);

        Map<String, String> msOld = conf();
        msOld.remove("signEnabled");   // 老版本界面存下的配置里没有这个键
        String tsOld = SignHook.uiConfText(msOld);
        check("老配置（没有这个键）按「开」处理", "1".equals(parse(tsOld).get("signenabled")), parse(tsOld).get("signenabled"));

        say("");
        say("-- 9. 有效期显示为 9999（显示层，只看样子） --");
        Map<String, String> me1 = conf();
        me1.put("fakeExpiry", "1");
        String te1 = SignHook.uiConfText(me1);
        check("开关打开时写 fakeExpiry=1", "1".equals(parse(te1).get("fakeexpiry")), parse(te1).get("fakeexpiry"));
        Map<String, String> me2 = conf();
        me2.remove("fakeExpiry");
        String te2 = SignHook.uiConfText(me2);
        check("没开时写 fakeExpiry=0", "0".equals(parse(te2).get("fakeexpiry")), parse(te2).get("fakeexpiry"));
        check("fakeExpiry 与签到/车图互不影响",
                te1.contains("vehicleImage=") && te1.contains("signEnabled="), null);
        check("带日期的有效期 → 换成 9999.12.31",
                "服务有效期：9999.12.31".equals(SignHook.expiryText("服务有效期：2027.02.22")),
                SignHook.expiryText("服务有效期：2027.02.22"));
        check("横杠日期也认",
                "有效期至 9999-12-31".equals(SignHook.expiryText("有效期至 2019-05-01")),
                SignHook.expiryText("有效期至 2019-05-01"));
        check("没有「有效期」三个字就不动",
                SignHook.expiryText("骑行里程 2027.02.22") == null, null);
        check("已经是 9999 就不再改（不会递归）",
                SignHook.expiryText("服务有效期：9999.12.31") == null, null);
        say("");
        say("-- 10. 设置界面不能碰 Xposed 类（2026-10-15 真机闪退的根因） --");
        Map<String, String> m13 = conf();
        m13.put("fakeExpiry", "1");
        check("SignHook.uiConfText 与 ConfText.build 结果一致（同一份逻辑）",
                SignHook.uiConfText(m13).equals(ConfText.build(m13)), null);
        String actCode = noComments(slurp("module/src/com/ninebotsign/lsp/SettingsActivity.java"));
        check("SettingsActivity 源码（去掉注释）里不再引用 SignHook",
                actCode != null && actCode.indexOf("SignHook") < 0, ctx(actCode, "SignHook"));
        String ctSrc = slurp("module/src/com/ninebotsign/lsp/ConfText.java");
        check("ConfText.java 能读到", ctSrc != null, null);
        check("ConfText 不 import android.*（它要能跑在没有 Android 的进程里）",
                ctSrc != null && ctSrc.indexOf("import android") < 0, null);
        check("ConfText 不引用 Xposed",
                ctSrc != null && ctSrc.indexOf("robv.android.xposed") < 0
                        && ctSrc.indexOf("XposedBridge") < 0, null);
        // 2026-10-15：注入进程读不到模块的 SharedPreferences（真机日志里那个键读不出来），
        // 加了 ConfProvider 这条内容提供者通道；它和设置界面在同一个进程里，同样不能碰 Xposed 类。
        String cpSrc = noComments(slurp("module/src/com/ninebotsign/lsp/ConfProvider.java"));
        check("ConfProvider.java 能读到", cpSrc != null, null);
        check("ConfProvider 不引用 SignHook / Xposed（它和设置界面同一个进程）",
                cpSrc != null && cpSrc.indexOf("SignHook") < 0
                        && cpSrc.indexOf("robv.android.xposed") < 0, null);
        String mf = slurp("module/AndroidManifest.xml");
        check("Manifest 里注册了 exported 的 ConfProvider（authority 对得上）",
                mf != null && mf.indexOf(".ConfProvider") >= 0
                        && mf.indexOf("com.ninebotsign.lsp.conf") >= 0, null);
        check("SignHook 只在 handleLoadPackage 之外仍保留 uiConfText 供探针比对",
                SignHook.uiConfText(conf()).indexOf("signEnabled=") >= 0, null);

        say("");
        say("-- 11. conf() 叠加界面设置（真机写不进 ninebot-sign.conf 时的保底） --");
        Map<String, String> pc = SignHook.parseConfText(
                "# 由设置界面生成\nsignEnabled=1\nfakeExpiry=1\n\nveh=0");
        check("parseConfText 跳过注释/空行", pc.size() == 3, "size=" + pc.size());
        check("parseConfText 取到 fakeExpiry=1", "1".equals(pc.get("fakeExpiry")), pc.get("fakeExpiry"));
        check("parseConfText 取到 signEnabled=1", "1".equals(pc.get("signEnabled")), pc.get("signEnabled"));

        say("");
        say("-- 12. 相册选图（走内容提供者取图，不再拷公共相册） --");
        Map<String, String> mv = conf();
        mv.put("vehicleImage", "1");
        mv.put("vehicleImageStamp", "12345-1700000000");
        String tv = SignHook.uiConfText(mv);
        check("相册选的图会写 vehicleImageStamp",
                tv.contains("vehicleImageStamp=12345-1700000000"), tv);
        Map<String, String> mvOff = conf();
        mvOff.put("vehicleImage", "0");
        mvOff.put("vehicleImageStamp", "12345-1700000000");
        check("车图开关关掉时不写 vehicleImageStamp",
                !SignHook.uiConfText(mvOff).contains("vehicleImageStamp="), null);
        Map<String, String> mvNoStamp = conf();
        mvNoStamp.put("vehicleImage", "1");
        check("开关开着但没在相册选过图 → 不写这一行",
                !SignHook.uiConfText(mvNoStamp).contains("vehicleImageStamp="), null);
        String actAfter = noComments(slurp("module/src/com/ninebotsign/lsp/SettingsActivity.java"));
        check("设置界面不再往公共相册写图（copyViaMediaStore 已删）",
                actAfter != null && actAfter.indexOf("copyViaMediaStore") < 0, null);
        check("设置界面把选中的图存进私有目录（VEHICLE_SRC）",
                actAfter != null && actAfter.indexOf("VEHICLE_SRC") >= 0, null);
        String shSrc = noComments(slurp("module/src/com/ninebotsign/lsp/SignHook.java"));
        check("注入端车图开关走 conf()（不再只读 ninebot-sign.conf 文件）",
                shSrc != null && shSrc.indexOf("confOn(\"vehicleImage\"") >= 0, null);
        check("注入端从内容提供者把图取回来",
                shSrc != null && shSrc.indexOf("vehicleFromProvider") >= 0, null);
        check("模块日志同时写进 logcat（adb logcat -s NinebotSign 直接看）",
                shSrc != null && shSrc.indexOf("android.util.Log.i(\"NinebotSign\"") >= 0, null);
        say("== 结果：PASS=" + pass + " FAIL=" + fail + " ==");
        try {
            java.io.OutputStream os = new java.io.FileOutputStream("probe/settings_report.txt");
            os.write(REP.toString().getBytes("UTF-8"));
            os.close();
        } catch (Throwable t) {
            say("写报告失败: " + t);
        }
        System.out.println(REP.toString());
        System.out.println("PASS=" + pass + " FAIL=" + fail);
        System.exit(fail == 0 ? 0 : 1);
    }
}
