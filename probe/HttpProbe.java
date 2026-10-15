import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * 把模块里真正跑在手机上的那几个方法（http / respCode / explain / deepInt / rewardSummary /
 * looksJwt / addJwtCandidates / addTok）原样搬到桌面上跑一遍，用来在没有真机的情况下
 * 验证「请求构造 + 响应解析」这条代码路径本身是对的。
 *
 * 最后还有一节 [J] 漂移检查：读 module/src/.../SignHook.java，断言这些请求头与判读分支
 * 在 probe 与手机上跑的模块里都存在 —— 防止验证脚本悄悄和真代码走散。
 *
 * 用的是**故意无效的 token**：只探路由和错误签名，不提交任何数据、不改任何状态。
 * org.json 用 repo1.maven.org 的官方 jar 20231013（与 Android 内置的同名同 API）。
 *
 * 输出写进 probe_report.txt（UTF-8），避免 Windows 控制台编码把中文搞乱。
 */
public class HttpProbe {

    // ---- 与模块完全一致的常量 -------------------------------------------------
    static final String UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Segway v6 C 609033420";

    static final String GW = "https://cn-cbu-gateway.ninebot.com";
    static final String URL_SIGN_V2 = GW + "/portal/api/user-sign/v2/sign";
    static final String URL_SIGN_V1 = GW + "/portal/api/user-sign/v1/sign";
    static final String URL_STATUS = GW + "/portal/api/user-sign/v2/status";
    static final String GW_H5 = "https://api5-h5-app-bj.ninebot.com";
    static final String FAKE_PATH = GW + "/portal/api/user-sign/v2/no-such-path-probe";

    static String deviceId = "probe-device-id";
    static String uid = null;

    // ---- 结果收集 ------------------------------------------------------------
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
        say((ok ? "  [PASS] " : "  [FAIL] ") + name + (detail.isEmpty() ? "" : "   (" + detail + ")"));
    }

    static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (Throwable ignored) {
        }
    }

    // ---- ↓↓↓ 以下 http / respCode / explain / deepInt 与模块源码逐字一致 ↓↓↓ ----

    static class Resp {
        int httpCode;
        String body = "";
    }

    static Resp http(String method, String urlStr, String body, String auth) {
        Resp out = new Resp();
        HttpURLConnection c = null;
        try {
            URL u = new URL(urlStr);
            c = (HttpURLConnection) u.openConnection();
            c.setRequestMethod(method);
            c.setConnectTimeout(10000);
            c.setReadTimeout(15000);
            c.setInstanceFollowRedirects(true);
            c.setRequestProperty("Accept", "application/json, text/plain, */*");
            c.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
            c.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
            c.setRequestProperty("language", "zh");
            c.setRequestProperty("sys_language", "zh-CN");
            c.setRequestProperty("platform", "h5");
            c.setRequestProperty("from_platform_1", "1");
            c.setRequestProperty("Origin", "https://h5-bj.ninebot.com");
            c.setRequestProperty("Referer", "https://h5-bj.ninebot.com/");
            c.setRequestProperty("User-Agent", UA);
            c.setRequestProperty("device_id", deviceId == null ? "" : deviceId);
            c.setRequestProperty("deviceId", deviceId == null ? "" : deviceId);
            if (uid != null && uid.length() > 0) {
                c.setRequestProperty("uid", uid);
            }
            if (auth != null) {
                c.setRequestProperty("Authorization", auth);
            }
            if (body != null) {
                c.setDoOutput(true);
                byte[] b = body.getBytes("UTF-8");
                c.setFixedLengthStreamingMode(b.length);
                OutputStream os = c.getOutputStream();
                os.write(b);
                os.flush();
                os.close();
            }
            out.httpCode = c.getResponseCode();
            InputStream is = (out.httpCode >= 200 && out.httpCode < 400)
                    ? c.getInputStream() : c.getErrorStream();
            out.body = is == null ? "" : readAll(is);
        } catch (Throwable t) {
            out.httpCode = -1;
            out.body = "EXC " + t;
        } finally {
            if (c != null) {
                try {
                    c.disconnect();
                } catch (Throwable ignore) {
                }
            }
        }
        return out;
    }

    static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        try {
            is.close();
        } catch (Throwable ignore) {
        }
        return new String(bos.toByteArray(), "UTF-8");
    }

    static int respCode(String body) {
        try {
            return new JSONObject(body).optInt("code", -999);
        } catch (Throwable t) {
            return -999;
        }
    }

    static String explain(String body) {
        if (body == null) {
            return "无响应体";
        }
        if (body.startsWith("EXC ")) {
            return "请求根本没发出去（异常见上）";
        }
        if (body.indexOf("\"status\":404") >= 0) {
            return "接口路径不存在（404）";
        }
        if (respCode(body) == 0) {
            return "成功";
        }
        if (respCode(body) == 540004) {
            return "今日已签到（服务端明确回绝，属正常）";
        }
        if (respCode(body) == 54019) {
            return "会话失效，需要重新登录（当前 token 过期）";
        }
        if (body.indexOf("response.params.error") >= 0) {
            return "Authorization 结构不被接受/缺参数";
        }
        if (body.indexOf("response.system.error") >= 0) {
            return "凭据被服务器拒绝（token 无效或不是这个接口认的格式）";
        }
        return "未知签名，把原文发我";
    }

    static int deepInt(String body, String key, int def) {
        try {
            JSONObject o = new JSONObject(body);
            if (o.has(key)) {
                return o.optInt(key, def);
            }
            JSONObject d = o.optJSONObject("data");
            if (d != null && d.has(key)) {
                return d.optInt(key, def);
            }
        } catch (Throwable t) {
        }
        return def;
    }

    static String rewardSummary(String body) {
        try {
            JSONObject o = new JSONObject(body);
            JSONObject d = o.optJSONObject("data");
            if (d == null) {
                return "";
            }
            JSONArray arr = d.optJSONArray("rewardList");
            if (arr == null || arr.length() == 0) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < arr.length(); i++) {
                JSONObject r = arr.optJSONObject(i);
                if (r == null) {
                    continue;
                }
                int rt = r.optInt("rewardType", -1);
                String name;
                if (rt == 2) {
                    name = r.optInt("rewardValue", 0) + " N币";
                } else if (rt == 1) {
                    name = r.optInt("rewardValue", 0) + " 经验值";
                } else if (rt == 3) {
                    name = r.optString("medalName", "勋章");
                } else if (rt == 4) {
                    name = r.optInt("rewardValue", 0) + " 张补签卡";
                } else if (rt == 5) {
                    name = "商城兑换券";
                } else {
                    name = r.optString("name", "奖励");
                }
                if (sb.length() > 0) {
                    sb.append(" + ");
                }
                sb.append(name);
            }
            return sb.length() > 0 ? "，获得 " + sb : "";
        } catch (Throwable t) {
            return "";
        }
    }

    // ---- ↑↑↑ 以上与模块源码一致 ↑↑↑ -------------------------------------------

    static void addTok(Set<String> out, String t) {
        if (t == null || t.length() < 8) {
            return;
        }
        t = t.trim();
        out.add(t);
        if (t.startsWith("Bearer ") || t.startsWith("bearer ")) {
            out.add(t.substring(7));
        } else {
            out.add("Bearer " + t);
        }
    }

    static void addJwtCandidates(Set<String> out, String url) {
        if (url == null || url.length() < 10) {
            return;
        }
        int q = url.indexOf('?');
        String qs = q >= 0 ? url.substring(q + 1) : url;
        String[] parts = qs.split("&");
        for (int i = 0; i < parts.length; i++) {
            int e = parts[i].indexOf('=');
            if (e <= 0) {
                continue;
            }
            String k = parts[i].substring(0, e).toLowerCase(Locale.US);
            String v = parts[i].substring(e + 1);
            if (v.length() < 20) {
                continue;
            }
            if (k.contains("jwt") || k.contains("token") || k.contains("auth") || looksJwt(v)) {
                addTok(out, v);
            }
        }
    }

    static boolean looksJwt(String v) {
        int d = 0;
        for (int i = 0; i < v.length(); i++) {
            if (v.charAt(i) == '.') {
                d++;
            }
        }
        return d == 2 && v.length() > 40;
    }

    static String clip(String s, int n) {
        if (s == null) {
            return "null";
        }
        return s.length() <= n ? s : s.substring(0, n) + "...(+" + (s.length() - n) + ")";
    }

    static String readText(String path) {
        try {
            java.io.File f = new java.io.File(path);
            if (!f.isFile()) {
                return null;
            }
            byte[] b = new byte[(int) f.length()];
            java.io.FileInputStream in = new java.io.FileInputStream(f);
            int off = 0;
            int n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) {
                off += n;
            }
            in.close();
            return new String(b, 0, off, "UTF-8");
        } catch (Throwable t) {
            return null;
        }
    }

    public static void main(String[] args) throws Exception {
        String json = "{\"deviceId\":\"" + deviceId + "\"}";
        String bad = "probe-invalid-token";

        say("== 九号签到模块：网络 + 解析代码路径线上验证");
        say("   执行的是与手机模块逐字一致的 http()/respCode()/explain()/deepInt()");
        say("   token 故意无效，只读路由，不提交数据、不改任何状态");
        say("   org.json = org.json:json:20231013 (Android 同款 API)");
        say("");

        // ---------- A 对照组：故意写错的路径 ----------
        say("[A] 对照组 — 假路径 POST（应为 404，证明后面的判据有区分度）");
        Resp a = http("POST", FAKE_PATH, json, bad);
        say("    HTTP " + a.httpCode + "  判定: " + explain(a.body));
        say("    原文: " + clip(a.body, 240));
        check("假路径被判为「接口路径不存在」", explain(a.body).contains("路径不存在"), "");
        check("假路径 respCode 拿不到 code（-999）", respCode(a.body) == -999, "code=" + respCode(a.body));
        sleep(400);

        // ---------- B 真实签到端点 + 无效凭据 ----------
        say("");
        say("[B] POST /portal/api/user-sign/v2/sign（真路径 + 无效 token）");
        Resp b = http("POST", URL_SIGN_V2, json, bad);
        say("    HTTP " + b.httpCode + "  判定: " + explain(b.body));
        say("    原文: " + clip(b.body, 400));
        check("请求真的发出去了（拿到 HTTP 状态码）", b.httpCode == 200, "httpCode=" + b.httpCode);
        check("响应体不是 EXC（无 SSL/连接异常）", !b.body.startsWith("EXC "), clip(b.body, 80));
        check("路径真实，不是 404", !explain(b.body).contains("路径不存在"), "");
        check("respCode() 能解析出 code", respCode(b.body) != -999, "code=" + respCode(b.body));
        check("无效凭据 → 业务码非 0（不会误判成功）", respCode(b.body) != 0, "code=" + respCode(b.body));
        sleep(400);

        // ---------- C 状态查询（GET） ----------
        say("");
        say("[C] GET /portal/api/user-sign/v2/status?t=<ms>（真路径 + 无效 token）");
        Resp c = http("GET", URL_STATUS + "?t=" + System.currentTimeMillis(), null, bad);
        say("    HTTP " + c.httpCode + "  判定: " + explain(c.body));
        say("    原文: " + clip(c.body, 400));
        check("status 走 GET 能拿到响应", c.httpCode == 200, "httpCode=" + c.httpCode);
        check("status 路径真实，不是 404", !explain(c.body).contains("路径不存在"), "");
        say("    注意：无效 token 拿不到 data，所以这次 currentSignStatus="
                + deepInt(c.body, "currentSignStatus", -1)
                + "（-1 = 没解析到，不是「今天没签」）");
        sleep(400);

        // ---------- C2 deepInt 解析路径（用真成功的响应形状做离线断言） ----------
        say("");
        say("[C2] deepInt 取值路径断言（离线，模拟成功响应）");
        String okBody = "{\"code\":0,\"msg\":\"ok\",\"data\":{\"currentSignStatus\":1,\"consecutiveDays\":7}}";
        check("从 data 里取到 currentSignStatus=1",
                deepInt(okBody, "currentSignStatus", -1) == 1,
                "got=" + deepInt(okBody, "currentSignStatus", -1));
        check("从 data 里取到 consecutiveDays=7",
                deepInt(okBody, "consecutiveDays", -1) == 7,
                "got=" + deepInt(okBody, "consecutiveDays", -1));
        String deepBody = "{\"code\":0,\"data\":{\"signInfo\":{\"currentSignStatus\":1}}}";
        say("    已知局限：字段若嵌到 data.signInfo.* 里，deepInt 取不到 → 返回 -1（"
                + deepInt(deepBody, "currentSignStatus", -1) + "），只是会多做一次签到、不会误判成功");
        String topBody = "{\"code\":0,\"currentSignStatus\":1}";
        check("字段在顶层也能取到", deepInt(topBody, "currentSignStatus", -1) == 1, "");

        // ---------- D 老版本端点 ----------
        say("");
        say("[D] POST /portal/api/user-sign/v1/sign（老版本端点）");
        Resp d = http("POST", URL_SIGN_V1, json, bad);
        say("    HTTP " + d.httpCode + "  判定: " + explain(d.body));
        say("    原文: " + clip(d.body, 300));
        check("v1 端点存在（不是 404）", !explain(d.body).contains("路径不存在"), "");
        sleep(400);

        // ---------- E 第二个网关（H5 后端） ----------
        say("");
        say("[E] POST https://api5-h5-app-bj.ninebot.com/portal/api/user-sign/v2/sign（兜底主机）");
        Resp e = http("POST", GW_H5 + "/portal/api/user-sign/v2/sign", json, bad);
        say("    HTTP " + e.httpCode + "  判定: " + explain(e.body));
        say("    原文: " + clip(e.body, 300));
        check("兜底网关可用且路径真实", e.httpCode == 200 && !explain(e.body).contains("路径不存在"),
                "httpCode=" + e.httpCode);
        sleep(400);

        // ---------- F Bearer 前缀 A/B（无效凭据下没有区分度，仅作演示） ----------
        say("");
        say("[F] Bearer 前缀对照（同一串**无效** token，加前缀 vs 不加）");
        Resp f1 = http("POST", URL_SIGN_V2, json, bad);
        sleep(400);
        Resp f2 = http("POST", URL_SIGN_V2, json, "Bearer " + bad);
        say("    不加前缀: code=" + respCode(f1.body) + "  " + explain(f1.body));
        say("    加 前缀 : code=" + respCode(f2.body) + "  " + explain(f2.body));
        say("    ↑ 这一节**不能**用来判定前缀要不要加：无效 token 先被鉴权挡掉，");
        say("      两种写法的差异被同一个错误码淹没（lesson：无效凭据做对照没有区分度）。");
        say("      前缀的最终结论来自另外两处证据：");
        say("        1) 真机日志 —— 同一个真实 591 字符 JWT，裸 token 让 status 返 code 0、");
        say("           v2/sign 返 540004；加 `Bearer ` 立刻变 code 1。");
        say("        2) 签到页自己的 JS —— Authorization 取 sessionStorage 的 LOGIN_TOKEN 原值。");
        check("两种写法在无效凭据下响应码相同（说明此处无区分度，非结论）",
                respCode(f1.body) == respCode(f2.body),
                "裸=" + respCode(f1.body) + " 带前缀=" + respCode(f2.body));

        // ---------- G/H 纯逻辑断言 ----------
        say("");
        say("[G] looksJwt 判定");
        check("三段式且长度>40 → true", looksJwt(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz1"), "");
        check("普通短串 → false", !looksJwt("not-a-jwt"), "");
        check("两段式 → false", !looksJwt("aaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), "");

        say("");
        say("[H] addJwtCandidates 抠 URL 里的凭据");
        Set<String> got = new LinkedHashSet<String>();
        addJwtCandidates(got, "https://api5-h5-app-bj.ninebot.com/x?token="
                + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrstuvwxyz&language=zh&device_id=9");
        say("    抠出 " + got.size() + " 个: " + got);
        check("抠出了 token 且自动带/去 Bearer 两个变体", got.size() == 2, "size=" + got.size());

        // ---------- I 第七轮：按签到页自身 JS 做的改动（离线断言） ----------
        say("");
        say("[I] rewardSummary() —— 奖励字段名来自签到页自己的 JS，不是猜的");
        String r1 = "{\"code\":0,\"data\":{\"rewardList\":[{\"rewardId\":\"9\",\"name\":\"N\\u5e01\","
                + "\"rewardType\":2,\"rewardValue\":10}]}}";
        check("rewardType=2 → 读出 N币数额（10 N币）",
                rewardSummary(r1).contains("10 N币"), "[" + rewardSummary(r1) + "]");
        String r2 = "{\"code\":0,\"data\":{\"rewardList\":[{\"rewardType\":1,\"rewardValue\":5},"
                + "{\"rewardType\":3,\"medalName\":\"\\u8fde\\u7eed\\u7b7e\\u5230\\u52cb\\u7ae0\"},"
                + "{\"rewardType\":4,\"rewardValue\":1},{\"rewardType\":5}]}}";
        String s2 = rewardSummary(r2);
        check("多项奖励用 + 连接（经验值/勋章/补签卡/商城券都认）",
                s2.contains("5 经验值") && s2.contains("连续签到勋章")
                        && s2.contains("1 张补签卡") && s2.contains("商城兑换券"),
                "[" + s2 + "]");
        check("未知 rewardType 回退到 name 字段",
                rewardSummary("{\"code\":0,\"data\":{\"rewardList\":[{\"rewardType\":99,\"name\":\"\\u795e\\u79d8\\u793c\\u7269\"}]}}")
                        .contains("神秘礼物"),
                "[" + rewardSummary("{\"code\":0,\"data\":{\"rewardList\":[{\"rewardType\":99,\"name\":\"X\"}]}}") + "]");
        check("没有 rewardList 时返回空串且不抛异常",
                rewardSummary("{\"code\":0,\"data\":{}}").isEmpty(), "");
        check("响应体是 HTML 时返回空串且不抛异常",
                rewardSummary("<html>403</html>").isEmpty(), "");
        check("rewardList 为空数组时返回空串",
                rewardSummary("{\"code\":0,\"data\":{\"rewardList\":[]}}").isEmpty(), "");

        say("");
        say("[I2] explain() 对签到页里两个写死分支的判读");
        check("540004 → 判为「今日已签到」（签到页自己也是直接 return）",
                explain("{\"code\":540004,\"msg\":\"already signed in\"}").contains("今日已签到"),
                explain("{\"code\":540004}"));
        check("54019 → 判为「会话失效」（签到页的做法是 location.reload()）",
                explain("{\"code\":54019}").contains("会话失效"), explain("{\"code\":54019}"));
        check("真机那次的状态响应仍判为「成功」",
                explain("{\"code\":0,\"msg\":\"Success\"}").equals("成功"),
                explain("{\"code\":0,\"msg\":\"Success\"}"));

        say("");
        say("[I3] 签到请求体形状与签到页一致");
        JSONObject jb = new JSONObject(json);
        check("body 只有 deviceId 一个键（签到页发的是 {deviceId:e}）",
                jb.length() == 1 && jb.has("deviceId"), "keys=" + jb.keySet());

        // ---------- J 漂移检查：probe 与手机上的模块必须同步 ----------
        say("");
        say("[J] 漂移检查 —— probe 里的请求头/判读必须与 module 源码一致");
        String mod = readText("../module/src/com/ninebotsign/lsp/SignHook.java");
        if (mod == null) {
            mod = readText("module/src/com/ninebotsign/lsp/SignHook.java");
        }
        String self = readText("HttpProbe.java");
        say("    读模块源码: " + (mod == null ? "失败" : mod.length() + " 字符"));
        check("读到了模块源码", mod != null, "");
        String[] hn = {"device_id", "deviceId", "platform", "sys_language",
                "from_platform_1", "language", "Authorization"};
        for (int i = 0; i < hn.length; i++) {
            boolean inMod = mod != null && mod.contains("setRequestProperty(\"" + hn[i] + "\"");
            boolean inProbe = self != null && self.contains("setRequestProperty(\"" + hn[i] + "\"");
            check("请求头 " + hn[i] + " 两边都在", inMod && inProbe,
                    "模块=" + inMod + " probe=" + inProbe);
        }
        check("540004 分支两边都在",
                mod != null && mod.contains("respCode(body) == 540004")
                        && self != null && self.contains("respCode(body) == 540004"), "");
        check("54019 分支两边都在",
                mod != null && mod.contains("respCode(body) == 54019")
                        && self != null && self.contains("respCode(body) == 54019"), "");
        check("rewardSummary 两边都在",
                mod != null && mod.contains("static String rewardSummary(String body)")
                        && self != null && self.contains("static String rewardSummary(String body)"), "");

        // ---------- 汇总 ----------
        say("");
        say("== 汇总: PASS " + pass + " / FAIL " + fail);

        OutputStreamWriter w = new OutputStreamWriter(
                new FileOutputStream("probe_report.txt"), "UTF-8");
        w.write(REP.toString());
        w.flush();
        w.close();

        System.out.println("PASS=" + pass + " FAIL=" + fail);
        System.exit(fail == 0 ? 0 : 1);
    }
}
