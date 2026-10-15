package com.ninebotsign.lsp;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

/**
 * 抓「模块真正发出去的请求」到底长什么样。
 *
 * 做法：在本地起一个 HttpServer，把模块自己的 http() 指过来（http() 的 URL 是入参），
 * 然后把收到的 method / URI / 每一个请求头 / body 原文全部抓下来做断言。
 *
 * 这样就补上了此前所有验证的盲区：以前只能证明「服务器接受了我们的请求」
 * （真机 status 返回 code 0），但**没有人检查过我们到底发了哪些头、值对不对**
 * —— 那是照着一手证据逐个 setRequestProperty 写进去的，必须逐条锁死。
 *
 * 输出写 probe/request_shape_report.txt（UTF-8）。全程本地回环，不碰真实服务器。
 */
public class RequestShapeTest {

    static final StringBuilder REP = new StringBuilder();
    static int pass = 0;
    static int fail = 0;

    // 服务器抓到的内容
    static volatile String capMethod;
    static volatile String capUri;
    static volatile String capBody;
    static volatile Map<String, String> capHeaders = new HashMap<String, String>();

    // 让服务器扮演回去的内容
    static volatile int respStatus = 200;
    static volatile String respBody = "{\"code\":0,\"msg\":\"Success\"}";
    static volatile String respType = "application/json";

    static void say(String s) {
        REP.append(s).append('\n');
    }

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            pass++;
        } else {
            fail++;
        }
        say((ok ? "  [PASS] " : "  [FAIL] ") + name + (detail == null || detail.isEmpty() ? "" : "   (" + detail + ")"));
    }

    static String readAll(InputStream is) throws IOException {
        if (is == null) {
            return "";
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return new String(bos.toByteArray(), "UTF-8");
    }

    static void handle(HttpExchange ex) throws IOException {
        capMethod = ex.getRequestMethod();
        capUri = ex.getRequestURI().toString();
        Headers h = ex.getRequestHeaders();
        Map<String, String> m = new HashMap<String, String>();
        for (String k : h.keySet()) {
            m.put(k.toLowerCase(), h.getFirst(k));
        }
        capHeaders = m;
        capBody = readAll(ex.getRequestBody());
        byte[] b = respBody.getBytes("UTF-8");
        ex.getResponseHeaders().set("Content-Type", respType);
        ex.sendResponseHeaders(respStatus, b.length);
        OutputStream os = ex.getResponseBody();
        os.write(b);
        os.close();
    }

    static void reset() {
        capMethod = null;
        capUri = null;
        capBody = null;
        capHeaders = new HashMap<String, String>();
        respStatus = 200;
        respBody = "{\"code\":0,\"msg\":\"Success\"}";
        respType = "application/json";
    }

    static String hdr(String name) {
        String v = capHeaders.get(name.toLowerCase());
        return v == null ? "<缺失>" : v;
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/capture", new com.sun.net.httpserver.HttpHandler() {
            public void handle(HttpExchange ex) throws IOException {
                RequestShapeTest.handle(ex);
            }
        });
        server.setExecutor(null);
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/capture";

        SignHook.deviceId = "probe-device-id-0123456789abcdef";
        SignHook.uid = "100000001";
        final String token = "eyJhbGciOiJIUzI1NiJ9.probe.token";
        final String body = "{\"deviceId\":\"" + SignHook.deviceId + "\"}";

        say("== 模块 http() 真正发出去的请求（本地回环抓包）");
        say("   被测代码 = module/src/com/ninebotsign/lsp/SignHook.java 本身");
        say("   这一步补的盲区：以前只证明「服务器没拒绝」，没证明「我们发的头对不对」");
        say("");

        // ---------- 1. 签到 POST 的完整形状 ----------
        say("[1] POST 签到请求：逐个头核对");
        reset();
        SignHook.Resp r = SignHook.http("POST", base, body, token);

        say("    抓到的请求头：");
        for (String k : new java.util.TreeSet<String>(capHeaders.keySet())) {
            say("      " + k + ": " + capHeaders.get(k));
        }
        say("    body: " + capBody);
        say("");

        check("方法 = POST", "POST".equals(capMethod), "got=" + capMethod);
        check("Authorization 就是 token 原文（不加 Bearer）", token.equals(hdr("authorization")),
                "got=" + SignHook.mask(hdr("authorization")));
        check("Authorization 里没有 Bearer 前缀", !hdr("authorization").contains("Bearer"), "");
        check("device_id（下划线）= deviceId", SignHook.deviceId.equals(hdr("device_id")), hdr("device_id"));
        check("deviceId（驼峰）= deviceId", SignHook.deviceId.equals(hdr("deviceId")), hdr("deviceId"));
        check("uid 头带上了", SignHook.uid.equals(hdr("uid")), hdr("uid"));
        check("platform = h5", "h5".equals(hdr("platform")), hdr("platform"));
        check("language = zh", "zh".equals(hdr("language")), hdr("language"));
        check("sys_language = zh-CN", "zh-CN".equals(hdr("sys_language")), hdr("sys_language"));
        check("from_platform_1 = 1", "1".equals(hdr("from_platform_1")), hdr("from_platform_1"));
        // Origin 在 JDK 的 HttpURLConnection 里属于**受限头**，setRequestProperty 会被静默忽略
        // （除非加 -Dsun.net.http.allowRestrictedHeaders=true）。所以这里分两种模式断言，
        // 两种都不能是「恒真」：放开时必须是预期值，没放开时必须确实缺失（否则说明 JDK 行为变了）。
        String origin = capHeaders.get("origin");
        boolean allowRestricted = "true".equals(System.getProperty("sun.net.http.allowRestrictedHeaders"));
        if (allowRestricted) {
            check("Origin = https://h5-bj.ninebot.com（已放开 JDK 受限头）",
                    "https://h5-bj.ninebot.com".equals(origin), "got=" + origin);
        } else {
            check("Origin 被 JDK 受限头策略丢掉（模块的调用没写错，见下方说明）",
                    origin == null, "got=" + origin);
            say("    说明：模块确实调用了 setRequestProperty(\"Origin\", ...)，但桌面 JDK 会吞掉它。");
            say("    这次带上 -Dsun.net.http.allowRestrictedHeaders=true 再跑一遍，就能证明调用本身是对的。");
            say("    Android 的 HttpURLConnection 是 OkHttp 实现，**不一定**同样吞掉 Origin；"
                    + "但真机日志里的 status 返回 code 0 已经证明这个头不是必需的（缺了也能通过）。");
        }
        check("Referer = https://h5-bj.ninebot.com/",
                "https://h5-bj.ninebot.com/".equals(hdr("referer")), hdr("referer"));
        check("User-Agent 与一手证据一致", SignHook.UA.equals(hdr("user-agent")), hdr("user-agent"));
        check("Content-Type 是 json",
                hdr("content-type").startsWith("application/json"), hdr("content-type"));
        check("Accept 与页面一致",
                "application/json, text/plain, */*".equals(hdr("accept")), hdr("accept"));
        check("body 就是 {\"deviceId\":\"...\"}",
                body.equals(capBody), capBody);
        say("    参考（模块没有显式设置，交给平台自己处理）：Accept-Encoding = "
                + hdr("accept-encoding"));
        check("响应 200 + code 0 → 判为成功", SignHook.respCode(r.body) == 0
                && SignHook.explain(r.body).equals("成功"), SignHook.explain(r.body));

        // ---------- 2. 不带凭据时不发 Authorization ----------
        say("");
        say("[2] auth = null / uid 为空时的边界");
        reset();
        SignHook.http("POST", base, body, null);
        check("auth=null → 不发 Authorization 头", !capHeaders.containsKey("authorization"),
                "headers=" + capHeaders.keySet());
        SignHook.uid = "";
        reset();
        SignHook.http("POST", base, body, token);
        check("uid 为空 → 不发 uid 头", !capHeaders.containsKey("uid"), "");
        SignHook.uid = "100000001";

        // ---------- 3. GET + 查询串 ----------
        say("");
        say("[3] status 那种 GET");
        reset();
        SignHook.http("GET", base + "?t=1791975339250", null, token);
        check("方法 = GET", "GET".equals(capMethod), "got=" + capMethod);
        check("查询串原样保留", "/capture?t=1791975339250".equals(capUri), "got=" + capUri);
        check("GET 没有 body", capBody == null || capBody.isEmpty(), "[" + capBody + "]");
        check("GET 也带 Authorization", token.equals(hdr("authorization")), "");

        // ---------- 4. 响应侧：404 / 403 / 服务器错误 的处理 ----------
        say("");
        say("[4] 服务端各种脸色下的行为");
        reset();
        respStatus = 404;
        respBody = "{\"timestamp\":1,\"status\":404,\"error\":\"Not Found\",\"path\":\"/capture\"}";
        SignHook.Resp r404 = SignHook.http("POST", base, body, token);
        check("404 → httpCode 404", r404.httpCode == 404, "got=" + r404.httpCode);
        check("404 → 错误流也读得到内容", r404.body.contains("Not Found"), "[" + r404.body + "]");
        check("404 → 判为路径不存在", SignHook.explain(r404.body).contains("路径不存在"), "");

        reset();
        respStatus = 403;
        respType = "text/html";
        respBody = "<html><head><title>403 Forbidden</title></head></html>";
        SignHook.Resp r403 = SignHook.http("POST", base, body, token);
        check("403 HTML → 不判成功", !SignHook.explain(r403.body).equals("成功"), SignHook.explain(r403.body));
        check("403 HTML → respCode -999", SignHook.respCode(r403.body) == -999, "");
        check("403 HTML → 奖励为空且不抛异常", SignHook.rewardSummary(r403.body).isEmpty(), "");

        reset();
        respStatus = 500;
        respBody = "{\"code\":1,\"msg\":\"系统错误\",\"key\":\"response.system.error\"}";
        SignHook.Resp r500 = SignHook.http("POST", base, body, token);
        check("500 → httpCode 500", r500.httpCode == 500, "got=" + r500.httpCode);
        check("500 → 判为凭据被拒（不是成功）",
                SignHook.explain(r500.body).contains("凭据被服务器拒绝"), SignHook.explain(r500.body));

        // ---------- 5. 全链路离线演练：服务器扮演「签到成功」 ----------
        say("");
        say("[5] 服务器扮演「签到成功」，看模块的判读链能不能读出奖励");
        reset();
        respBody = "{\"code\":0,\"msg\":\"Success\",\"data\":{\"consecutiveDays\":3,"
                + "\"currentSignStatus\":1,\"rewardList\":[{\"rewardType\":2,\"rewardValue\":10},"
                + "{\"rewardType\":4,\"rewardValue\":1}]}}";
        SignHook.Resp rok = SignHook.http("POST", base, body, token);
        say("    响应: " + SignHook.clip(rok.body, 200));
        check("HTTP 200", rok.httpCode == 200, "got=" + rok.httpCode);
        check("code = 0", SignHook.respCode(rok.body) == 0, "code=" + SignHook.respCode(rok.body));
        check("explain = 成功", SignHook.explain(rok.body).equals("成功"), SignHook.explain(rok.body));
        check("currentSignStatus = 1", SignHook.deepInt(rok.body, "currentSignStatus", -1) == 1, "");
        check("consecutiveDays = 3", SignHook.deepInt(rok.body, "consecutiveDays", -1) == 3, "");
        String rs = SignHook.rewardSummary(rok.body);
        say("    奖励解析: [" + rs + "]");
        check("奖励解析出 10 N币 + 1 张补签卡", rs.contains("10 N币") && rs.contains("1 张补签卡"), rs);

        // ---------- 6. 连接不上时不会把异常抛出去 ----------
        say("");
        say("[6] 打不通的地址");
        SignHook.Resp rdead = SignHook.http("POST", "http://127.0.0.1:1/capture", body, token);
        check("连接失败 → httpCode -1、body 以 EXC 开头（不抛异常）",
                rdead.httpCode == -1 && rdead.body.startsWith("EXC "), "http=" + rdead.httpCode);
        check("连接失败 → 判为「请求根本没发出去」",
                SignHook.explain(rdead.body).contains("根本没发出去"), SignHook.explain(rdead.body));

        server.stop(0);

        say("");
        say("== 汇总: PASS " + pass + " / FAIL " + fail);
        java.io.OutputStreamWriter w = new java.io.OutputStreamWriter(
                new java.io.FileOutputStream(allowRestricted
                        ? "probe/request_shape_report.txt"
                        : "probe/request_shape_report_norestrict.txt"), "UTF-8");
        w.write(REP.toString());
        w.flush();
        w.close();
        System.out.println("PASS=" + pass + " FAIL=" + fail);
        System.exit(fail == 0 ? 0 : 1);
    }
}
