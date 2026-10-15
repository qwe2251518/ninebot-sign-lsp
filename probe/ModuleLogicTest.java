package com.ninebotsign.lsp;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 用**模块真正的字节码**做断言 —— 不再把代码抄到桌面，而是直接编译
 * module/src/com/ninebotsign/lsp/SignHook.java，然后调用它自己的 static 方法。
 *
 * 这样就没有「probe 与手机上的代码走散」的可能：跑的就是打进 APK 的那份源码。
 *
 * 断言分两类：
 *   离线 —— 用**真机日志里抄下来的响应原文**喂给 respCode / explain / deepInt /
 *           rewardSummary / isAlreadySigned，检查判读对不对；
 *   线上 —— 调用模块自己的 http() 打一次真路径与一次假路径（凭据故意无效，只读路由）。
 *
 * 输出写进 probe/module_logic_report.txt（UTF-8）。
 */
public class ModuleLogicTest {

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

    // ---- 真机日志（2026-10-14，模块自己打的）里抄下来的响应原文 ------------------
    static final String DEV_SIGN_OK_INVALID = "{\"code\":1,\"msg\":\"系统错误\","
            + "\"key\":\"response.system.error\",\"t\":1791975339250}";

    static final String DEV_STATUS_OK = "{\"code\":0,\"msg\":\"Success\",\"key\":\"response.success\","
            + "\"data\":{\"consecutiveDays\":2,\"signCardsNum\":0,\"pushSwitch\":1,"
            + "\"currentSignStatus\":1,\"blindBoxStatus\":0,"
            + "\"jumpLink\":\"https://h5-bj.ninebot.com/ninebotApp/#/clockIns\","
            + "\"jumpToTaskCenterLink\":\"https://h5-bj.ninebot.com/ninebotApp/#/taskCenter"
            + "?immersed=1&pre_page=mn-cic&checkInChannel=0\"}}";

    static final String DEV_SIGN_ALREADY = "{\"code\":540004,\"msg\":\"already signed in, "
            + "cannot sign in again\"}";

    static final String DEV_SIGN_V1_DEAD = "{\"code\":57016,\"msg\":\"该功能仅支持最新版本，请升级后使用\"}";

    static final String DEV_SESSION_EXPIRED = "{\"code\":54019,\"msg\":\"token invalid\"}";

    static final String NOT_FOUND = "{\"timestamp\":1791975338739,\"status\":404,"
            + "\"error\":\"Not Found\",\"path\":\"/portal/api/user-sign/v2/no-such-path-probe\"}";

    static final String HTML_403 = "<html><head><title>403 Forbidden</title></head></html>";

    static final String SUCCESS_WITH_REWARDS = "{\"code\":0,\"msg\":\"Success\",\"data\":{\"rewardList\":["
            + "{\"rewardId\":\"1\",\"name\":\"N币\",\"rewardType\":2,\"rewardValue\":10},"
            + "{\"rewardId\":\"2\",\"rewardType\":3,\"medalName\":\"连续签到勋章\"},"
            + "{\"rewardId\":\"3\",\"rewardType\":4,\"rewardValue\":1},"
            + "{\"rewardId\":\"4\",\"rewardType\":1,\"rewardValue\":5},"
            + "{\"rewardId\":\"5\",\"rewardType\":5}]}}";

    static final String LONG_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI5OTk5OTk5OTk5OTk5OSIsInVpZCI6IjQ1OTk5MTcyMSJ9"
            + ".I0SD54abcdefghijklmnopqrstuvwxyz0123456789";

    public static void main(String[] args) throws Exception {
        SignHook.deviceId = "probe-device-id";

        say("== 模块**真代码**逻辑验证（编的是 module/src/.../SignHook.java 本身）");
        say("   证据 = 真机日志里抄下来的响应原文 + 签到页自身 JS 的字段名");
        say("   线上部分凭据故意无效，只探路由，不提交数据");
        say("");

        // ---------- 1. 判读：真机那几个响应 ----------
        say("[1] explain() 对真机响应原文的判读");
        check("真机 status(无效 token) → 判为「凭据被拒」",
                SignHook.explain(DEV_SIGN_OK_INVALID).contains("凭据被服务器拒绝"),
                SignHook.explain(DEV_SIGN_OK_INVALID));
        check("真机 status(code 0) → 判为「成功」",
                SignHook.explain(DEV_STATUS_OK).equals("成功"), SignHook.explain(DEV_STATUS_OK));
        check("真机 v2/sign(code 540004) → 判为「今日已签到」",
                SignHook.explain(DEV_SIGN_ALREADY).contains("今日已签到"),
                SignHook.explain(DEV_SIGN_ALREADY));
        check("v1 已废弃(code 57016) → **不得**判成成功",
                !SignHook.explain(DEV_SIGN_V1_DEAD).equals("成功"),
                SignHook.explain(DEV_SIGN_V1_DEAD));
        check("会话失效(code 54019) → 判为「会话失效」",
                SignHook.explain(DEV_SESSION_EXPIRED).contains("会话失效"),
                SignHook.explain(DEV_SESSION_EXPIRED));
        check("404 对照 → 判为「接口路径不存在」",
                SignHook.explain(NOT_FOUND).contains("路径不存在"), SignHook.explain(NOT_FOUND));
        check("异常体(EXC) → 判为「请求根本没发出去」",
                SignHook.explain("EXC java.net.UnknownHostException: x").contains("根本没发出去"), "");
        check("HTML(403 页) → 不会判成成功", !SignHook.explain(HTML_403).equals("成功"),
                SignHook.explain(HTML_403));

        // ---------- 2. respCode ----------
        say("");
        say("[2] respCode()");
        check("code 1 → 1", SignHook.respCode(DEV_SIGN_OK_INVALID) == 1, "");
        check("code 0 → 0", SignHook.respCode(DEV_STATUS_OK) == 0, "");
        check("540004 → 540004", SignHook.respCode(DEV_SIGN_ALREADY) == 540004, "");
        check("404 JSON 没有 code → -999", SignHook.respCode(NOT_FOUND) == -999, "");
        check("HTML → -999", SignHook.respCode(HTML_403) == -999, "");

        // ---------- 3. deepInt：真机 code 0 那几个字段 ----------
        say("");
        say("[3] deepInt() 对真机 code 0 响应的取值");
        check("currentSignStatus = 1", SignHook.deepInt(DEV_STATUS_OK, "currentSignStatus", -1) == 1,
                "got=" + SignHook.deepInt(DEV_STATUS_OK, "currentSignStatus", -1));
        check("consecutiveDays = 2", SignHook.deepInt(DEV_STATUS_OK, "consecutiveDays", -1) == 2,
                "got=" + SignHook.deepInt(DEV_STATUS_OK, "consecutiveDays", -1));
        check("signCardsNum = 0", SignHook.deepInt(DEV_STATUS_OK, "signCardsNum", -9) == 0,
                "got=" + SignHook.deepInt(DEV_STATUS_OK, "signCardsNum", -9));
        check("blindBoxStatus = 0", SignHook.deepInt(DEV_STATUS_OK, "blindBoxStatus", -9) == 0,
                "got=" + SignHook.deepInt(DEV_STATUS_OK, "blindBoxStatus", -9));
        check("pushSwitch = 1", SignHook.deepInt(DEV_STATUS_OK, "pushSwitch", -1) == 1,
                "got=" + SignHook.deepInt(DEV_STATUS_OK, "pushSwitch", -1));
        check("字段在顶层也能取", SignHook.deepInt("{\"code\":0,\"currentSignStatus\":1}", "currentSignStatus", -1) == 1, "");
        say("    已知局限：字段嵌到 data.signInfo.* 里取不到 → "
                + SignHook.deepInt("{\"code\":0,\"data\":{\"signInfo\":{\"currentSignStatus\":1}}}",
                        "currentSignStatus", -1)
                + "（只会多做一次签到，不会误判成功）");

        // ---------- 4. 已签判定（三重兜底里的第三重） ----------
        say("");
        say("[4] isAlreadySigned() —— 只认 540004 / 中文「已签到」/ already / repeat");
        check("真机 540004 原文 → true", SignHook.isAlreadySigned(DEV_SIGN_ALREADY), "");
        check("中文「今日已签到」→ true", SignHook.isAlreadySigned("{\"msg\":\"今天已签到\"}"), "");
        check("普通系统错误 → false", !SignHook.isAlreadySigned(DEV_SIGN_OK_INVALID), "");
        check("v1 已废弃那条 → false（不能被当成已签吞掉）",
                !SignHook.isAlreadySigned(DEV_SIGN_V1_DEAD), "");
        check("404 → false", !SignHook.isAlreadySigned(NOT_FOUND), "");
        check("null → false", !SignHook.isAlreadySigned(null), "");

        // ---------- 5. 奖励解析 ----------
        say("");
        say("[5] rewardSummary() —— 字段名来自签到页自己的 JS");
        String rs = SignHook.rewardSummary(SUCCESS_WITH_REWARDS);
        say("    解析结果: [" + rs + "]");
        check("rewardType2 → 10 N币", rs.contains("10 N币"), "");
        check("rewardType3 → 勋章名（medalName）", rs.contains("连续签到勋章"), "");
        check("rewardType4 → 1 张补签卡", rs.contains("1 张补签卡"), "");
        check("rewardType1 → 5 经验值", rs.contains("5 经验值"), "");
        check("rewardType5 → 商城兑换券", rs.contains("商城兑换券"), "");
        check("多项用 + 连接", rs.split(" \\+ ").length == 5, "段数=" + rs.split(" \\+ ").length);
        check("没有 rewardList → 空串", SignHook.rewardSummary(DEV_STATUS_OK).isEmpty(),
                "[" + SignHook.rewardSummary(DEV_STATUS_OK) + "]");
        check("响应是 HTML → 空串且不抛异常", SignHook.rewardSummary(HTML_403).isEmpty(), "");

        // ---------- 6. 凭据处理：掩码与候选构造 ----------
        say("");
        say("[6] mask() / candidateSummary() —— 日志里不能出现完整 token");
        String masked = SignHook.mask(LONG_TOKEN);
        say("    掩码示例: " + masked);
        check("掩码后不含原 token 全串", !masked.contains(LONG_TOKEN), "");
        check("掩码保留长度信息", masked.contains("len=" + LONG_TOKEN.length()), masked);
        check("短串只显示长度", SignHook.mask("abc").equals("***len=3"), SignHook.mask("abc"));
        check("null 不抛异常", SignHook.mask(null).equals("null"), "");

        Set<String> cands = new LinkedHashSet<String>();
        cands.add(LONG_TOKEN);
        SignHook.addTok(cands, LONG_TOKEN);
        SignHook.addJwtCandidates(cands,
                "https://api5-h5-app-bj.ninebot.com/x?token=" + LONG_TOKEN + "&language=zh&device_id=9");
        say("    候选数: " + cands.size() + " → " + SignHook.candidateSummary(cands));
        check("候选里裸 token 与 Bearer 版都在", cands.size() >= 2, "size=" + cands.size());
        check("候选摘要里没有完整 token",
                !SignHook.candidateSummary(cands).contains(LONG_TOKEN), "");
        check("looksJwt 三段式长串 → true", SignHook.looksJwt(LONG_TOKEN), "");
        check("looksJwt 两段式 → false", !SignHook.looksJwt("aaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), "");
        check("today() 形如 yyyy-MM-dd", SignHook.today().matches("\\d{4}-\\d{2}-\\d{2}"), SignHook.today());

        // ---------- 7. 线上：模块自己的 http() ----------
        say("");
        say("[7] 线上：用模块自己的 http() 打真路径 / 假路径（凭据无效）");
        SignHook.Resp r1 = SignHook.http("POST", SignHook.GW + "/portal/api/user-sign/v2/no-such-path-probe",
                "{\"deviceId\":\"" + SignHook.deviceId + "\"}", "probe-invalid-token");
        say("    假路径: HTTP " + r1.httpCode + "  判定: " + SignHook.explain(r1.body));
        check("假路径 → 404", r1.httpCode == 404, "http=" + r1.httpCode);
        check("假路径 → 判为路径不存在", SignHook.explain(r1.body).contains("路径不存在"), "");
        sleep(400);
        SignHook.Resp r2 = SignHook.http("POST", SignHook.URL_SIGN_V2,
                "{\"deviceId\":\"" + SignHook.deviceId + "\"}", "probe-invalid-token");
        say("    真路径: HTTP " + r2.httpCode + "  code=" + SignHook.respCode(r2.body)
                + "  判定: " + SignHook.explain(r2.body));
        say("    原文: " + SignHook.clip(r2.body, 200));
        check("真路径 → HTTP 200（第七轮新增的请求头没有把请求弄坏）", r2.httpCode == 200,
                "http=" + r2.httpCode);
        check("真路径 → 不是 404", !SignHook.explain(r2.body).contains("路径不存在"), "");
        check("真路径 → 无 SSL/连接异常", !r2.body.startsWith("EXC "), "");
        check("无效凭据 → 不会误判成功", SignHook.respCode(r2.body) != 0 && !r2.body.startsWith("EXC"),
                "code=" + SignHook.respCode(r2.body));
        sleep(400);
        SignHook.Resp r3 = SignHook.http("GET", SignHook.URL_STATUS + "?t=" + System.currentTimeMillis(),
                null, "probe-invalid-token");
        say("    status : HTTP " + r3.httpCode + "  code=" + SignHook.respCode(r3.body));
        check("status 走 GET 有响应", r3.httpCode == 200, "http=" + r3.httpCode);

        say("");
        say("== 汇总: PASS " + pass + " / FAIL " + fail);

        java.io.OutputStreamWriter w = new java.io.OutputStreamWriter(
                new java.io.FileOutputStream("probe/module_logic_report.txt"), "UTF-8");
        w.write(REP.toString());
        w.flush();
        w.close();

        System.out.println("PASS=" + pass + " FAIL=" + fail);
        System.exit(fail == 0 ? 0 : 1);
    }
}
