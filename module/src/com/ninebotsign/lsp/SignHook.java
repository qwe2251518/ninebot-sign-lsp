package com.ninebotsign.lsp;

import android.app.Application;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ImageView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class SignHook implements IXposedHookLoadPackage {

    static final String TAG = "NinebotSign: ";
    static final String PKG = "cn.ninebot.ninebot";

    static final String GW = "https://cn-cbu-gateway.ninebot.com";
    static final String URL_SIGN_V2 = GW + "/portal/api/user-sign/v2/sign";
    static final String URL_SIGN_V1 = GW + "/portal/api/user-sign/v1/sign";
    static final String URL_STATUS = GW + "/portal/api/user-sign/v2/status";

    static final String GW_H5 = "https://api5-h5-app-bj.ninebot.com";

    static final String UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Segway v6 C 609033420";

    static volatile Context appCtx;
    static volatile boolean isMainProcess;
    static volatile boolean appStarted;

    static volatile String deviceId;
    static volatile String uid;

    static volatile String token;
    static volatile String rnToken;
    static volatile String passportToken;
    static volatile String authHeader;
    static volatile String gwAuthHeader;

    static volatile String jwtBase;
    static volatile String jwtWhole;
    static volatile String webUrl;
    static final Set<String> seenWebUrls = new LinkedHashSet<String>();

    static volatile String curActivity = "?";

    static final Set<String> seenImages = new LinkedHashSet<String>();
    static final int IMG_LOG_MAX = 300;

    static final String VEH_IMG_KEY = "device-config";

    static volatile boolean vehImgOn = false;
    static volatile String vehImgPath = null;
    static volatile long vehConfAt = 0L;

    static volatile String vehSrcPath = null;

    static final AtomicBoolean inFlight = new AtomicBoolean(false);

    static volatile long lastAttemptAt = 0L;

    static volatile boolean quietToday = false;

    static final Set<String> hookLog = new LinkedHashSet<String>();

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if (!PKG.equals(lp.packageName)) {
            return;
        }
        isMainProcess = PKG.equals(lp.processName) || lp.processName == null;
        log("注入成功 process=" + lp.processName);

        hookApplicationContext(lp);
        hookLifecycle(lp);
        hookImageDiag(lp);
        hookVehicleCmds(lp);
        hookConfigDump(lp);
        hookFakeExpiry(lp);

        hook(lp, "cn.ninebot.commonlibs.nbnet.BodyParametersProvider", "setDeviceId",
                new Arg0Saver(new Sink() {
                    public void put(String v) { deviceId = v; }
                }, "deviceId(BodyParametersProvider)"));
        hook(lp, "cn.ninebot.commonlibs.nbnet.NbHttpClient", "setDeviceId",
                new Arg0Saver(new Sink() {
                    public void put(String v) { deviceId = v; }
                }, "deviceId(NbHttpClient)"));
        hook(lp, "cn.ninebot.commonlibs.nbnet.BodyParametersProvider", "setUid",
                new Arg0Saver(new Sink() {
                    public void put(String v) { uid = v; }
                }, "uid"));

        hook(lp, "cn.ninebot.commonlibs.nbnet.NbHttpClient", "setToken",
                new Arg0Saver(new Sink() {
                    public void put(String v) { token = v; }
                }, "token(NbHttpClient#setToken)"));

        hook(lp, "cn.ninebot.lib.passport.account.PassportApiClient", "getAccessToken",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Object r = p.getResult();
                            if (r instanceof String && ((String) r).length() >= 8) {
                                String s = (String) r;
                                if (!s.equals(passportToken)) {
                                    passportToken = s;
                                    log("捕获 passportToken(getAccessToken)=" + mask(s));
                                }
                            }
                        } catch (Throwable t) {
                        }
                        maybeSign();
                    }
                });
        hook(lp, "cn.ninebot.lib.passport.account.PassportApiClient", "saveToken",
                new Arg0Saver(new Sink() {
                    public void put(String v) { passportToken = v; }
                }, "passportToken(saveToken)"));

        hook(lp, "cn.ninebot.react.modules.CommonModule", "syncToken",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Object map = p.args[0];
                            Object v = XposedHelpers.callMethod(map, "getString", "access_token");
                            if (v instanceof String) {
                                rnToken = (String) v;
                                log("捕获 rnToken=" + mask(rnToken));
                            }
                        } catch (Throwable t) {

                        }
                        maybeSign();
                    }
                });

        hook(lp, "okhttp3.internal.http.RealInterceptorChain", "proceed",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        try {
                            Object req = p.args[0];
                            Object h = XposedHelpers.callMethod(req, "header", "Authorization");
                            if (h instanceof String && ((String) h).length() > 0) {
                                String s = (String) h;

                                String host = "";
                                try {
                                    Object url = XposedHelpers.callMethod(req, "url");
                                    if (url != null) {
                                        host = String.valueOf(XposedHelpers.callMethod(url, "host"));
                                    }
                                } catch (Throwable ignore) {
                                }
                                if (host.contains("ninebot")) {
                                    if (!s.equals(gwAuthHeader)) {
                                        gwAuthHeader = s;
                                        log("捕获 gwAuthHeader(host=" + host + ")=" + mask(s));
                                    }
                                }
                                if (!s.equals(authHeader)) {
                                    authHeader = s;
                                    log("捕获 authHeader(host=" + host + ")=" + mask(s));
                                }
                            }
                            if (deviceId == null) {
                                Object d = XposedHelpers.callMethod(req, "header", "deviceId");
                                if (d instanceof String && ((String) d).length() > 0) {
                                    deviceId = (String) d;
                                    log("捕获 deviceId(请求头)=" + deviceId);
                                }
                            }
                        } catch (Throwable t) {
                        }
                        maybeSign();
                    }
                });

        hook(lp, "cn.ninebot.lib.passport.account.PassportApiClient", "generateAuthorizationHeaders",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Object r = p.getResult();
                            if (r instanceof java.util.Map) {
                                java.util.Map<?, ?> m = (java.util.Map<?, ?>) r;
                                Object v = m.get("Authorization");
                                if (!(v instanceof String)) {
                                    v = m.get("authorization");
                                }
                                if (v instanceof String && ((String) v).length() > 0) {
                                    authHeader = (String) v;
                                    log("捕获 authHeader(generateAuthorizationHeaders)=" + mask(authHeader));
                                }
                            }
                        } catch (Throwable t) {
                        }
                        maybeSign();
                    }
                });

        hook(lp, "cn.ninebot.lib.passport.account.TokenInterceptor", "intercept",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Object chain = p.args[0];
                            Object req = XposedHelpers.callMethod(chain, "request");
                            Object h = XposedHelpers.callMethod(req, "header", "Authorization");
                            if (h instanceof String && ((String) h).length() > 0) {
                                String s = (String) h;
                                if (!s.equals(authHeader)) {
                                    authHeader = s;
                                    log("捕获 authHeader=" + mask(s));
                                }
                            }
                        } catch (Throwable t) {
                        }
                        maybeSign();
                    }
                });

        hook(lp, "cn.ninebot.commonlibs.nbnet.NbHttpClient", "getH5BaseJwtUrl",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        if (p.getResult() instanceof String) {
                            String s = (String) p.getResult();
                            if (s.length() > 0 && !s.equals(jwtBase)) {
                                jwtBase = s;
                                log("捕获 jwtBase=" + s);
                            }
                        }
                        maybeSign();
                    }
                });
        hook(lp, "cn.ninebot.commonlibs.nbnet.NbH5UrlHelper", "getJwtWholeUrl",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            if (p.args != null && p.args.length > 0 && p.args[0] instanceof String) {
                                log("getJwtWholeUrl 入参 path=" + p.args[0]);
                            }
                        } catch (Throwable t) {
                        }
                        if (p.getResult() instanceof String) {
                            jwtWhole = (String) p.getResult();
                            log("捕获 jwtWhole=" + clip(jwtWhole, 400));
                        }
                        maybeSign();
                    }
                });
        hook(lp, "cn.ninebot.commonlibs.nbnet.NbH5UrlHelper", "getWholeUrl",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        if (p.getResult() instanceof String) {
                            String s = (String) p.getResult();
                            if (jwtWhole == null && s.length() > 0) {
                                jwtWhole = s;
                                log("捕获 wholeUrl=" + clip(s, 400));
                            }
                        }
                        maybeSign();
                    }
                });

        hook(lp, "cn.ninebot.support.web.JsInterfaceImpl", "interactiveWithAndroid",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        log("JS->Android: " + clip(str(p.args, 0), 400));
                    }
                });
        hook(lp, "cn.ninebot.support.web.JsInterfaceImpl", "callUnifiedMethod",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        StringBuilder sb = new StringBuilder("callUnifiedMethod");
                        for (int i = 0; i < p.args.length; i++) {
                            sb.append(" a").append(i).append('=').append(clip(str(p.args, i), 200));
                        }
                        log(sb.toString());
                    }
                });

        hook(lp, "android.webkit.WebView", "loadUrl",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        String u = str(p.args, 0);
                        if (u == null || u.length() < 12
                                || u.startsWith("data:") || u.startsWith("about:")
                                || u.startsWith("javascript:") || u.startsWith("blob:")) {
                            return;
                        }
                        webUrl = u;
                        synchronized (seenWebUrls) {
                            if (seenWebUrls.size() < 15 && seenWebUrls.add(u)) {
                                log("loadUrl: " + clip(u, 400));
                            }
                        }
                    }
                });

        int okN = 0, failN = 0;
        for (String s : hookLog) {
            if (s.startsWith("OK ")) {
                okN++;
            } else if (s.startsWith("FAIL")) {
                failN++;
            }
        }
        log("hook 安装汇总：成功 " + okN + " 个，失败 " + failN + " 个"
                + (failN == 0 ? "" : "（失败明细见上面的 hook 失败 行）"));
    }

    private void hookApplicationContext(final XC_LoadPackage.LoadPackageParam lp) {
        try {
            XposedHelpers.findAndHookMethod(android.app.Instrumentation.class,
                    "callApplicationOnCreate", Application.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            try {
                                appCtx = (Application) p.args[0];
                            } catch (Throwable t) {
                            }
                            appStarted = true;
                            log("应用 onCreate，模块开始待命");
                            selfCheckLater();
                        }
                    });
            note("Instrumentation#callApplicationOnCreate 已挂");
        } catch (Throwable t) {
            log("hook Instrumentation 失败: " + t);
        }
    }

    private void hookLifecycle(final XC_LoadPackage.LoadPackageParam lp) {

        try {
            XposedHelpers.findAndHookMethod(android.app.Activity.class, "onResume",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            try {
                                if (p.thisObject != null) {
                                    curActivity = p.thisObject.getClass().getSimpleName();
                                    if (appCtx == null && p.thisObject instanceof android.content.Context) {
                                        appCtx = ((android.content.Context) p.thisObject).getApplicationContext();
                                    }
                                }
                            } catch (Throwable t) {
                            }
                            maybeSign();
                        }
                    });
            note("Activity#onResume 已挂（暖启动触发）");
        } catch (Throwable t) {
            log("hook Activity#onResume 失败: " + t);
        }

        try {
            XposedHelpers.findAndHookMethod(android.app.Application.class, "onCreate",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            if (appCtx == null && p.thisObject instanceof Context) {
                                appCtx = (Context) p.thisObject;
                                log("Application#onCreate 兜住上下文");
                            }
                            appStarted = true;
                        }
                    });
            note("Application#onCreate 已挂（上下文兜底）");
        } catch (Throwable t) {
            log("hook Application#onCreate 失败: " + t);
        }
    }

    private void selfCheckLater() {
        new Thread(new Runnable() {
            public void run() {
                try {
                    Thread.sleep(25000);
                } catch (InterruptedException e) {
                }
                if (token == null && authHeader == null && rnToken == null && passportToken == null) {
                    String pn = procName();
                    log("提示：本进程（" + pn + "）25 秒内未捕获到任何 token。");
                    if (!"cn.ninebot.ninebot".equals(pn)) {
                        log("本进程不是主进程 —— 辅助进程本来就不建网络层、不存 token，"
                                + "出现这行是正常的，可以忽略。");
                    }
                    log("已挂载的 hook 清单：");
                    for (String s : hookLog) {
                        log("   [" + s + "]");
                    }
                    log("可能原因：九号 app 版本变化导致 hook 点偏移，或本次启动尚未初始化网络层。");
                }
            }
        }).start();
    }

    static String procName() {
        FileInputStream in = null;
        try {
            in = new FileInputStream("/proc/self/cmdline");
            byte[] buf = new byte[256];
            int n = in.read(buf);
            if (n <= 0) {
                return "?";
            }
            int end = 0;
            while (end < n && buf[end] != 0) {
                end++;
            }
            return new String(buf, 0, end, "UTF-8");
        } catch (Throwable t) {
            return "?";
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    static final long RETRY_INTERVAL_MS = 120000L;

    static void maybeSign() {

        syncUiConf();

        if (!confOn("signEnabled", true)) {
            if (!signOffLogged) {
                signOffLogged = true;
                log("设置里关掉了自动签到，本轮不签");
            }
            return;
        }

        if (deviceId == null || deviceId.length() == 0) {
            return;
        }
        if (token == null && authHeader == null && rnToken == null && passportToken == null) {
            return;
        }

        if (inFlight.get()) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastAttemptAt < RETRY_INTERVAL_MS) {
            return;
        }
        if (okToday()) {
            lastAttemptAt = now;
            if (!quietToday) {
                quietToday = true;
                log("今日已签到成功过（ninebot-sign.ok），今天不再请求");
            }
            return;
        }
        if (!inFlight.compareAndSet(false, true)) {
            return;
        }
        lastAttemptAt = now;
        log("凭据已齐，6 秒后开始签到");
        new Thread(new SignTask()).start();
    }

    static class SignTask implements Runnable {
        public void run() {
            try {
                Thread.sleep(6000);
            } catch (InterruptedException e) {
            }
            try {
                doSign();
            } catch (Throwable t) {
                log("签到过程异常: " + t);
                toast("九号签到：异常，详见 LSPosed 日志");
            } finally {
                inFlight.set(false);
            }
        }

        private void doSign() {
            if (okToday()) {
                if (!quietToday) {
                    quietToday = true;
                    log("今日已签到成功过（ninebot-sign.ok），本次不重复请求");
                }
                return;
            }

            String did = deviceId;
            log("================ 开始签到 ================");
            log("deviceId = " + did);
            log("uid      = " + uid);
            log("gwAuthHeader(ninebot 域名)       = " + mask(gwAuthHeader));
            log("authHeader(RealInterceptorChain) = " + mask(authHeader));
            log("passportToken(getAccessToken)    = " + mask(passportToken));
            log("token(原生 setToken)             = " + mask(token));
            log("rnToken(CommonModule)            = " + mask(rnToken));
            log("jwtBase  = " + clip(jwtBase, 300));
            log("jwtWhole = " + clip(jwtWhole, 300));

            Resp st = http("GET", URL_STATUS + "?t=" + System.currentTimeMillis(), null,
                    firstNonNull(firstNonNull(firstNonNull(token, gwAuthHeader), authHeader),
                            passportToken));
            log("状态查询 HTTP " + st.httpCode + " | " + explain(st.body) + " -> "
                    + clip(st.body, 500));
            if (st.httpCode == 200 && respCode(st.body) == 0) {
                int cs = deepInt(st.body, "currentSignStatus", -1);
                log("状态解析：currentSignStatus=" + cs
                        + " consecutiveDays=" + deepInt(st.body, "consecutiveDays", -1)
                        + " signCardsNum=" + deepInt(st.body, "signCardsNum", -1)
                        + " blindBoxStatus=" + deepInt(st.body, "blindBoxStatus", -1));
                if (cs == 1) {
                    int days = deepInt(st.body, "consecutiveDays", -1);
                    markOkToday();
                    log("状态接口显示今日已签到（连续 " + days + " 天），不再重复请求");
                    toast("九号签到：今日已签到" + (days > 0 ? "，连续 " + days + " 天" : ""));
                    return;
                }
            }

            String json = "{\"deviceId\":\"" + did + "\"}";
            Set<String> cands = candidateTokens();

            if (cands.isEmpty()) {
                log("没有任何可用凭据，放弃");
                toast("九号签到：没抓到凭据");
                return;
            }

            List<String> rawList = new ArrayList<String>();
            List<String> bearerList = new ArrayList<String>();
            for (String c : cands) {
                if (c.startsWith("Bearer ") || c.startsWith("bearer ")) {
                    bearerList.add(c);
                } else {
                    rawList.add(c);
                }
            }
            List<String> ordered = new ArrayList<String>();
            ordered.addAll(rawList);
            ordered.addAll(bearerList);
            log("候选 Authorization 共 " + ordered.size() + " 个（裸 " + rawList.size()
                    + " + Bearer " + bearerList.size() + "）：" + candidateSummary(ordered));

            int i = 0;
            for (String cand : ordered) {
                if (i++ >= 20) {
                    log("候选过多，只试前 20 个");
                    break;
                }
                if (i > 1) {

                    sleepQuiet(350);
                }
                Resp r = http("POST", URL_SIGN_V2, json, cand);
                log("v2 <- " + mask(cand) + " : HTTP " + r.httpCode + " | "
                        + explain(r.body) + " | " + clip(r.body, 400));
                if (respCode(r.body) == 0) {
                    report(true, r.body, cand);
                    return;
                }
                if (isAlreadySigned(r.body)) {

                    log("服务端判定今日已签到（原文见上），按已签到处理");
                    markOkToday();
                    toast("九号签到：今日已签到");
                    return;
                }
            }

            String first = ordered.get(0);

            sleepQuiet(350);
            Resp r1 = http("POST", URL_SIGN_V1, json, first);
            log("v1 <- " + mask(first) + " : HTTP " + r1.httpCode + " | "
                    + explain(r1.body) + " | " + clip(r1.body, 400));
            if (respCode(r1.body) == 0) {
                report(true, r1.body, first);
                return;
            }

            sleepQuiet(350);
            Resp r2 = http("POST", GW_H5 + "/portal/api/user-sign/v2/sign", json, first);
            log("h5api <- " + mask(first) + " : HTTP " + r2.httpCode + " | "
                    + explain(r2.body) + " | " + clip(r2.body, 400));
            if (respCode(r2.body) == 0) {
                report(true, r2.body, first);
                return;
            }

            report(false, r2.body, first);
        }

        private void report(boolean ok, String body, String used) {
            if (ok) {
                int days = deepInt(body, "consecutiveDays", -1);

                String extra = (days > 0 ? "，连续 " + days + " 天" : "") + rewardSummary(body);
                log("签到成功" + extra + "，使用凭据 " + mask(used));
                markOkToday();
                toast("九号签到成功" + extra);
            } else {
                log("签到失败，未使用凭据 " + mask(used) + " 成功。请把本日志发给开发者。");
                log("失败原因判读：" + explain(body));
                log("（对照：接口路径本身是存在的——已用无效 token 在线上实测过，"
                        + "写错路径会返回 404 Not Found，而真实路径返回 code 1/2 的业务错误）");
                if (body != null && body.startsWith("EXC ")) {
                    log("提示：请求根本没发出去（异常见上）。若是 SSL 相关，说明宿主对网关做了"
                            + "额外信任限制，需要改为复用 app 自己的网络栈。");
                }
                toast("九号签到失败，详见 LSPosed 日志");
            }
        }
    }

    interface Sink {
        void put(String v);
    }

    static Set<String> candidateTokens() {
        Set<String> out = new LinkedHashSet<String>();
        addTok(out, gwAuthHeader);
        addTok(out, authHeader);
        addTok(out, passportToken);
        addTok(out, rnToken);
        addTok(out, token);
        addJwtCandidates(out, jwtWhole);
        addJwtCandidates(out, jwtBase);
        addJwtCandidates(out, webUrl);
        return out;
    }

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

    static String today() {
        return new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date());
    }

    static File okFile() {
        Context c = appCtx;
        if (c == null) {
            return null;
        }
        File dir = c.getExternalFilesDir(null);
        if (dir == null) {
            dir = c.getFilesDir();
        }
        if (dir == null) {
            return null;
        }
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return new File(dir, "ninebot-sign.ok");
    }

    static boolean okToday() {
        try {
            File f = okFile();
            if (f == null || !f.exists()) {
                return false;
            }
            byte[] b = new byte[(int) f.length()];
            InputStream in = new java.io.FileInputStream(f);
            int off = 0;
            while (off < b.length) {
                int r = in.read(b, off, b.length - off);
                if (r <= 0) {
                    break;
                }
                off += r;
            }
            in.close();
            return new String(b, 0, off, "UTF-8").trim().equals(today());
        } catch (Throwable t) {
            return false;
        }
    }

    static void markOkToday() {
        try {
            File f = okFile();
            if (f == null) {
                return;
            }
            FileOutputStream fos = new FileOutputStream(f, false);
            fos.write(today().getBytes("UTF-8"));
            fos.close();
        } catch (Throwable t) {
        }
    }

    private void hookImageDiag(final XC_LoadPackage.LoadPackageParam lp) {

        try {
            Class<?> rb = XposedHelpers.findClass("com.bumptech.glide.RequestBuilder", lp.classLoader);
            XposedBridge.hookAllMethods(rb, "load", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        if (p.args == null || p.args.length != 1 || !(p.args[0] instanceof String)) {
                            return;
                        }
                        String s = (String) p.args[0];
                        if (!isVehicleImage(s)) {
                            return;
                        }
                        if (!vehImgEnabled()) {
                            img("glide(车辆图·替换未开启)", s, null);
                            return;
                        }
                        if (vehImgPath == null || vehImgPath.length() == 0) {
                            img("glide(车辆图·还没有可用的图)", s, null);
                            return;
                        }
                        File f = new File(vehImgPath);
                        if (!f.exists() || f.length() <= 0L) {
                            img("glide(车辆图·文件不存在 " + vehImgPath + ")", s, null);
                            return;
                        }

                        p.args[0] = "file://" + vehImgPath;
                        img("glide(车辆图·已替换)", s + "  ->  file://" + vehImgPath, null);
                    } catch (Throwable t) {
                        log("车辆图替换失败: " + t);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    img("glide", p.args != null && p.args.length > 0 ? p.args[0] : null, null);
                }
            });
            note("ImageDiag: Glide RequestBuilder#load 已挂");
        } catch (Throwable t) {
            log("ImageDiag: hook Glide 失败 " + t);
        }

        String[] drawee = new String[]{
                "com.facebook.drawee.view.SimpleDraweeView",
                "com.facebook.drawee.view.DraweeView"};
        for (final String cls : drawee) {
            try {
                Class<?> c = XposedHelpers.findClass(cls, lp.classLoader);
                XposedBridge.hookAllMethods(c, "setImageURI", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        img("drawee", p.args != null && p.args.length > 0 ? p.args[0] : null,
                                p.thisObject);
                    }
                });
                note("ImageDiag: " + cls + "#setImageURI 已挂");
            } catch (Throwable t) {
                log("ImageDiag: hook " + cls + " 失败 " + t);
            }
        }

        try {
            Class<?> rv = XposedHelpers.findClass(
                    "com.facebook.react.views.image.ReactImageView", lp.classLoader);
            XposedBridge.hookAllMethods(rv, "setSource", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    img("rn", p.args != null && p.args.length > 0 ? p.args[0] : null, p.thisObject);
                }
            });
            note("ImageDiag: ReactImageView#setSource 已挂");
        } catch (Throwable t) {
            log("ImageDiag: hook ReactImageView 失败 " + t);
        }

        try {
            XposedBridge.hookAllMethods(ImageView.class, "setImageResource", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    int id = (p.args != null && p.args.length > 0 && p.args[0] instanceof Integer)
                            ? (Integer) p.args[0] : 0;
                    img("setImageResource", resName(id), p.thisObject);
                }
            });
            XposedBridge.hookAllMethods(ImageView.class, "setImageBitmap", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    img("setImageBitmap", p.args != null && p.args.length > 0 ? p.args[0] : null,
                            p.thisObject);
                }
            });
            XposedBridge.hookAllMethods(ImageView.class, "setImageDrawable", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    img("setImageDrawable", p.args != null && p.args.length > 0 ? p.args[0] : null,
                            p.thisObject);
                }
            });
            note("ImageDiag: ImageView#setImageResource/setImageBitmap/setImageDrawable 已挂");
        } catch (Throwable t) {
            log("ImageDiag: hook ImageView 失败 " + t);
        }
    }

    static boolean isVehicleImage(String s) {
        if (s == null || s.indexOf(VEH_IMG_KEY) < 0) {
            return false;
        }
        return s.indexOf("/category/") >= 0
                || s.indexOf(".png") >= 0
                || s.indexOf(".webp") >= 0
                || s.indexOf(".jpg") >= 0;
    }

    static boolean vehImgEnabled() {
        long now = System.currentTimeMillis();
        if (now - vehConfAt > 5000L) {
            vehConfAt = now;
            boolean on = false;
            String path = null;
            String stamp = null;
            try {

                Map<String, String> c = conf();
                on = confOn("vehicleImage", false);
                path = c.get("vehicleImagePath");
                stamp = c.get("vehicleImageStamp");
                File dir = dataDir();
                if (dir != null && new File(dir, "vehicle-image-off").exists()) {
                    on = false;
                }
                if (path == null || path.length() == 0) {
                    path = dir == null ? null : new File(dir, "vehicle.png").getAbsolutePath();
                }
            } catch (Throwable t) {
                log("读 vehicle 配置失败: " + t);
            }

            String src = null;
            if (on) {
                src = (stamp != null && stamp.length() > 0) ? vehicleFromProvider(stamp) : null;
                if (src == null) {
                    src = vehicleFromManual(path);
                }
            }
            String key = (stamp == null ? "" : stamp) + "|" + path + "|" + on;
            if (!key.equals(vehSrcPath)) {
                vehSrcPath = key;
                log("车辆图配置：开关=" + (on ? "开" : "关")
                        + "  用图=" + (src == null ? "(没有)" : src));
            }
            vehImgOn = on;
            vehImgPath = src;
        }
        return vehImgOn && vehImgPath != null && vehImgPath.length() > 0;
    }

    static String vehicleFromProvider(String stamp) {
        try {
            Context ctx = appCtx;
            if (ctx == null) {
                return null;
            }
            File dir = ctx.getFilesDir();
            if (dir == null) {
                return null;
            }
            File dst = new File(dir, "vehicle-" + stamp.replace(':', '-').replace('/', '-') + ".png");
            if (dst.exists() && dst.length() > 0L) {
                return dst.getAbsolutePath();
            }
            java.io.InputStream in = ctx.getContentResolver().openInputStream(
                    android.net.Uri.parse("content://com.ninebotsign.lsp.conf/"
                            + ConfProvider.VEHICLE_SEGMENT));
            if (in == null) {
                log("车辆图：设置界面里还没有图（先去设置界面点「从相册选择图片」）");
                return null;
            }
            FileOutputStream out = new FileOutputStream(dst, false);
            byte[] buf = new byte[8192];
            int n;
            long total = 0L;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                total += n;
            }
            out.flush();
            out.close();
            in.close();
            if (total <= 0L) {
                dst.delete();
                return null;
            }
            log("车辆图：从设置界面取到 " + total + " 字节 → " + dst.getName());
            File[] olds = dir.listFiles();
            if (olds != null) {
                for (int i = 0; i < olds.length; i++) {
                    String nm = olds[i].getName();
                    if (nm.startsWith("vehicle-") && nm.endsWith(".png") && !olds[i].equals(dst)) {
                        olds[i].delete();
                    }
                }
            }
            return dst.getAbsolutePath();
        } catch (Throwable t) {
            log("车辆图：从设置界面取图失败 " + t);
            return null;
        }
    }

    static String vehicleFromManual(String src) {
        try {
            Context ctx = appCtx;
            if (ctx == null || src == null || src.length() == 0) {
                return null;
            }
            File s = new File(src);
            if (!s.exists() || s.length() <= 0L) {
                return null;
            }
            File dir = ctx.getFilesDir();
            if (dir == null) {
                return null;
            }
            File dst = new File(dir,
                    "vehicle-manual-" + s.length() + "-" + s.lastModified() + ".png");
            if (dst.exists() && dst.length() > 0L) {
                return dst.getAbsolutePath();
            }
            java.io.FileInputStream fi = new java.io.FileInputStream(s);
            FileOutputStream fo = new FileOutputStream(dst, false);
            byte[] buf = new byte[8192];
            int n;
            while ((n = fi.read(buf)) > 0) {
                fo.write(buf, 0, n);
            }
            fo.flush();
            fo.close();
            fi.close();
            log("车辆图：复制手工图片 → " + dst.getName());
            return dst.getAbsolutePath();
        } catch (Throwable t) {
            log("车辆图：复制手工图片失败 " + t);
            return null;
        }
    }

    static String effectiveVehPath(String src) {
        try {
            File f = new File(src);
            if (f.length() <= 0L || !f.exists()) {
                return src;
            }
            long stamp = f.length() * 1000003L + f.lastModified();
            File dir = f.getParentFile();
            if (dir == null) {
                return src;
            }
            File out = new File(dir, "vehicle-cache-" + stamp + ".png");
            if (!out.exists() || out.length() <= 0L) {
                copyFile(f, out);
                File[] olds = dir.listFiles();
                if (olds != null) {
                    for (int i = 0; i < olds.length; i++) {
                        String n = olds[i].getName();
                        if (n.startsWith("vehicle-cache-") && !n.equals(out.getName())) {
                            olds[i].delete();
                        }
                    }
                }
                log("车辆图：源 " + f.getName() + "(" + f.length() + "B) → 副本 " + out.getName());
            }
            return out.getAbsolutePath();
        } catch (Throwable t) {
            log("车辆图副本失败: " + t);
            return src;
        }
    }

    static void copyFile(File in, File out) throws Throwable {
        InputStream is = new FileInputStream(in);
        OutputStream os = new FileOutputStream(out);
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) {
            os.write(buf, 0, n);
        }
        os.flush();
        os.close();
        is.close();
    }

    static File dataDir() {
        Context c = appCtx;
        if (c == null) {
            return null;
        }
        File d = c.getExternalFilesDir(null);
        if (d == null) {
            d = c.getFilesDir();
        }
        if (d != null && !d.exists()) {
            d.mkdirs();
        }
        return d;
    }

    static void img(String src, Object value, Object view) {
        if (seenImages.size() >= IMG_LOG_MAX) {
            return;
        }
        String v = describeImg(value);
        String vd = viewName(view);
        if (!seenImages.add(src + "|" + v + "|" + vd)) {
            return;
        }
        log("img " + src + " act=" + curActivity + " view=" + vd + " val=" + v);
        if (seenImages.size() == IMG_LOG_MAX) {
            log("img 诊断已达上限 " + IMG_LOG_MAX + " 条，后续不再记录");
        }
    }

    static String describeImg(Object o) {
        try {
            if (o == null) {
                return "null";
            }
            if (o instanceof String) {
                return trunc(String.valueOf(o), 300);
            }
            if (o instanceof android.net.Uri) {
                return "uri:" + trunc(String.valueOf(o), 300);
            }
            if (o instanceof byte[]) {
                return "bytes[" + ((byte[]) o).length + "]";
            }
            if (o instanceof Bitmap) {
                return "bitmap:" + ((Bitmap) o).getWidth() + "x" + ((Bitmap) o).getHeight();
            }
            if (o instanceof Drawable) {
                return "drawable:" + o.getClass().getSimpleName();
            }
            if (o instanceof Integer) {
                return "res:0x" + Integer.toHexString((Integer) o);
            }
            return o.getClass().getSimpleName() + ":" + trunc(String.valueOf(o), 300);
        } catch (Throwable t) {
            return "?";
        }
    }

    static String resName(int id) {
        if (id == 0) {
            return "0";
        }
        Context c = appCtx;
        if (c != null) {
            try {
                return c.getResources().getResourcePackageName(id) + ":drawable/"
                        + c.getResources().getResourceEntryName(id)
                        + "(0x" + Integer.toHexString(id) + ")";
            } catch (Throwable t) {
            }
        }
        return "res:0x" + Integer.toHexString(id);
    }

    static String viewName(Object view) {
        if (!(view instanceof View)) {
            return "-";
        }
        View v = (View) view;
        String cls = v.getClass().getSimpleName();
        if (cls == null || cls.length() == 0) {
            cls = v.getClass().getName();
        }
        int id = v.getId();
        if (id == 0 || id == View.NO_ID) {
            return cls + "#noid";
        }
        String n;
        try {
            n = v.getResources().getResourceEntryName(id);
        } catch (Throwable t) {
            n = "0x" + Integer.toHexString(id);
        }
        return cls + "#" + n;
    }

    static String trunc(String s, int max) {
        if (s == null) {
            return "null";
        }
        String o = s.replace('\n', ' ').replace('\r', ' ');
        return o.length() <= max ? o : o.substring(0, max) + "...";
    }

    static final String PREF = "ninebot_sign";

    static final String CONF_HEADER = "# 由「九号自动签到」设置界面生成；想手动改配置就先删掉这一行";
    static volatile long uiConfAt = 0L;

    static volatile long confAt = 0L;
    static volatile Map<String, String> confMap = null;

    static volatile boolean signOffLogged = false;

    static Map<String, String> conf() {
        long now = System.currentTimeMillis();
        Map<String, String> cached = confMap;
        if (cached != null && now - confAt <= 5000L) {
            return cached;
        }
        Map<String, String> out = new LinkedHashMap<String, String>();

        try {
            File dir = dataDir();
            if (dir != null) {
                File f = new File(dir, "ninebot-sign.conf");
                if (f.exists()) {
                    BufferedReader r = new BufferedReader(
                            new InputStreamReader(new FileInputStream(f), "UTF-8"));
                    String ln;
                    while ((ln = r.readLine()) != null) {
                        putLine(out, ln);
                    }
                    r.close();
                }
            }
        } catch (Throwable t) {
            log("读配置失败: " + t);
        }

        Map<String, String> ui = uiConfMap();
        if (ui != null) {
            out.putAll(ui);
        }
        confMap = out;
        confAt = now;
        return out;
    }

    static void putLine(Map<String, String> out, String ln) {
        ln = ln == null ? "" : ln.trim();
        if (ln.length() == 0 || ln.charAt(0) == '#') {
            return;
        }
        int e = ln.indexOf('=');
        if (e > 0) {
            out.put(ln.substring(0, e).trim(), ln.substring(e + 1).trim());
        }
    }

    static boolean confOn(String key, boolean def) {
        String v = conf().get(key);
        if (v == null || v.length() == 0) {
            return def;
        }
        if ("1".equals(v) || "true".equalsIgnoreCase(v) || "on".equalsIgnoreCase(v)) {
            return true;
        }
        if ("0".equals(v) || "false".equalsIgnoreCase(v) || "off".equalsIgnoreCase(v)) {
            return false;
        }
        return def;
    }

    static boolean uiOn(String v) {
        return ConfText.on(v);
    }

    static String uiNz(String v) {
        return ConfText.nz(v);
    }

    static String uiConfText(Map<String, String> m) {
        return ConfText.build(m);
    }

    static Map<String, String> uiPrefs() {
        try {
            de.robv.android.xposed.XSharedPreferences p =
                    new de.robv.android.xposed.XSharedPreferences("com.ninebotsign.lsp", PREF);
            p.reload();
            if (!"1".equals(p.getString("ui", ""))) {
                return null;
            }
            String[] keys = {"signEnabled", "vehicleImage", "vehicleImagePath",
                    "fakeExpiry"};
            Map<String, String> m = new java.util.LinkedHashMap<String, String>();
            for (int i = 0; i < keys.length; i++) {
                String v = p.getString(keys[i], "");
                m.put(keys[i], v == null ? "" : v);
            }
            return m;
        } catch (Throwable t) {
            log("设置界面：读取失败 " + t);
            return null;
        }
    }

    static Map<String, String> parseConfText(String text) {
        Map<String, String> out = new LinkedHashMap<String, String>();
        if (text == null) {
            return out;
        }
        String[] lines = text.split("\n");
        for (int i = 0; i < lines.length; i++) {
            putLine(out, lines[i]);
        }
        return out;
    }

    static Map<String, String> uiConfMap() {
        String text = providerConfText();
        if (text != null) {
            return parseConfText(text);
        }
        return uiPrefs();
    }

    static String providerConfText() {

        if (System.currentTimeMillis() < provSkipUntil) {
            return null;
        }
        try {
            android.content.Context ctx = appCtx;
            if (ctx == null) {
                return null;
            }
            android.os.Bundle b = ctx.getContentResolver().call(
                    android.net.Uri.parse("content://com.ninebotsign.lsp.conf"), "conf", null, null);
            if (b == null) {
                return null;
            }
            String s = b.getString("conf");
            return (s == null || s.length() == 0) ? null : s;
        } catch (Throwable t) {
            if (++provFails >= 3) {
                provSkipUntil = System.currentTimeMillis() + 600000L;
                log("内容提供者通道被包可见性挡住，改用 XSharedPreferences：" + t);
            } else {
                logUiWarn("设置界面：内容提供者读不到 " + t);
            }
            return null;
        }
    }

    static volatile int provFails = 0;
    static volatile long provSkipUntil = 0L;

    static volatile long uiWarnAt = 0L;

    static void logUiWarn(String s) {
        long now = System.currentTimeMillis();
        if (now - uiWarnAt < 60000L) {
            return;
        }
        uiWarnAt = now;
        log(s);
    }

    static void syncUiConf() {
        try {
            long now = System.currentTimeMillis();
            if (now - uiConfAt < 5000L) {
                return;
            }
            uiConfAt = now;
            Map<String, String> m = uiPrefs();
            String text = m == null ? null : uiConfText(m);
            boolean viaProvider = false;
            if (text == null) {
                text = providerConfText();
                viaProvider = text != null;
                if (text == null) {
                    logUiWarn("设置界面：两条通道都没读到界面设置（SharedPreferences 与内容提供者），配置保持原样");
                    return;
                }
            }
            File dir = dataDir();
            if (dir == null) {
                return;
            }
            File f = new File(dir, "ninebot-sign.conf");
            if (text.equals(uiReadText(f))) {
                return;
            }

            if (f.exists() && !f.canWrite()) {
                boolean gone = f.delete();
                log("配置：旧的 ninebot-sign.conf 不可写（" + (gone ? "已删除重建" : "删不掉，仍试覆盖") + "）");
            }
            FileOutputStream fos = new FileOutputStream(f, false);
            fos.write(text.getBytes("UTF-8"));
            fos.close();
            vehConfAt = 0L;
            confAt = 0L;
            log("设置界面：已写入 ninebot-sign.conf（" + text.length() + " 字节，来源="
                    + (viaProvider ? "内容提供者" : "SharedPreferences")
                    + (text.contains("signEnabled=0") ? "，签到=关" : "，签到=开")
                    + (text.contains("vehicleImage=1") ? "，车图=开" : "，车图=关") + "）");
        } catch (Throwable t) {
            logUiWarn("设置界面：同步失败 " + t);
        }
    }

    static String uiReadText(File f) {
        try {
            if (f == null || !f.exists()) {
                return null;
            }
            byte[] b = new byte[(int) f.length()];
            FileInputStream in = new FileInputStream(f);
            int off = 0;
            while (off < b.length) {
                int r = in.read(b, off, b.length - off);
                if (r <= 0) {
                    break;
                }
                off += r;
            }
            in.close();
            return new String(b, 0, off, "UTF-8");
        } catch (Throwable t) {
            return null;
        }
    }

    static String jsonStr(String body, String key) {
        if (body == null) {
            return null;
        }
        String needle = "\"" + key + "\"";
        int at = body.indexOf(needle);
        while (at >= 0) {
            int c = body.indexOf(':', at + needle.length());
            if (c < 0) {
                return null;
            }
            int i = c + 1;
            while (i < body.length() && Character.isWhitespace(body.charAt(i))) {
                i++;
            }
            if (i < body.length() && body.charAt(i) == '"') {
                StringBuilder sb = new StringBuilder();
                int j = i + 1;
                while (j < body.length()) {
                    char ch = body.charAt(j);
                    if (ch == '\\' && j + 1 < body.length()) {
                        char n = body.charAt(j + 1);
                        if (n == 'n') {
                            sb.append('\n');
                        } else if (n == 't') {
                            sb.append('\t');
                        } else if (n == 'r') {
                            sb.append('\r');
                        } else {
                            sb.append(n);
                        }
                        j += 2;
                        continue;
                    }
                    if (ch == '"') {
                        return sb.toString();
                    }
                    sb.append(ch);
                    j++;
                }
                return null;
            }
            at = body.indexOf(needle, at + needle.length());
        }
        return null;
    }

    static int jsonInt(String body, String key, int def) {
        if (body == null) {
            return def;
        }
        String needle = "\"" + key + "\"";
        int at = body.indexOf(needle);
        while (at >= 0) {
            int c = body.indexOf(':', at + needle.length());
            if (c < 0) {
                return def;
            }
            int i = c + 1;
            while (i < body.length() && Character.isWhitespace(body.charAt(i))) {
                i++;
            }
            int s = i;
            if (i < body.length() && (body.charAt(i) == '-' || body.charAt(i) == '+')) {
                i++;
            }
            int d = i;
            while (d < body.length() && Character.isDigit(body.charAt(d))) {
                d++;
            }
            if (d > i) {
                try {
                    return Integer.parseInt(body.substring(s, d));
                } catch (Throwable t) {
                    return def;
                }
            }
            at = body.indexOf(needle, at + needle.length());
        }
        return def;
    }

    static void hook(XC_LoadPackage.LoadPackageParam lp, String cls, String method,
                     XC_MethodHook cb) {
        try {
            Class<?> c = XposedHelpers.findClass(cls, lp.classLoader);
            XposedBridge.hookAllMethods(c, method, cb);
            hookLog.add("OK   " + cls + "#" + method);
            log("hook 成功 " + cls + "#" + method);
        } catch (Throwable t) {
            hookLog.add("FAIL " + cls + "#" + method + " -> " + t);
            log("hook 失败 " + cls + "#" + method + " -> " + t);
        }
    }

    static int cfgDumpCount = 0;

    private void hookConfigDump(final XC_LoadPackage.LoadPackageParam lp) {
        hook(lp, "com.google.gson.Gson", "fromJson",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Object a0 = p.args != null && p.args.length > 0 ? p.args[0] : null;
                            if (!(a0 instanceof String)) {
                                return;
                            }
                            String s = (String) a0;
                            if (s.length() < 200) {
                                return;
                            }
                            if (s.indexOf("device_ui") < 0 && s.indexOf("commandList") < 0
                                    && s.indexOf("GearEnergy") < 0 && s.indexOf("energy") < 0
                                    && s.indexOf("items") < 0 && s.indexOf("features") < 0) {
                                return;
                            }
                            String cls = p.args.length > 1 && p.args[1] != null
                                    ? String.valueOf(p.args[1]) : "?";
                            dumpCfgText("gson_" + cls, s);
                        } catch (Throwable t) {
                        }
                    }
                });
        hook(lp, "cn.ninebot.library.bluetooth.dynamic.DynamicConfigManager", "decryptNbFile",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        try {
                            log("动态配置：要解密 "
                                    + (p.args != null && p.args.length > 1 ? p.args[1] : "?"));
                        } catch (Throwable t) {
                        }
                    }
                });
    }

    static void dumpCfgText(String tag, String text) {
        try {
            Context c = appCtx;
            if (c == null || cfgDumpCount > 400) {
                return;
            }
            cfgDumpCount++;
            File dir = new File(c.getExternalFilesDir(null), "dyncfg_out");
            dir.mkdirs();
            String safe = tag.replaceAll("[^A-Za-z0-9_.$-]", "_");
            if (safe.length() > 90) {
                safe = safe.substring(safe.length() - 90);
            }
            File f = new File(dir, cfgDumpCount + "_" + safe + ".txt");
            java.io.FileOutputStream out = new java.io.FileOutputStream(f, false);
            out.write(text.getBytes("UTF-8"));
            out.close();
            log("动态配置：抄出 " + f.getName() + " " + text.length() + " 字符");
        } catch (Throwable t) {
            log("动态配置：抄出失败 " + t);
        }
    }

    static final java.util.Set<String> cmdNames = new java.util.LinkedHashSet<String>();
    static final java.util.Set<String> cmdFrames = new java.util.LinkedHashSet<String>();
    static int cmdLogCount = 0;
    static final int CMD_LOG_MAX = 600;

    private void hookVehicleCmds(final XC_LoadPackage.LoadPackageParam lp) {
        hostCl = lp.classLoader;

        hook(lp, "cn.ninebot.library.bluetooth.dynamic.DynamicCommandFactory", "getCommandConfig",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Object cfg = p.getResult();
                            if (cfg == null || p.args == null || p.args.length == 0) {
                                return;
                            }
                            String name = String.valueOf(p.args[0]);
                            if (!cmdNames.add(name) || cmdNames.size() > 200) {
                                return;
                            }
                            log("车控：命令表 name=" + name
                                    + " s_cmd=" + fieldInt(cfg, "s_cmd")
                                    + " s_index=" + fieldInt(cfg, "s_index")
                                    + " s_data=" + fieldStr(cfg, "s_data")
                                    + " r_cmd=" + fieldInt(cfg, "r_cmd")
                                    + " r_index=" + fieldInt(cfg, "r_index")
                                    + " key=" + fieldStr(cfg, "dataValueKey")
                                    + " module=" + fieldStr(cfg, "module")
                                    + " retry=" + fieldInt(cfg, "retryTimes")
                                    + " timeout=" + fieldInt(cfg, "timeout"));

                            dumpCommandMapOnce(p.thisObject);
                        } catch (Throwable t) {
                        }
                    }
                });

        hook(lp, "cn.ninebot.library.nbbluetooth.command.CommandExecutorImpl", "execute",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        try {
                            if (p.args != null && p.args.length > 0) {
                                cmdDump("发送", p.args[0]);
                            }
                        } catch (Throwable t) {
                        }
                    }
                });

        hook(lp, "cn.ninebot.library.nbbluetooth.NbBluetoothDevice", "onCharacteristicChanged",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            if (p.args == null || p.args.length == 0 || p.args[0] == null) {
                                return;
                            }
                            Object v = XposedHelpers.callMethod(p.args[0], "getValue");
                            if (v instanceof byte[]) {
                                cmdFrame("上行", (byte[]) v);
                            }
                        } catch (Throwable t) {
                        }
                    }
                });

        hook(lp, "cn.ninebot.library.bluetooth.dynamic.viewHolder.BtDynamicViewHolder", "sendCommand",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        dumpNameArgs("功能发命令", p.args);
                    }
                });
        hook(lp, "cn.ninebot.library.bluetooth.dynamic.viewHolder.BtDynamicViewHolder", "sendCommandImpl",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        dumpNameArgs("功能发命令 impl", p.args);
                    }
                });

        hook(lp, "cn.ninebot.library.bluetooth.dynamic.DynamicCommandFactory", "createCommand",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        dumpNameArgs("建命令", p.args);
                    }
                });

        hook(lp, "cn.ninebot.library.bluetooth.dynamic.DynamicDevice", "createPreparatoryProcessor",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            if (p.getResult() != null && !protoLogged) {
                                protoLogged = true;
                                log("车控：本次握手处理器=" + p.getResult().getClass().getName());
                            }
                        } catch (Throwable t) {
                        }
                    }
                });

        try {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(9000L);
                    } catch (Throwable t) {
                    }
                    dumpDynamicConfigOnce();
                }
            }).start();
        } catch (Throwable t) {
        }

    }

    static boolean dynCfgDumped = false;

    static void dumpDynamicConfigOnce() {
        if (dynCfgDumped) {
            return;
        }
        dynCfgDumped = true;
        try {
            Context c = appCtx;
            if (c == null) {
                log("动态配置：上下文还没好，跳过");
                return;
            }
            File src = new File(c.getFilesDir(), "dynamic_config_new");
            File dst = new File(c.getExternalFilesDir(null), "dyncfg");
            int[] cnt = new int[] { 0 };
            long[] bytes = new long[] { 0 };
            File root = c.getFilesDir().getParentFile();
            log("动态配置：扫描 " + root);
            copyTree(src, dst, 0, cnt, bytes);
            copyTree(new File(root, "shared_prefs"), new File(dst, "_shared_prefs"), 0, cnt, bytes);
            copyTree(new File(root, "databases"), new File(dst, "_databases"), 0, cnt, bytes);
            copyTree(c.getFilesDir(), new File(dst, "_files"), 0, cnt, bytes);
            log("动态配置：已导出 " + cnt[0] + " 个文件 / " + bytes[0] + " 字节 → " + dst);
        } catch (Throwable t) {
            log("动态配置：导出失败 " + t);
        }
    }

    static int dynCfgLogs = 0;

    static void copyTree(File src, File dst, int depth, int[] cnt, long[] bytes) {
        if (src == null || !src.exists() || depth > 3) {
            return;
        }
        if (src.isDirectory()) {
            File[] kids = src.listFiles();
            if (kids == null) {
                return;
            }
            for (int i = 0; i < kids.length; i++) {
                copyTree(kids[i], new File(dst, kids[i].getName()), depth + 1, cnt, bytes);
            }
            return;
        }
        long len = src.length();
        if (dynCfgLogs < 90) {
            dynCfgLogs++;
            log("动态配置：文件 " + src.getAbsolutePath() + " " + len + "B");
        }
        if (len <= 0 || len > 1024L * 1024L || bytes[0] > 24L * 1024 * 1024) {
            return;
        }
        String n = src.getName().toLowerCase();
        if (n.endsWith(".log") || n.endsWith(".mp4") || n.endsWith(".apk") || n.endsWith(".so")
                || n.endsWith(".dex") || n.endsWith(".ttf") || n.endsWith(".mp3")) {
            return;
        }
        try {
            if (dst.getParentFile() != null) {
                dst.getParentFile().mkdirs();
            }
            java.io.FileInputStream in = new java.io.FileInputStream(src);
            java.io.FileOutputStream out = new java.io.FileOutputStream(dst);
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) > 0) {
                out.write(buf, 0, r);
            }
            in.close();
            out.close();
            cnt[0]++;
            bytes[0] += len;
        } catch (Throwable t) {
        }
    }

    static boolean protoLogged = false;
    static boolean cmdMapDumped = false;

    static void dumpCommandMapOnce(Object factory) {
        if (cmdMapDumped || factory == null) {
            return;
        }
        cmdMapDumped = true;
        try {
            Object map = XposedHelpers.getObjectField(factory, "commandConfigMap");
            if (!(map instanceof java.util.Map)) {
                log("车控：整表 dump 失败，字段=" + (map == null ? "null" : map.getClass().getName()));
                return;
            }
            java.util.Map<?, ?> m = (java.util.Map<?, ?>) map;
            log("车控：整表 dump 开始 条目=" + m.size());
            int n = 0;
            for (java.util.Map.Entry<?, ?> e : m.entrySet()) {
                if (n++ > 700) {
                    log("车控：整表 dump 截断到 700 条");
                    break;
                }
                Object cfg = e.getValue();
                log("车控：整表 name=" + e.getKey()
                        + " s_cmd=" + fieldInt(cfg, "s_cmd")
                        + " s_index=" + fieldInt(cfg, "s_index")
                        + " s_data=" + fieldStr(cfg, "s_data")
                        + " r_cmd=" + fieldInt(cfg, "r_cmd")
                        + " r_index=" + fieldInt(cfg, "r_index")
                        + " key=" + fieldStr(cfg, "dataValueKey")
                        + " module=" + fieldStr(cfg, "module"));
            }
            log("车控：整表 dump 结束");
        } catch (Throwable t) {
            log("车控：整表 dump 异常 " + t);
        }
    }

    static void dumpNameArgs(String tag, Object[] args) {
        if (args == null || args.length == 0) {
            return;
        }
        try {
            Object a0 = args[0];
            Object a1 = args.length > 1 ? args[1] : null;
            String name = a0 == null ? "null" : String.valueOf(a0);
            String val;
            if (a1 instanceof byte[]) {
                val = "bytes[" + ((byte[]) a1).length + "] " + hex((byte[]) a1);
            } else {
                val = a1 == null ? "null"
                        : (String.valueOf(a1) + " (" + a1.getClass().getName() + ")");
            }
            String key = tag + "/" + name + "/" + val;
            if (!cmdFrames.add(key)) {
                return;
            }
            if (cmdLogCount++ > CMD_LOG_MAX) {
                return;
            }
            log("车控：" + tag + " name=" + name + " val=" + val);
        } catch (Throwable t) {
        }
    }

    static void cmdDump(String tag, Object cmd) {
        if (cmd == null) {
            return;
        }
        try {
            int c = XposedHelpers.getByteField(cmd, "cmd") & 0xFF;
            Object idx = null;
            Object si = XposedHelpers.getObjectField(cmd, "startIndex");
            if (si != null) {
                try {
                    idx = XposedHelpers.callMethod(si, "id");
                } catch (Throwable t) {
                }
                if (idx == null) {
                    try {
                        idx = XposedHelpers.callMethod(si, "index");
                    } catch (Throwable t) {
                    }
                }
            }
            if (idx == null) {
                try {
                    idx = XposedHelpers.getObjectField(cmd, "indexValue");
                } catch (Throwable t) {
                }
            }
            Object tgt = null;
            try {
                tgt = XposedHelpers.getObjectField(cmd, "targetId");
            } catch (Throwable t) {
            }
            byte[] data = null;
            try {
                data = (byte[]) XposedHelpers.getObjectField(cmd, "data");
            } catch (Throwable t) {
            }
            String key = "c/" + c + "/" + idx + "/" + hex(data);
            if (!cmdFrames.add(key)) {
                return;
            }
            if (cmdLogCount++ > CMD_LOG_MAX) {
                return;
            }
            log("车控：" + tag + " cmd=0x" + Integer.toHexString(c)
                    + " index=" + idx
                    + " target=" + tgt
                    + " len=" + (data == null ? 0 : data.length)
                    + " data=" + hex(data));
        } catch (Throwable t) {
            log("车控：解析 Command 失败 " + t);
        }
    }

    static void cmdFrame(String tag, byte[] v) {
        if (v == null || v.length == 0) {
            return;
        }
        if (!cmdFrames.add("f/" + hex(v))) {
            return;
        }
        if (cmdLogCount++ > CMD_LOG_MAX) {
            return;
        }
        log("车控：" + tag + " " + v.length + "B " + hex(v));
    }

    static String hex(byte[] b) {
        if (b == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(b.length * 3);
        int n = Math.min(b.length, 64);
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            int x = b[i] & 0xFF;
            if (x < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(x));
        }
        if (b.length > n) {
            sb.append(" …(共").append(b.length).append("B)");
        }
        return sb.toString();
    }

    static int fieldInt(Object o, String f) {
        try {
            return XposedHelpers.getIntField(o, f);
        } catch (Throwable t) {
        }
        try {
            return XposedHelpers.getByteField(o, f) & 0xFF;
        } catch (Throwable t) {
        }
        try {
            Object v = XposedHelpers.getObjectField(o, f);
            return v == null ? -1 : Integer.parseInt(String.valueOf(v));
        } catch (Throwable t) {
            return -1;
        }
    }

    static String fieldStr(Object o, String f) {
        try {
            Object v = XposedHelpers.getObjectField(o, f);
            return v == null ? "null" : String.valueOf(v);
        } catch (Throwable t) {
            return "-";
        }
    }

    static class Arg0Saver extends XC_MethodHook {
        private final Sink sink;
        private final String name;

        Arg0Saver(Sink s, String n) {
            this.sink = s;
            this.name = n;
        }

        @Override
        protected void afterHookedMethod(MethodHookParam p) {
            try {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof String) {
                    String v = (String) p.args[0];
                    sink.put(v);
                    log("捕获 " + name + "=" + mask(v));
                }
            } catch (Throwable t) {
            }
            maybeSign();
        }
    }

    static ClassLoader hostCl;

    static Class<?> hostClass(String name) throws ClassNotFoundException {
        ClassLoader cl = hostCl;
        if (cl == null) {
            throw new ClassNotFoundException(name + "（宿主 ClassLoader 还没拿到）");
        }
        return Class.forName(name, false, cl);
    }

    static boolean fakeExpiryOn() {
        try {
            String v = conf().get("fakeExpiry");
            return v != null && ConfText.on(v);
        } catch (Throwable t) {
            return false;
        }
    }

    static final java.util.regex.Pattern EXPIRE_YEAR = java.util.regex.Pattern.compile(
            "(?<![0-9])(?:19|20)[0-9]{2}([\\s]*)([.\\-/])([\\s]*)[0-9]{1,2}([\\s]*)([.\\-/])([\\s]*)[0-9]{1,2}");

    static String expiryText(String s) {
        if (s == null || s.length() == 0 || s.indexOf("有效期") < 0) {
            return null;
        }
        java.util.regex.Matcher m = EXPIRE_YEAR.matcher(s);
        if (!m.find()) {
            return null;
        }
        String sep = m.group(2);
        return m.replaceFirst("9999" + sep + "12" + sep + "31");
    }

    static final Set<String> expirySeen = new LinkedHashSet<String>();

    private void hookFakeExpiry(final XC_LoadPackage.LoadPackageParam lp) {
        try {
            XposedBridge.hookAllMethods(android.widget.TextView.class, "setText", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    if (!fakeExpiryOn()) {
                        return;
                    }
                    try {
                        Object o = p.thisObject;
                        if (!(o instanceof android.widget.TextView)) {
                            return;
                        }
                        CharSequence cs = ((android.widget.TextView) o).getText();
                        if (cs == null) {
                            return;
                        }
                        String fixed = expiryText(cs.toString());
                        if (fixed == null) {
                            return;
                        }
                        ((android.widget.TextView) o).setText(fixed);
                        synchronized (expirySeen) {
                            if (expirySeen.size() < 8 && expirySeen.add(fixed)) {
                                log("界面文字：" + fixed);
                            }
                        }
                    } catch (Throwable t) {
                    }
                }
            });
            note("OK   android.widget.TextView#setText");
        } catch (Throwable t) {
            note("FAIL android.widget.TextView#setText -> " + t);
        }
    }

    static void note(String s) {
        hookLog.add(s);
    }

    static void log(String msg) {
        String line = TAG + msg;
        try {
            XposedBridge.log(line);
        } catch (Throwable t) {
        }

        try {
            android.util.Log.i("NinebotSign", msg);
        } catch (Throwable t) {
        }
        appendFile(msg);
    }

    static void appendFile(String msg) {
        Context c = appCtx;
        if (c == null) {
            return;
        }
        try {
            File dir = c.getExternalFilesDir(null);
            if (dir == null) {
                dir = c.getFilesDir();
            }
            if (dir == null) {
                return;
            }
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File f = new File(dir, "ninebot-sign.log");
            FileOutputStream fos = new FileOutputStream(f, true);
            String line = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(new Date())
                    + "  " + msg + "\n";
            fos.write(line.getBytes("UTF-8"));
            fos.close();
        } catch (Throwable t) {
        }
    }

    static void toast(final String msg) {
        final Context c = appCtx;
        if (c == null) {
            return;
        }
        try {
            new Handler(Looper.getMainLooper()).post(new Runnable() {
                public void run() {
                    try {
                        Toast.makeText(c, msg, Toast.LENGTH_LONG).show();
                    } catch (Throwable t) {
                    }
                }
            });
        } catch (Throwable t) {
        }
    }

    static String str(Object[] args, int i) {
        if (args == null || i >= args.length || args[i] == null) {
            return "null";
        }
        return String.valueOf(args[i]);
    }

    static String firstNonNull(String a, String b) {
        return a != null ? a : b;
    }

    static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (Throwable ignored) {
        }
    }

    static boolean isAlreadySigned(String body) {
        if (body == null) {
            return false;
        }
        String s = body.toLowerCase(Locale.US);
        return body.contains("已签到") || s.contains("already") || s.contains("repeat");
    }

    static String clip(String s, int n) {
        if (s == null) {
            return "null";
        }
        return s.length() <= n ? s : s.substring(0, n) + "...(+" + (s.length() - n) + ")";
    }

    static String mask(String s) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= 20) {
            return "***len=" + s.length();
        }
        return s.substring(0, 10) + "…" + s.substring(s.length() - 6) + " (len=" + s.length() + ")";
    }

    static String candidateSummary(Collection<String> cands) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (String c : cands) {
            if (n++ > 0) {
                sb.append(" | ");
            }
            sb.append(mask(c));
            if (n >= 12) {
                break;
            }
        }
        return sb.toString();
    }

}
