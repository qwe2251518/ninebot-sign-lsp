package com.ninebotsign.lsp;

import android.app.Application;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
        hookBgImage(lp);
        hookVehicleCmds(lp);
        hookWebDiag(lp);
        hookConsoleDiag(lp);
        hookFakeShare(lp.classLoader);
        hookAutoShareFlow(lp.classLoader);
        hookFakeExpiry(lp);
        hookAutoShare(lp);
        hookRnIntent(lp.classLoader);
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(new Runnable() {
            public void run() {
            }
        }, 12000);

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

    static boolean bgOn = false;
    static String bgPath = null;
    static String bgKey = null;
    static android.graphics.Bitmap bgBmp = null;

    static boolean bgImgEnabled() {
        try {
            if (!"1".equals(conf().get("bgImage"))) {
                return false;
            }
            String p = conf().get("bgImagePath");
            return p != null && p.length() > 0;
        } catch (Throwable t) {
            return false;
        }
    }

    static android.graphics.Bitmap bgBitmap() {
        try {
            if (bgBmp != null) {
                return bgBmp;
            }
            if (!bgImgEnabled()) {
                return null;
            }
            android.graphics.BitmapFactory.Options o = new android.graphics.BitmapFactory.Options();
            o.inJustDecodeBounds = true;
            android.graphics.BitmapFactory.decodeFile(bgPath, o);
            int sample = 1;
            while (o.outWidth / (sample * 2) >= 1440) {
                sample *= 2;
            }
            android.graphics.BitmapFactory.Options o2 = new android.graphics.BitmapFactory.Options();
            o2.inSampleSize = sample;
            String[] cands = new String[]{bgPath, "/data/data/cn.ninebot.ninebot/files/bg-custom.png", "/data/user/0/cn.ninebot.ninebot/files/bg-custom.png"};
            for (int ci = 0; ci < cands.length && bgBmp == null; ci++) {
                if (cands[ci] != null && cands[ci].length() > 0) {
                    bgBmp = android.graphics.BitmapFactory.decodeFile(cands[ci], o2);
                }
            }
            if (bgBmp == null) {
                try {
                    String priv = "/data/user/0/cn.ninebot.ninebot/files/bg-custom.png";
                    java.io.File srcF = new java.io.File("/sdcard/Pictures/ninebot-bg.png");
                    if (srcF.exists()) {
                        java.io.FileInputStream in1 = new java.io.FileInputStream(srcF);
                        java.io.FileOutputStream out1 = new java.io.FileOutputStream(priv);
                        byte[] buf = new byte[65536];
                        int r1;
                        while ((r1 = in1.read(buf)) > 0) {
                            out1.write(buf, 0, r1);
                        }
                        out1.close();
                        in1.close();
                        bgBmp = android.graphics.BitmapFactory.decodeFile(priv, o2);
                        log("\u80cc\u666f\u56fe\uff1a\u5df2\u81ea\u590d\u5236\u5230\u79c1\u6709\u76ee\u5f55 -> " + (bgBmp == null ? "\u4ecd\u5931\u8d25" : "OK"));
                    }
                } catch (Throwable t) {
                    log("\u80cc\u666f\u56fe\uff1a\u81ea\u590d\u5236\u5931\u8d25 " + t);
                }
            }
            if (bgBmp != null) {
                log("背景图：已解码 " + bgBmp.getWidth() + "x" + bgBmp.getHeight());
            }
            return bgBmp;
        } catch (Throwable t) {
            log("背景图：解码失败 " + t);
            return null;
        }
    }

    private void hookBgImage(final XC_LoadPackage.LoadPackageParam lp) {
        try {
            XposedHelpers.findAndHookMethod(android.widget.ImageView.class, "setImageDrawable",
                    android.graphics.drawable.Drawable.class, new XC_MethodHook() {
                        protected void afterHookedMethod(MethodHookParam p) {
                            try {
                                Object o = p.thisObject;
                                if (!(o instanceof android.widget.ImageView)) {
                                    return;
                                }
                                final android.widget.ImageView iv = (android.widget.ImageView) o;
                                if ("bgCustom".equals(iv.getTag())) {
                                    return;
                                }
                                if (!bgImgEnabled()) {
                                    return;
                                }
                                if (iv.getWidth() <= 0 || iv.getHeight() <= 0) {
                                    iv.post(new Runnable() {
                                        public void run() {
                                            try {
                                                applyBg(iv);
                                            } catch (Throwable t) {
                                            }
                                        }
                                    });
                                    return;
                                }
                                applyBg(iv);
                            } catch (Throwable t) {
                            }
                        }
                    });
            try {
                XposedHelpers.findAndHookMethod(android.view.View.class, "setBackgroundDrawable",
                        android.graphics.drawable.Drawable.class, new XC_MethodHook() {
                            protected void afterHookedMethod(MethodHookParam p) {
                                try {
                                    Object o = p.thisObject;
                                    if (!(o instanceof android.view.View)) {
                                        return;
                                    }
                                    applyBgView((android.view.View) o);
                                } catch (Throwable t) {
                                }
                            }
                        });
            } catch (Throwable t) {
                log("背景图：容器背景钩子失败 " + t);
            }
            try {
                XposedHelpers.findAndHookMethod(android.app.Activity.class, "onResume", new XC_MethodHook() {
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            final android.app.Activity act = (android.app.Activity) p.thisObject;
                            if (act == null || !bgImgEnabled()) {
                                return;
                            }
                            final android.view.View dv = act.getWindow().getDecorView();
                            final long[] ds = new long[]{1500L};
                            for (int di = 0; di < ds.length; di++) {
                                final long dd = ds[di];
                                dv.postDelayed(new Runnable() {
                                    public void run() {
                                        try {
                                            walkBg(dv);
                                        } catch (Throwable t) {
                                        }
                                    }
                                }, dd);
                            }
                        } catch (Throwable t) {
                        }
                    }
                });
            } catch (Throwable t) {
                log("背景图：Activity.onResume 钩子失败 " + t);
            }
            log("OK   背景图钩子已装");
        } catch (Throwable t) {
            log("背景图钩子失败 " + t);
        }
    }

    static class BgDrawable extends android.graphics.drawable.Drawable {
        private final android.graphics.Bitmap bm;
        private final android.graphics.Paint pt = new android.graphics.Paint(android.graphics.Paint.FILTER_BITMAP_FLAG);
        private final android.graphics.Rect src = new android.graphics.Rect();
        private final android.graphics.RectF dst = new android.graphics.RectF();

        BgDrawable(android.graphics.Bitmap b) {
            bm = b;
        }

        public void draw(android.graphics.Canvas c) {
            android.graphics.Rect bb = getBounds();
            if (bm == null || bb.isEmpty()) {
                return;
            }
            float bw = bm.getWidth();
            float bh = bm.getHeight();
            float cw = bb.width();
            float ch = bb.height();
            float scale = Math.max(cw / bw, ch / bh);
            float vw = cw / scale;
            float vh = ch / scale;
            float left = (bw - vw) / 2f;
            float top = (bh - vh) / 2f;
            src.set((int) left, (int) top, (int) (left + vw), (int) (top + vh));
            dst.set(bb);
            c.drawBitmap(bm, src, dst, pt);
        }

        public void setAlpha(int a) {
        }

        public void setColorFilter(android.graphics.ColorFilter cf) {
        }

        public int getOpacity() {
            return android.graphics.PixelFormat.OPAQUE;
        }
    }

    private static void applyBgView(android.view.View v) {
        try {
            if (v == null || "bgCustom".equals(v.getTag())) {
                return;
            }
            if (v instanceof android.widget.ImageView) {
                return;
            }
            if (!(v instanceof android.view.ViewGroup)) {
                return;
            }
            if (!bgImgEnabled()) {
                return;
            }
            int w = v.getWidth();
            int h = v.getHeight();
            if (w <= 0 || h <= 0) {
                return;
            }
            android.util.DisplayMetrics dm = v.getResources().getDisplayMetrics();
            if (w >= 700 && h >= 400 && bgHits == 0) {
                log("\u80cc\u666f\u56fe\uff1a\u5019\u9009 " + v.getClass().getName() + " " + w + "x" + h + " \u5c4f=" + dm.widthPixels + "x" + dm.heightPixels);
            }
            String nm1 = null;
            try {
                int id1 = v.getId();
                if (id1 != 0 && id1 != -1) {
                    nm1 = v.getResources().getResourceEntryName(id1);
                }
            } catch (Throwable t) {
            }
            boolean gate1 = h >= dm.heightPixels * 0.95f && w >= dm.widthPixels * 0.95f;
            if (!gate1) {
                try {
                    android.view.ViewParent par1 = v.getParent();
                    if (par1 instanceof android.view.View) {
                        String pn1 = par1.getClass().getSimpleName();
                        gate1 = pn1 != null && pn1.contains("ScrollView");
                    }
                } catch (Throwable t) {
                }
            }
            if (!gate1 && h > dm.heightPixels * 6 / 5) {
                gate1 = true;
            }
            if (!gate1) {
                return;
            }
            android.graphics.Bitmap b = bgBitmap();
            if (b == null) {
                if (bgHits == 0) {
                    log("\u80cc\u666f\u56fe\uff1a\u89e3\u7801\u5931\u8d25 path=" + conf().get("bgImagePath"));
                }
                return;
            }
            v.setTag("bgCustom");
            bgHits++;
            v.setBackgroundDrawable(new BgDrawable(b));
            log("背景图：已给容器上背景 view=" + w + "x" + h);
        } catch (Throwable t) {
        }
    }

    private static int bgHits = 0;

    private static void walkBg(android.view.View root) {
        try {
            if (!bgImgEnabled()) {
                log("\u80cc\u666f\u56fe\uff1awalk \u8df3\u8fc7\uff08\u5f00\u5173\u672a\u5f00\uff09");
                return;
            }
            bgHits = 0;
            int seen = walkBg1(root, 0);
            log("\u80cc\u666f\u56fe\uff1awalk \u5b8c\u6210 \u8282\u70b9=" + seen + " \u66ff\u6362=" + bgHits);
        } catch (Throwable t) {
        }
    }



    private static String bgResName(android.view.View v) {
        try {
            int id = v.getId();
            if (id == 0 || id == -1) {
                return null;
            }
            return v.getResources().getResourceEntryName(id);
        } catch (Throwable t) {
            return null;
        }
    }

    private static boolean bgForceOn() {
        try {
            if (!bgImgEnabled()) {
                return false;
            }
            return !"0".equals(conf().get("bgForce"));
        } catch (Throwable t) {
            return false;
        }
    }

    private static int walkBg1(android.view.View v, int depth) {
        int n = 1;
        try {
            applyBgView(v);
            if (depth < 30 && v instanceof android.view.ViewGroup) {
                android.view.ViewGroup g = (android.view.ViewGroup) v;
                for (int i = 0; i < g.getChildCount(); i++) {
                    n += walkBg1(g.getChildAt(i), depth + 1);
                }
            }
        } catch (Throwable t) {
        }
        return n;
    }

    private static void applyBg(android.widget.ImageView iv) {
        try {
            if ("bgCustom".equals(iv.getTag())) {
                return;
            }
            if (!bgImgEnabled()) {
                return;
            }
            int w = iv.getWidth();
            int h = iv.getHeight();
            if (w <= 0 || h <= 0) {
                return;
            }
            int sw = iv.getResources().getDisplayMetrics().widthPixels;
            if (w < sw * 0.9f || h < w * 0.5f) {
                return;
            }
            android.graphics.Bitmap b = bgBitmap();
            if (b == null) {
                return;
            }
            iv.setTag("bgCustom");
            iv.setScaleType(android.widget.ImageView.ScaleType.CENTER_CROP);
            iv.setImageDrawable(new android.graphics.drawable.BitmapDrawable(iv.getResources(), b));
            log("背景图：已替换 view=" + w + "x" + h);
        } catch (Throwable t) {
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
                    "dashFix", "openDash", "autoShare", "fakeShare", "postId",
                    "showEnergyOff", "showNitro"};
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
                    + (text.contains("vehicleImage=1") ? "，车图=开" : "，车图=关")
                    + "）");
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
                            Object a0 = p.args != null && p.args.length > 0 ? p.args[0] : null;
                            String nm = p.args != null && p.args.length > 1 ? String.valueOf(p.args[1]) : "?";
                            String info = "?";
                            int alen = -1;
                            if (a0 instanceof String) {
                                String s0 = (String) a0;
                                alen = s0.length();
                                info = "String(" + alen + ") " + s0.substring(0, Math.min(30, alen));
                            } else if (a0 instanceof byte[]) {
                                byte[] b0 = (byte[]) a0;
                                alen = b0.length;
                                info = "byte[" + alen + "]";
                                try {
                                    info += " " + new String(b0, 0, Math.min(30, alen), "UTF-8");
                                } catch (Throwable t2) {
                                }
                            } else if (a0 != null) {
                                info = a0.getClass().getName();
                            }

                            if (alen > 20000 || nm.toLowerCase().contains("setting")) {
                                log("动态配置：要解密 name=" + nm + " args=" + info);
                            }
                        } catch (Throwable t) {
                        }
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Object r = p.getResult();
                            if (r instanceof String) {
                                String s = (String) r;
                                if (s.length() > 20000) {
                                    log("动态配置：解密结果 String(" + s.length() + ") 含氮气="
                                            + s.contains("string.nitro_speed") + " 含关闭="
                                            + s.contains("setting_tap_lock_state_off") + " 开头="
                                            + s.substring(0, Math.min(40, s.length())));
                                }
                            } else if (r instanceof byte[]) {
                                byte[] b = (byte[]) r;
                                if (b.length > 20000) {
                                    String s = new String(b, "UTF-8");
                                    log("动态配置：解密结果 byte[" + b.length + "] 含氮气="
                                            + s.contains("string.nitro_speed") + " 含关闭="
                                            + s.contains("setting_tap_lock_state_off"));
                                }
                            }
                        } catch (Throwable t) {
                        }
                    }
                });

        hook(lp, "cn.ninebot.library.bluetooth.dynamic.utils.UtilsKt", "decrypt",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            if (!dashFixOn()) {
                                return;
                            }
                            Object a0 = p.args != null && p.args.length > 0 ? p.args[0] : null;
                            if (!(a0 instanceof String)) {
                                return;
                            }
                            String c = ((String) a0).trim();

                            if (!c.startsWith("{")) {
                                return;
                            }
                            p.setResult(null);
                            log("仪表修复：页面是明文，让九号走「解密失败当明文」那条路（" + c.length() + " 字符）");
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
                    if (!confOn("diag", false)) {
                        return;
                    }
                }
            }).start();
        } catch (Throwable t) {
        }

        try {
        } catch (Throwable t) {
        }
    }

    static boolean dynCfgDumped = false;
static boolean needleHunted = false;static int dynCfgLogs = 0;

    static void listTree(File dir, int depth, StringBuilder sb) {
        if (dir == null || !dir.exists() || depth > 4) {
            return;
        }
        File[] kids = dir.listFiles();
        if (kids == null) {
            return;
        }
        for (int i = 0; i < kids.length; i++) {
            File f = kids[i];
            if (f.isDirectory()) {
                sb.append(f.getName()).append("/ ");
                listTree(f, depth + 1, sb);
            } else {
                sb.append(f.getName()).append(':').append(f.length()).append(' ');
            }
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

    private static java.lang.reflect.Method mDevSendBytes;
    private static java.lang.Class<?> clsFunction1;
    private static boolean vcmdWatchStarted;

    static ClassLoader hostCl;

    static Class<?> hostClass(String name) throws ClassNotFoundException {
        ClassLoader cl = hostCl;
        if (cl == null) {
            throw new ClassNotFoundException(name + "（宿主 ClassLoader 还没拿到）");
        }
        return Class.forName(name, false, cl);
    }

    static Object connectedVehicle() {
        try {
            Class<?> c = hostClass("cn.ninebot.library.bluetooth.dynamic.DynamicConfigManager");
            Object companion = c.getField("Companion").get(null);
            Object mgr = companion.getClass().getMethod("getInstance").invoke(companion);
            if (mgr == null) {
                return null;
            }
            java.lang.reflect.Field f = c.getDeclaredField("connectedDeviceList");
            f.setAccessible(true);
            Object list = f.get(mgr);
            if (list instanceof java.util.List) {
                java.util.List<?> l = (java.util.List<?>) list;
                if (!l.isEmpty()) {
                    return l.get(0);
                }
            }
        } catch (Throwable t) {
            log("车控：取已连接设备失败 " + t);
        }
        return null;
    }

    static Object vehicleCallback(final String tag) {
        try {
            if (clsFunction1 == null) {
                clsFunction1 = hostClass("kotlin.jvm.functions.Function1");
            }
            final Class<?> f1 = clsFunction1;
            return java.lang.reflect.Proxy.newProxyInstance(f1.getClassLoader(), new Class<?>[] { f1 },
                    new java.lang.reflect.InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, java.lang.reflect.Method m, Object[] a) {
                            try {
                                String s = "";
                                if (a != null) {
                                    for (int i = 0; i < a.length; i++) {
                                        s += (i == 0 ? "" : ", ") + describe(a[i]);
                                    }
                                }
                                log("车控回调 " + tag + " → " + m.getName() + "(" + s + ")");
                            } catch (Throwable t) {
                            }
                            return null;
                        }
                    });
        } catch (Throwable t) {
            log("车控：建回调失败 " + t);
            return null;
        }
    }

    static String describe(Object o) {
        if (o == null) {
            return "null";
        }
        if (o instanceof byte[]) {
            return "bytes[" + ((byte[]) o).length + "] " + hex((byte[]) o);
        }
        if (o instanceof Number || o instanceof Boolean || o instanceof String) {
            return String.valueOf(o);
        }
        return o.getClass().getSimpleName() + "@" + Integer.toHexString(o.hashCode());
    }

    static boolean sendVehicleCmd(String name, byte[] data) {
        Object dev = connectedVehicle();
        if (dev == null) {
            log("车控：没有已连接的车，发不了 " + name);
            return false;
        }
        try {
            if (mDevSendBytes == null) {
                mDevSendBytes = dev.getClass().getMethod("sendCommand", String.class, byte[].class,
                        boolean.class, hostClass("kotlin.jvm.functions.Function1"));
            }
            String tag = name + (data == null ? "(读)" : " " + hex(data));
            mDevSendBytes.invoke(dev, name, data, Boolean.FALSE, vehicleCallback(tag));
            log("车控：已交给发送链路 " + tag);
            return true;
        } catch (Throwable t) {
            log("车控：发送失败 " + name + " " + t);
            return false;
        }
    }

    static byte[] parseBytesArg(String s) {
        if (s == null || s.trim().length() == 0) {
            return null;
        }
        String[] parts = s.trim().split("[,;\\s]+");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i].trim();
            try {
                if (p.startsWith("0x") || p.startsWith("0X")) {
                    out[i] = (byte) Integer.parseInt(p.substring(2), 16);
                } else {
                    out[i] = (byte) Integer.parseInt(p);
                }
            } catch (Throwable t) {
                out[i] = 0;
            }
        }
        return out;
    }

    static byte[] bytesOf(Object o) {
        if (o == null) {
            return null;
        }
        if (o instanceof byte[]) {
            return (byte[]) o;
        }
        try {
            java.lang.reflect.Method m = o.getClass().getMethod("getData");
            Object r = m.invoke(o);
            if (r instanceof byte[]) {
                return (byte[]) r;
            }
        } catch (Throwable t) {
        }
        try {
            java.lang.reflect.Method m = o.getClass().getMethod("getValue");
            Object r = m.invoke(o);
            if (r instanceof byte[]) {
                return (byte[]) r;
            }
        } catch (Throwable t) {
        }
        return null;
    }

    static boolean readGearData() {
        boolean a = sendVehicleCmd("rGearData1", null);
        boolean b = sendVehicleCmd("rGearData2", null);
        return a || b;
    }

    static boolean setNitroSpeed(final int on) {
        if (connectedVehicle() == null) {
            log("车控：没有已连接的车，改不了氮气加速");
            return false;
        }
        byte[] v = new byte[] { (byte) (on & 0xFF), (byte) ((on >> 8) & 0xFF) };
        boolean a = sendVehicleCmd("setGearNitroSpeed", v);
        boolean b = sendVehicleCmd("setGearNitroSpeed2", v);
        log("车控：氮气加速=" + on + "（S档 " + a + " / 二档 " + b + "）");
        readGearData();
        return a || b;
    }

    static final String DCM = "cn.ninebot.library.bluetooth.dynamic.DynamicConfigManager";

    static final String DASH_NB = "device_ui_dashboard.nb";

    static final String[] DASH_PICK_PATHS = {
            "/sdcard/Android/data/cn.ninebot.ninebot/files/" + DASH_NB,
            "/sdcard/ninebot/" + DASH_NB,
            "/storage/emulated/0/ninebot/" + DASH_NB,
    };
    static volatile boolean dashHookDone = false;
    static volatile boolean dashWatchStarted = false;

    static volatile boolean dashOpenHookDone = false;

    static volatile String dashAppliedSig = "";
    static volatile long dashAppliedAt = -1L;

    static boolean dashFixOn() {
        try {
            String v = conf().get("dashFix");
            return v != null && ConfText.on(v);
        } catch (Throwable t) {
            return false;
        }
    }

    static void killCheckSign(Object obj) {
        try {
            if (obj != null) {
                XposedHelpers.setBooleanField(obj, "mCheckSign", false);
            }
        } catch (Throwable t) {
        }
    }

    private void hookDashboardSign(final XC_LoadPackage.LoadPackageParam lp) {
        try {
            final Class<?> c = XposedHelpers.findClass(DCM, lp.classLoader);

            XposedBridge.hookAllConstructors(c, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    if (dashFixOn()) {
                        killCheckSign(p.thisObject);
                    }
                }
            });

            XposedBridge.hookAllMethods(c, "setMCheckSign", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    if (!dashFixOn()) {
                        return;
                    }
                    killCheckSign(p.thisObject);
                    p.setResult(null);
                }
            });

            XposedBridge.hookAllMethods(c, "getMCheckSign", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    if (dashFixOn()) {
                        p.setResult(Boolean.FALSE);
                    }
                }
            });

            String[] names = {"checkSign", "isCheckSignPass"};
            for (int i = 0; i < names.length; i++) {
                XposedBridge.hookAllMethods(c, names[i], new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        if (!dashFixOn()) {
                            return;
                        }
                        killCheckSign(p.thisObject);
                        if (p.method instanceof java.lang.reflect.Method
                                && ((java.lang.reflect.Method) p.method).getReturnType() == boolean.class) {
                            p.setResult(Boolean.TRUE);
                        }
                    }
                });
            }
            dashHookDone = true;
            log("仪表修复：已挂钩 " + DCM + "（mCheckSign / getMCheckSign / checkSign）");

            try {
                Class<?> ci = XposedHelpers.findClass(
                        "cn.ninebot.device.dynamic.ConfigInterfaceImpl", lp.classLoader);
                XposedBridge.hookAllMethods(ci, "checkSign", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        if (!dashFixOn()) {
                            return;
                        }
                        if (p.method instanceof java.lang.reflect.Method
                                && ((java.lang.reflect.Method) p.method).getReturnType() == boolean.class) {
                            p.setResult(Boolean.TRUE);
                        }
                    }
                });
                log("仪表修复：已挂钩 ConfigInterfaceImpl#checkSign（验签直接放行）");
            } catch (Throwable t) {
                log("仪表修复：ConfigInterfaceImpl#checkSign 挂钩失败（不影响其它几处）：" + t);
            }

            try {
                Class<?> eu = XposedHelpers.findClass(
                        "cn.ninebot.tools.util.EncryptionUtils", lp.classLoader);
                XposedBridge.hookAllMethods(eu, "rsaCheckSign", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        if (dashFixOn()) {
                            p.setResult(Boolean.TRUE);
                        }
                    }
                });
                XposedBridge.hookAllMethods(eu, "rsaCheckSign$default", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        if (dashFixOn()) {
                            p.setResult(Boolean.TRUE);
                        }
                    }
                });
                log("仪表修复：已挂钩 EncryptionUtils#rsaCheckSign（兜底）");
            } catch (Throwable t) {
                log("仪表修复：EncryptionUtils 没找到（不影响）：" + t);
            }
        } catch (Throwable t) {
            log("仪表修复：挂钩失败 " + t);
        }
    }

    static List<File> dashCodeDirs() {
        ArrayList<File> out = new ArrayList<File>();
        try {
            Context c = appCtx;
            if (c == null) {
                return out;
            }
            File[] kids = new File(c.getFilesDir(), "dynamic_config_new").listFiles();
            if (kids != null) {
                for (int i = 0; i < kids.length; i++) {
                    File code = new File(kids[i], "code");
                    if (code.isDirectory()) {
                        out.add(code);
                    }
                }
            }
        } catch (Throwable t) {
        }
        return out;
    }

    static List<File> dashSources() {
        ArrayList<File> out = new ArrayList<File>();
        ArrayList<File> dirs = new ArrayList<File>();
        try {
            Context c = appCtx;
            if (c != null) {
                dirs.add(c.getFilesDir());
                File ext = c.getExternalFilesDir(null);
                if (ext != null) {
                    dirs.add(ext);
                }
            }
        } catch (Throwable t) {
        }
        for (int i = 0; i < DASH_PICK_PATHS.length; i++) {
            try {
                File parent = new File(DASH_PICK_PATHS[i]).getParentFile();
                if (parent != null && !dirs.contains(parent)) {
                    dirs.add(parent);
                }
            } catch (Throwable t) {
            }
        }
        for (int i = 0; i < dirs.size(); i++) {
            File[] fs = dirs.get(i).listFiles();
            if (fs == null) {
                continue;
            }
            for (int j = 0; j < fs.length; j++) {
                File f = fs[j];
                if (f.isFile() && f.length() > 100 && f.getName().endsWith(".nb") && !out.contains(f)) {
                    out.add(f);
                }
            }
        }
        return out;
    }

    static final String SETTINGS_NB = "device_ui_settings.nb";

    static int settingsVariant() {
        int i = 0;
        if (confOn("showEnergyOff", false)) {
            i |= 1;
        }
        if (confOn("showNitro", false)) {
            i |= 2;
        }
        return i;
    }

    static boolean settingsManaged() {
        try {
            Map<String, String> c = conf();
            return c.containsKey("showEnergyOff") || c.containsKey("showNitro");
        } catch (Throwable t) {
            return false;
        }
    }

    static String pagePlain(String name) {
        try {
            if (name == null) {
                return null;
            }
            String n = name.toLowerCase();
            if (n.contains("device_ui_settings")) {
                if (!settingsManaged()) {
                    return null;
                }
                return PayloadsPlain.SETTINGS_VARIANTS[settingsVariant()];
            }
            if (n.contains("device_ui_dashboard")) {
                return PayloadsPlain.DASHBOARD;
            }
        } catch (Throwable t) {
        }
        return null;
    }

    static byte[] settingsPayload() {
        try {
            return PayloadsPlain.SETTINGS_VARIANTS[settingsVariant()].getBytes("UTF-8");
        } catch (Throwable t) {
            log("仪表修复：设置页变体取字节失败 " + t);
            return null;
        }
    }

    static final String NB_KEY = "TOGfX#qkYm@0t{83";

    private static byte[] nbIvCache = null;
    private static boolean nbIvTried = false;

    static final List<String> skippedSources = new ArrayList<String>();

    static final Map<String, Integer> payloadLen = new LinkedHashMap<String, Integer>();

    static final Map<String, byte[]> payloadHead = new LinkedHashMap<String, byte[]>();

    static boolean sameHead(File dst, byte[] head) {
        if (head == null) {
            return false;
        }
        FileInputStream in = null;
        try {
            in = new FileInputStream(dst);
            byte[] got = new byte[head.length];
            int off = 0;
            while (off < head.length) {
                int n = in.read(got, off, head.length - off);
                if (n <= 0) {
                    return false;
                }
                off += n;
            }
            return Arrays.equals(got, head);
        } catch (Throwable t) {
            return false;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable t) {
                }
            }
        }
    }

    static byte[] head32(byte[] data) {
        return data.length >= 32 ? Arrays.copyOf(data, 32) : data;
    }

    static byte[] officialNb(String name) {
        try {
            File root = new File(appCtx.getFilesDir(), "dynamic_config_new");
            File[] kids = root.listFiles();
            if (kids == null) {
                return null;
            }
            for (int i = 0; i < kids.length; i++) {
                File z = kids[i];
                if (!z.isFile() || !z.getName().endsWith(".zip")) {
                    continue;
                }
                ZipFile zf = null;
                try {
                    zf = new ZipFile(z);
                    String[] cands = {"encrypt/code/" + name, "code/" + name, name};
                    for (int c = 0; c < cands.length; c++) {
                        ZipEntry e = zf.getEntry(cands[c]);
                        if (e == null) {
                            continue;
                        }
                        InputStream in = zf.getInputStream(e);
                        try {
                            ByteArrayOutputStream bo = new ByteArrayOutputStream();
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = in.read(buf)) > 0) {
                                bo.write(buf, 0, n);
                            }
                            byte[] out = bo.toByteArray();
                            log("仪表修复：从 " + z.getName() + " 取到官方 " + name + "（" + out.length + " 字节）");
                            return out;
                        } finally {
                            try {
                                in.close();
                            } catch (Throwable t) {
                            }
                        }
                    }
                } catch (Throwable t) {
                    log("仪表修复：读 " + z.getName() + " 失败 " + t);
                } finally {
                    if (zf != null) {
                        try {
                            zf.close();
                        } catch (Throwable t) {
                        }
                    }
                }
            }
        } catch (Throwable t) {
            log("仪表修复：找官方页面文件出错 " + t);
        }
        return null;
    }

    static byte[] aesBlockDecrypt(byte[] block16) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(NB_KEY.getBytes("UTF-8"), "AES"));
        return c.doFinal(block16);
    }

    static byte[] aesCbc(byte[] data, byte[] iv, int mode) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(mode, new SecretKeySpec(NB_KEY.getBytes("UTF-8"), "AES"), new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    static byte[] deriveIv(byte[] ct, byte[] plainPrefix) {
        try {
            if (ct == null || ct.length < 32 || ct.length % 16 != 0 || plainPrefix.length < 16) {
                return null;
            }
            byte[] dk1 = aesBlockDecrypt(Arrays.copyOfRange(ct, 0, 16));
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++) {
                iv[i] = (byte) (dk1[i] ^ plainPrefix[i]);
            }
            String s = new String(aesCbc(ct, iv, Cipher.DECRYPT_MODE), "UTF-8").trim();
            if (!s.startsWith("{") || !s.endsWith("}") || !s.contains("\"view\"")) {
                return null;
            }
            return iv;
        } catch (Throwable t) {
            return null;
        }
    }

    static byte[] nbIv() {
        if (nbIvCache != null) {
            return nbIvCache.length == 0 ? null : nbIvCache;
        }
        if (nbIvTried) {
            return null;
        }
        nbIvTried = true;
        nbIvCache = new byte[0];
        try {
            byte[] off = officialNb(SETTINGS_NB);
            if (off == null) {
                log("仪表修复：没找到九号官方页面文件（dynamic_config_new/*.zip 里的 encrypt/code/" + SETTINGS_NB
                        + "），推导不出本机 IV —— 为了不把页面弄坏，这次不投内置变体");
                return null;
            }
            byte[] ct = Base64.decode(new String(off, "UTF-8").trim(), Base64.DEFAULT);
            byte[] iv = deriveIv(ct, PayloadsPlain.SETTINGS_V0.getBytes("UTF-8"));
            if (iv == null) {
                log("仪表修复：本机 IV 推导失败（官方文件解出来不是页面 JSON）—— 不投内置变体");
                return null;
            }
            nbIvCache = iv;
            log("仪表修复：本机 IV 推导成功 " + new String(iv, "ISO-8859-1"));
            return iv;
        } catch (Throwable t) {
            log("仪表修复：推导本机 IV 出错 " + t);
            return null;
        }
    }

    static byte[] encryptNb(byte[] plainJson) {
        byte[] iv = nbIv();
        if (iv == null) {
            return null;
        }
        try {
            return Base64.encodeToString(aesCbc(plainJson, iv, Cipher.ENCRYPT_MODE), Base64.NO_WRAP)
                    .getBytes("UTF-8");
        } catch (Throwable t) {
            log("仪表修复：加密页面失败 " + t);
            return null;
        }
    }

    static byte[] preparePayload(byte[] raw, String name) {
        try {
            String own = pagePlain(name);
            if (own != null) {
                return own.getBytes("UTF-8");
            }
            String t = new String(raw, "UTF-8").trim();
            if (t.startsWith("{")) {
                byte[] enc = encryptNb(t.getBytes("UTF-8"));
                if (enc != null) {
                    log("仪表修复：" + name + " 是明文，已按本机 IV 加密（" + enc.length + " 字节）");
                }
                return enc;
            }
            byte[] iv = nbIv();
            if (iv != null) {
                byte[] pt = aesCbc(Base64.decode(t, Base64.DEFAULT), iv, Cipher.DECRYPT_MODE);
                if (new String(pt, "UTF-8").trim().startsWith("{")) {
                    return raw;
                }
            }
            log("仪表修复：" + name + " 本机解不开（不是按本机 IV 加密的成品？），跳过不投");
            return null;
        } catch (Throwable t) {
            log("仪表修复：处理 " + name + " 出错 " + t);
            return null;
        }
    }

    static int writePayload(String name, byte[] data, String why) {
        int n = 0;
        List<File> dirs = dashCodeDirs();
        payloadLen.put(name, Integer.valueOf(data.length));
        byte[] head = head32(data);
        payloadHead.put(name, head);
        for (int i = 0; i < dirs.size(); i++) {
            File dst = new File(dirs.get(i), name);
            try {
                if (dst.isFile() && dst.length() == data.length) {
                    if (sameHead(dst, head)) {
                        continue;
                    }

                    log("仪表修复：" + dst.getAbsolutePath() + " 长度对得上但内容不是这份（旧 IV？），覆盖重写");
                }
                FileOutputStream o = new FileOutputStream(dst);
                try {
                    o.write(data);
                    o.flush();
                } finally {
                    try {
                        o.close();
                    } catch (Throwable t) {
                    }
                }
                n++;
                log("仪表修复：" + why + " → 已写入 " + dst.getAbsolutePath()
                        + "（" + data.length + " 字节）");
            } catch (Throwable t) {
                log("仪表修复：写 " + name + " 失败 " + t);
            }
        }
        return n;
    }

    static boolean nbPlainOk(byte[] pt) {
        try {
            String s = new String(pt, "UTF-8").trim();
            return s.startsWith("{") && s.endsWith("}");
        } catch (Throwable t) {
            return false;
        }
    }

    static boolean nbLoadable(File f) {
        byte[] iv = nbIv();
        if (iv == null || f == null || !f.isFile()) {
            return false;
        }
        try {
            byte[] raw = readAll(f);
            String t = new String(raw, "UTF-8").trim();
            if (t.startsWith("{")) {
                return true;
            }
            return nbPlainOk(aesCbc(Base64.decode(t, Base64.DEFAULT), iv, Cipher.DECRYPT_MODE));
        } catch (Throwable t) {
            return false;
        }
    }

    static int healBadTarget(String name, byte[] badRaw) {
        if (nbIv() == null) {
            return 0;
        }
        List<File> dirs = dashCodeDirs();
        if (dirs.isEmpty()) {
            return 0;
        }
        byte[] badHead = badRaw == null ? null : head32(badRaw);
        byte[] off = officialNb(name);
        int fixed = 0;
        for (int i = 0; i < dirs.size(); i++) {
            File dst = new File(dirs.get(i), name);
            try {
                if (!dst.isFile()) {
                    continue;
                }
                if (badHead != null && !(dst.length() == badRaw.length && sameHead(dst, badHead))) {
                    continue;
                }
                if (nbLoadable(dst)) {
                    continue;
                }
                if (off != null) {
                    writePayload(name, off, "还原官方页面（原来那份本机解不开）");
                    fixed++;
                } else if (dst.delete()) {
                    log("仪表修复：" + name + " 在 " + dst.getAbsolutePath()
                            + " 那份本机解不开、又找不到官方文件，已删掉让九号自己重下");
                    fixed++;
                }
            } catch (Throwable t) {
                log("仪表修复：修 " + name + " 出错 " + t);
            }
        }
        if (fixed > 0) {
            log("仪表修复：把 " + name + " 还原成官方页面（修好 " + fixed + " 处）——页面原来本机解不开，所以是空白/报加载失败");
        }
        return fixed;
    }

    static String dashSig() {
        StringBuilder sb = new StringBuilder();
        List<File> srcs = dashSources();
        for (int i = 0; i < srcs.size(); i++) {
            File f = srcs.get(i);
            if (SETTINGS_NB.equals(f.getName())) {
                continue;
            }
            sb.append(f.getName()).append(':').append(f.length()).append(';');
        }
        sb.append("SET:").append(settingsManaged() ? settingsVariant() : -1).append(';');
        return sb.toString();
    }

    static boolean dashDrift() {
        List<File> dirs = dashCodeDirs();
        List<File> srcs = dashSources();
        for (int i = 0; i < srcs.size(); i++) {
            File s = srcs.get(i);
            if (SETTINGS_NB.equals(s.getName())) {
                continue;
            }
            if (skippedSources.contains(s.getName())) {
                continue;
            }
            Integer want = payloadLen.get(s.getName());
            byte[] wh = payloadHead.get(s.getName());
            if (want == null || wh == null) {
                return true;
            }
            for (int j = 0; j < dirs.size(); j++) {
                File dst = new File(dirs.get(j), s.getName());
                if (!dst.isFile() || dst.length() != want.intValue() || !sameHead(dst, wh)) {
                    return true;
                }
            }
        }
        if (settingsManaged()) {
            byte[] set = settingsPayload();
            if (set != null) {
                byte[] sh = head32(set);
                for (int j = 0; j < dirs.size(); j++) {
                    File dst = new File(dirs.get(j), SETTINGS_NB);
                    if (!dst.isFile() || dst.length() != set.length || !sameHead(dst, sh)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    static byte[] readAll(File f) throws Exception {
        FileInputStream in = new FileInputStream(f);
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            return bo.toByteArray();
        } finally {
            try {
                in.close();
            } catch (Throwable t) {
            }
        }
    }

    static boolean deployDashboard(String why) {
        List<File> dirs = dashCodeDirs();
        if (dirs.isEmpty()) {
            log("仪表修复：还没有 dynamic_config_new/<车号>/code 目录（车没连过蓝牙？）");
            return false;
        }
        int n = 0;

        if (settingsManaged()) {
            byte[] set = settingsPayload();
            if (set != null) {
                n += writePayload(SETTINGS_NB, set, why + "·设置页变体 s" + settingsVariant());
            }
        }

        List<File> srcs = dashSources();
        boolean any = n > 0;
        int skip = 0;
        skippedSources.clear();
        List<byte[]> badRaws = new ArrayList<byte[]>();
        for (int s = 0; s < srcs.size(); s++) {
            File src = srcs.get(s);
            if (SETTINGS_NB.equals(src.getName())) {
                continue;
            }
            any = true;
            try {
                byte[] raw = readAll(src);
                byte[] use = preparePayload(raw, src.getName());
                if (use == null) {
                    skip++;
                    skippedSources.add(src.getName());
                    badRaws.add(raw);
                    continue;
                }
                n += writePayload(src.getName(), use, why);
            } catch (Throwable t) {
                log("仪表修复：读 " + src.getName() + " 失败 " + t);
            }
        }

        for (int i = 0; i < skippedSources.size(); i++) {
            n += healBadTarget(skippedSources.get(i), badRaws.get(i));
        }
        if (!settingsManaged()) {

            n += healBadTarget(SETTINGS_NB, null);
        }
        dashAppliedSig = dashSig();
        dashAppliedAt = System.currentTimeMillis();
        if (!any) {
            log("仪表修复：" + why + " → 没找到自定义文件（把 *.nb 放到 " + DASH_PICK_PATHS[0]
                    + " 那一层，或者在设置界面打开「显示开关」）");
        } else if (n == 0 && skip == 0) {
            log("仪表修复：" + why + " → 目录里已经是这些文件了，不重复写");
        } else if (skip > 0) {
            log("仪表修复：" + why + " → 有 " + skip + " 个文件本机解不开（多半是别的机型 IV 的成品），已跳过");
        }
        return true;
    }

    static void openDashboard() {
        if (!dashOpenHookDone) {
            dashOpenHookDone = true;

            try {
                XposedHelpers.findAndHookMethod("android.app.Activity", appCtx.getClassLoader(), "finish",
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) {
                                try {
                                    if (p.thisObject != null && p.thisObject.getClass().getName()
                                            .contains("DashboardActivity")) {
                                        log("仪表修复：DashboardActivity 自己调了 finish()，栈＝\n"
                                                + android.util.Log.getStackTraceString(new Throwable()));
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                        });
            } catch (Throwable ignored) {
            }

            try {
                XposedHelpers.findAndHookMethod("android.app.Activity", appCtx.getClassLoader(), "onCreate",
                        android.os.Bundle.class, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam p) {
                                try {
                                    if (p.thisObject == null) {
                                        return;
                                    }
                                    String cn = p.thisObject.getClass().getName();

                                    if (!cn.contains("Dynamic") && !cn.contains("Dashboard")) {
                                        return;
                                    }
                                    android.content.Intent in = ((android.app.Activity) p.thisObject).getIntent();
                                    android.os.Bundle b = in == null ? null : in.getExtras();
                                    log("仪表修复：进页面 " + cn
                                            + " config_name=" + (b == null ? null : b.getString("config_name"))
                                            + " device_tag=" + (b == null ? null : b.getString("device_tag"))
                                            + " device_server_id=" + (b == null ? -1 : b.getInt("device_server_id", -1)));

                                    if (b != null) {
                                        String st = b.getString("device_tag");
                                        if (st != null && st.length() > 0) {
                                            writeVtag(st, b.getInt("device_server_id", 0));
                                        }
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                        });
            } catch (Throwable ignored) {
            }
        }
        try {
            Context c = appCtx;
            if (c == null) {
                log("仪表修复：拿不到 App 上下文，拉不起仪表界面");
                return;
            }
            String[] rt = resolveVtag();
            if (rt[0].length() == 0) {

                log("仪表修复：还没拿到车架号（九号设备列表没加载完），等它 12 秒再开");
                for (int i = 0; i < 10 && rt[0].length() == 0; i++) {
                    try {
                        Thread.sleep(1200L);
                    } catch (InterruptedException ie) {
                        break;
                    }
                    rt = resolveVtag();
                }
            }
            if (rt[0].length() == 0) {
                log("仪表修复：还是拿不到车架号，这次不开仪表盘"
                        + "（先在九号里进一次车辆页，让 App 把设备列表拉出来，再点一次「打开仪表盘」）");
                toast("九号还没加载完车辆信息，请先进一次车辆页，再点「打开仪表盘」");
                return;
            }
            int vt = 0;
            try {
                vt = Integer.parseInt(rt[1]);
            } catch (Throwable ignored) {
            }
            android.content.Intent it = new android.content.Intent();
            it.setClassName("cn.ninebot.ninebot", "cn.ninebot.device.dynamic.sub.DashboardActivity");
            it.putExtra("device_server_id", vt);
            it.putExtra("device_tag", rt[0]);
            it.putExtra("config_name", "device_ui_dashboard");
            it.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            c.startActivity(it);
            log("仪表修复：已强制打开仪表界面（device_tag=" + rt[0] + ", vehicleType=" + vt + "）");
        } catch (Throwable t) {
            log("仪表修复：拉仪表界面失败 " + t);
        }
    }

    static String[] resolveVtag() {
        Object bean = null;
        try {
            Context c = appCtx;
            ClassLoader cl = c == null ? null : c.getClassLoader();
            if (cl != null) {
                Class<?> dm = cl.loadClass("cn.ninebot.device.DeviceManager");
                bean = staticField(dm, "currentDeviceBean");
                if (bean == null) {
                    Object list = staticField(dm, "mAuthDeviceList");
                    if (list instanceof java.util.List && !((java.util.List) list).isEmpty()) {
                        bean = ((java.util.List) list).get(0);
                    }
                }
            }
        } catch (Throwable t) {
            log("仪表修复：取当前设备失败 " + t);
        }
        int vt = 0;
        String tag = "";
        if (bean != null) {
            try {
                Object v = bean.getClass().getMethod("getVehicleType").invoke(bean);
                if (v instanceof Integer) {
                    vt = (Integer) v;
                }
            } catch (Throwable ignored) {
            }
            try {
                Object w = bean.getClass().getMethod("getWnumber").invoke(bean);
                if (w instanceof String) {
                    tag = (String) w;
                }
            } catch (Throwable ignored) {
            }
        }
        if (tag != null && tag.length() > 0) {
            writeVtag(tag, vt);
            return new String[]{tag, String.valueOf(vt)};
        }
        String[] cached = readVtag();
        if (cached != null) {
            log("仪表修复：设备列表还没好，用上次记下的车架号 " + cached[0]);
            return cached;
        }
        return new String[]{"", "0"};
    }

    static File vtagFile() {
        File dir = dataDir();
        return dir == null ? null : new File(dir, "ninebot-sign.vtag");
    }

    static String[] readVtag() {
        try {
            File f = vtagFile();
            if (f == null || !f.exists()) {
                return null;
            }
            BufferedReader r = new BufferedReader(
                    new InputStreamReader(new FileInputStream(f), "UTF-8"));
            String tag = r.readLine();
            String vt = r.readLine();
            r.close();
            if (tag == null) {
                return null;
            }
            tag = tag.trim();
            if (tag.length() == 0) {
                return null;
            }
            return new String[]{tag, vt == null ? "0" : vt.trim()};
        } catch (Throwable t) {
            return null;
        }
    }

    static void writeVtag(String tag, int vt) {
        try {
            if (tag == null || tag.length() == 0) {
                return;
            }
            String[] old = readVtag();
            if (old != null && tag.equals(old[0]) && String.valueOf(vt).equals(old[1])) {
                return;
            }
            File f = vtagFile();
            if (f == null) {
                return;
            }
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write((tag + "\n" + vt + "\n").getBytes("UTF-8"));
            fo.close();
            log("仪表修复：记下车架号 " + tag + "（车型 " + vt + "）");
        } catch (Throwable ignored) {
        }
    }

    static Object staticField(Class<?> cls, String name) {
        try {
            java.lang.reflect.Field f = cls.getDeclaredField(name);
            f.setAccessible(true);
            return f.get(null);
        } catch (Throwable t) {
            return null;
        }
    }

    static void clearOpenDash() {
        try {
            File dir = dataDir();
            if (dir == null) {
                return;
            }
            File f = new File(dir, "ninebot-sign.conf");
            if (!f.exists()) {
                return;
            }
            List<String> lines = new ArrayList<String>();
            BufferedReader r = new BufferedReader(
                    new InputStreamReader(new FileInputStream(f), "UTF-8"));
            String ln;
            boolean hit = false;
            while ((ln = r.readLine()) != null) {
                if (ln.trim().startsWith("openDash=")) {
                    ln = "openDash=0";
                    hit = true;
                }
                lines.add(ln);
            }
            r.close();
            if (!hit) {
                return;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < lines.size(); i++) {
                sb.append(lines.get(i)).append('\n');
            }
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write(sb.toString().getBytes("UTF-8"));
            fo.close();

            confMap = null;
            confAt = 0L;
            log("仪表修复：openDash 已复位为 0");
        } catch (Throwable t) {
            log("仪表修复：openDash 复位失败（下次开 App 可能还会自动进仪表页）: " + t);
        }
    }

    static boolean freshOpenDash(String v) {
        try {
            long ts = Long.parseLong(v);
            long age = System.currentTimeMillis() - ts;
            return age >= 0L && age < 60000L;
        } catch (Throwable t) {
            return false;
        }
    }

    static void startDashboardWatch() {
        if (dashWatchStarted) {
            return;
        }
        dashWatchStarted = true;
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                boolean last = false;
                boolean opened = false;

                String lastReq = "";
                while (true) {
                    try {
                        Thread.sleep(2000);
                        boolean on = dashFixOn();
                        if (on && !last) {
                            last = true;
                            log("仪表修复：开关已打开（跳过签名校验）");
                            deployDashboard("开关打开");
                        } else if (!on && last) {
                            last = false;
                            log("仪表修复：开关已关闭");
                        } else if (on) {
                            if (!dashSig().equals(dashAppliedSig)) {
                                deployDashboard("源文件变了");
                            } else if (dashDrift()) {
                                deployDashboard("被九号覆盖了，重投");
                            }
                        }

                        String od = null;
                        Map<String, String> up = uiPrefs();
                        if (up != null) {
                            od = up.get("openDash");
                        }
                        if (od == null) {
                            od = conf().get("openDash");
                        }
                        if (od == null) {
                            od = "";
                        }
                        od = od.trim();
                        boolean fileFlag = "1".equals(od) || "true".equalsIgnoreCase(od);
                        boolean uiReq = freshOpenDash(od);
                        boolean newReq = uiReq && !od.equals(lastReq);
                        if (newReq) {
                            lastReq = od;
                        }
                        if ((fileFlag && !opened) || newReq) {
                            opened = true;
                            openDashboard();
                            if (fileFlag) {

                                clearOpenDash();
                            }
                        } else if (!fileFlag && !uiReq) {
                            opened = false;
                        }
                    } catch (Throwable t2) {
                    }
                }
            }
        }, "NinebotSign-dash");
        t.setDaemon(true);
        t.start();
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
                                log("界面文字：把有效期那串日期换成 9999.12.31（「" + fixed + "」）");
                            }
                        }
                    } catch (Throwable t) {
                    }
                }
            });
            note("OK   android.widget.TextView#setText（假有效期）");
        } catch (Throwable t) {
            note("FAIL android.widget.TextView#setText（假有效期） -> " + t);
            log("界面文字：假有效期 hook 没装上 " + t);
        }
    }

    private void hookWebDiag(final XC_LoadPackage.LoadPackageParam lp) {
        final int[] budget = new int[]{40};
        try {
            XposedHelpers.findAndHookMethod("android.webkit.WebView", lp.classLoader, "loadUrl",
                    String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            try {
                                if (budget[0] <= 0) {
                                    return;
                                }
                                Object o = p.args[0];
                                String u = o == null ? "" : String.valueOf(o);
                                if (u.startsWith("http")) {
                                    budget[0]--;
                                    log("H5侦察(loadUrl)：" + (u.length() > 260 ? u.substring(0, 260) : u));
                                    if (u.indexOf("taskCenter") >= 0) {
                                        injectTaskH5(p.thisObject);
                                    }
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    });
            note("OK   android.webkit.WebView#loadUrl（H5侦察）");
        } catch (Throwable t) {
            note("FAIL android.webkit.WebView#loadUrl（H5侦察） -> " + t);
        }
        try {
            XposedHelpers.findAndHookMethod("android.webkit.WebView", lp.classLoader,
                    "addJavascriptInterface", Object.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            try {
                                Object obj = p.args[0];
                                log("H5侦察(JSBridge)：name=" + p.args[1] + " class="
                                        + (obj == null ? "null" : obj.getClass().getName()));
                            } catch (Throwable ignored) {
                            }
                        }
                    });
            note("OK   android.webkit.WebView#addJavascriptInterface（H5侦察）");
        } catch (Throwable t) {
            note("FAIL android.webkit.WebView#addJavascriptInterface（H5侦察） -> " + t);
        }
    }

private void hookConsoleDiag(final XC_LoadPackage.LoadPackageParam lp) {
        try {
            XposedHelpers.findAndHookMethod("android.webkit.WebChromeClient", lp.classLoader,
                    "onConsoleMessage", String.class, int.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            try {
                                String msg = String.valueOf(p.args[0]);
                                if (msg != null && msg.indexOf("[NBTASK]") >= 0) {
                                    log("H5任务：" + (msg.length() > 3000 ? msg.substring(0, 3000) : msg));
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    });
            note("OK   WebChromeClient#onConsoleMessage（H5任务抓取）");
        } catch (Throwable t) {
            note("FAIL WebChromeClient#onConsoleMessage（H5任务抓取） -> " + t);
        }
    }

    private static final String TASK_JS = "(function(){if(window.__nbt4){return}window.__nbt4=1;setTimeout(function(){try{var es=document.querySelectorAll('div,span');for(var i=0;i<es.length;i++){var t=(es[i].textContent||'').trim();if(t==='\u6210\u957f\u4efb\u52a1'){es[i].click();console.log('[NBTASK] tab');break}}}catch(e){}},1200);var L=function(s){try{console.log('[NBTASK] '+s)}catch(e){}};var H=null,SENT={},N=0;var OX=XMLHttpRequest.prototype.open,OS=XMLHttpRequest.prototype.send,OH=XMLHttpRequest.prototype.setRequestHeader;XMLHttpRequest.prototype.open=function(m,u){this.__m=m;this.__u=String(u||'');this.__h={};return OX.apply(this,arguments)};XMLHttpRequest.prototype.setRequestHeader=function(k,v){try{this.__h[k]=v}catch(e){}return OH.apply(this,arguments)};function claim(id){try{if(SENT[id]){return}SENT[id]=1;var h={};for(var k in H){h[k]=H[k]}h['Content-Type']='application/json';var tok=null;try{tok=sessionStorage.getItem('LOGIN_TOKEN')}catch(e){}if(tok&&!h['Authorization']){h['Authorization']=tok}L('claim id='+id+' auth='+(h['Authorization']?'yes':'no'));fetch('https://cn-cbu-gateway.ninebot.com/portal/self-service/task/reward',{method:'POST',headers:h,body:JSON.stringify({taskId:id})}).then(function(r){return r.text()}).then(function(x){L('claim-res '+String(x).slice(0,300))}).catch(function(e){L('claim-err '+e)})}catch(e){L('claim-throw '+e)}}try{XMLHttpRequest.prototype.send=function(b){var t=this;try{if(t.__u&&t.__u.indexOf('ninebot.com')>=0&&N<25){N++;t.addEventListener('load',function(){try{L('XHR '+t.__m+' '+t.__u.split('?')[0]+(b?' BODY='+String(b).slice(0,200):'')+' RESP='+String(t.responseText||'').slice(0,220))}catch(e){}});if(t.__u.indexOf('task/v3/list')>=0){t.addEventListener('load',function(){try{H=t.__h;var j=JSON.parse(t.responseText);var arr=(j&&j.data)||[];for(var i=0;i<arr.length;i++){var it=arr[i];if(it.title&&String(it.title).indexOf('分享')>=0){claim(it.taskId)}}}catch(e){L('parse-err '+e)}})}}}catch(e){}return OS.apply(this,arguments)}}catch(e){}L('installed4')})();";

    private static void injectTaskH5(final Object webView) {
        try {
            final android.os.Handler h = new android.os.Handler(android.os.Looper.getMainLooper());
            final int[] delays = new int[]{250, 600, 1200, 2000};
            for (int i = 0; i < delays.length; i++) {
                final int d = delays[i];
                h.postDelayed(new Runnable() {
                    public void run() {
                        try {
                            XposedHelpers.callMethod(webView, "evaluateJavascript", TASK_JS, null);
                        } catch (Throwable t) {
                            log("H5注入失败：" + t);
                        }
                    }
                }, d);
            }
        } catch (Throwable t) {
            log("H5注入失败：" + t);
        }
    }
private static void findDb(java.io.File dir, java.util.List<java.io.File> out, int depth) {
        if (depth > 3) {
            return;
        }
        java.io.File[] fs = dir.listFiles();
        if (fs == null) {
            return;
        }
        for (java.io.File f : fs) {
            if (f.isDirectory()) {
                findDb(f, out, depth + 1);
            } else if (f.getName().endsWith(".db") || f.getName().endsWith(".sqlite")) {
                out.add(f);
            }
        }
    }
    private static Object m(Object o, String name, Object... args) {
        try {
            Class<?> c = o.getClass();
            for (java.lang.reflect.Method mm : c.getMethods()) {
                if (!mm.getName().equals(name)) {
                    continue;
                }
                Class<?>[] ps = mm.getParameterTypes();
                if (ps.length != args.length) {
                    continue;
                }
                boolean ok = true;
                for (int i = 0; i < ps.length; i++) {
                    Object a = args[i];
                    Class<?> p = ps[i];
                    if (p.isPrimitive()) {
                        if (!((p == long.class && a instanceof Long) || (p == int.class && a instanceof Integer))) {
                            ok = false;
                        }
                    } else if (a != null && !p.isAssignableFrom(a.getClass())) {
                        ok = false;
                    }
                    if (!ok) {
                        break;
                    }
                }
                if (ok) {
                    mm.setAccessible(true);
                    return mm.invoke(o, args);
                }
            }
        } catch (Throwable t) {
        }
        return null;
    }

    private static final java.util.Set<String> shareSeen = java.util.Collections.synchronizedSet(new java.util.LinkedHashSet<String>());
    private static final java.util.Set<String> urlSeen = java.util.Collections.synchronizedSet(new java.util.LinkedHashSet<String>());private static void hookKeyStore(ClassLoader cl) {
        String[] cls = {"cn.ninebot.commonlibs.keystore.NBKeyStore", "cn.ninebot.commonlibs.keystore.NBKeyStoreKt"};
        for (String cn : cls) {
            try {
                final String tag = cn.substring(cn.lastIndexOf('.') + 1);
                XposedBridge.hookAllMethods(cl.loadClass(cn), "aesDecryptData", new XC_MethodHook() {
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Object r = p.getResult();
                        if (r instanceof String) {
                            String s = (String) r;
                            log("解密：" + tag + " -> " + s.substring(0, Math.min(1200, s.length())));
                        } else {
                            Object[] as = p.args;
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < (as == null ? 0 : as.length) && i < 3; i++) {
                                sb.append(String.valueOf(as[i])).append(" | ");
                            }
                            log("解密：" + tag + " 调参 " + sb + " 结果=" + (r == null ? "null" : r.getClass().getSimpleName()));
                        }
                    }
                });
                XposedBridge.hookAllMethods(cl.loadClass(cn), "aesDecryptDataSafe", new XC_MethodHook() {
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Object r = p.getResult();
                        if (r instanceof String) {
                            String s = (String) r;
                            log("解密Safe：" + tag + " -> " + s.substring(0, Math.min(1200, s.length())));
                        }
                    }
                });
                log("OK   " + cn + " aesDecrypt");
            } catch (Throwable t) {
                log("NG   " + cn + " aesDecrypt " + t);
            }
        }
    }private static void hookShareDiag(ClassLoader cl) {
        String[] cs = {"cn.ninebot.moment.manager.MomentShareManager", "cn.ninebot.moment.manager.MomentShareActivity", "cn.ninebot.moment.track.SpecialShareClick"};
        for (String cn : cs) {
            try {
                final String tag = cn.substring(cn.lastIndexOf('.') + 1);

            } catch (Throwable ig) {
            }
            try {
                Class<?> c = cl.loadClass(cn);
                for (java.lang.reflect.Method mm : c.getDeclaredMethods()) {
                    final String mn = mm.getName();
                    try {
                        XposedBridge.hookAllMethods(c, mn, new XC_MethodHook() {
                            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                try {
                                    Object[] as = p.args;
                                    StringBuilder sb = new StringBuilder();
                                    for (int i = 0; i < (as == null ? 0 : as.length) && i < 3; i++) {
                                        String v = String.valueOf(as[i]);
                                        sb.append(v.length() > 80 ? v.substring(0, 80) : v).append("¦");
                                    }
                                    Object r = p.getResult();
                                    String rs = r == null ? "null" : String.valueOf(r);
                                    if (rs.length() > 120) {
                                        rs = rs.substring(0, 120);
                                    }
                                    String tgx = p.method.getDeclaringClass().getSimpleName();
                                    log("分享：" + tgx + "#" + mn + "(" + sb + ") => " + rs);
                                } catch (Throwable t) {
                                }
                            }
                        });
                    } catch (Throwable ig2) {
                    }
                }
                log("OK   " + cn + " 分享钩子");
            } catch (Throwable t) {
                log("NG   " + cn + " " + t);
            }
        }
    }private static void hookWxShare(ClassLoader cl) {
        String[] cls = {"com.tencent.mm.opensdk.openapi.WXApiImplV10", "com.tencent.tauth.Tencent"};
        String[] mns = {"sendReq", "shareToQQ", "shareToQzone"};
        for (int i = 0; i < cls.length; i++) {
            for (String mn : mns) {
                try {
                    XposedBridge.hookAllMethods(cl.loadClass(cls[i]), mn, new XC_MethodHook() {
                        protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                            try {
                                StringBuilder sb = new StringBuilder();
                                StackTraceElement[] st = Thread.currentThread().getStackTrace();
                                for (int k = 2; k < st.length && k < 8; k++) {
                                    sb.append(st[k].getClassName().substring(st[k].getClassName().lastIndexOf('.') + 1)).append('.').append(st[k].getMethodName()).append(" | ");
                                }
                                log("微信分享：" + p.method.getName() + " => " + p.getResult() + " 调用链 " + sb);
                            } catch (Throwable t) {
                            }
                        }
                    });
                    log("OK   " + cls[i] + "#" + mn);
                } catch (Throwable t) {
                    log("NG   " + cls[i] + "#" + mn);
                }
            }
        }
    }private static void hookFakeShare(ClassLoader cl) {
        try {
            XposedBridge.hookAllMethods(cl.loadClass("com.tencent.mm.opensdk.channel.MMessageActV2"), "send", new XC_MethodHook() {
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    try {
                        if (!fakeShareOn()) {
                            return;
                        }
                        p.setResult(Boolean.TRUE);
                        shareBlocked = true;
                        log("伪造分享：拦下微信启动（MMessageActV2#send）");
                    } catch (Throwable t) {
                    }
                }
            });
            log("OK   MMessageActV2#send(伪造分享)");
        } catch (Throwable t) {
            log("NG   MMessageActV2 " + t);
        }
    }

    static boolean fakeShareOn() {
        String v = conf().get("fakeShare");
        return v != null && (v.equals("1") || v.equals("true") || v.equals("on"));
    }
    static android.app.Activity sWebAct;
    static volatile boolean shareBlocked;

    static boolean autoShareOn() {
        String v = conf().get("autoShare");
        return v != null && (v.equals("1") || v.equals("true") || v.equals("on"));
    }

    private static void tapAt(final android.app.Activity act, final int x, final int y, final String tag) {
        try {
            final android.view.View dv = act.getWindow().getDecorView();
            final long t0 = android.os.SystemClock.uptimeMillis();
            final android.view.MotionEvent d = android.view.MotionEvent.obtain(t0, t0, android.view.MotionEvent.ACTION_DOWN, x, y, 0);
            d.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);
            final android.view.MotionEvent u = android.view.MotionEvent.obtain(t0, t0 + 60, android.view.MotionEvent.ACTION_UP, x, y, 0);
            u.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);
            dv.post(new Runnable() {
                public void run() {
                    dv.dispatchTouchEvent(d);
                    dv.dispatchTouchEvent(u);
                }
            });
            log("自动分享：" + tag + " (" + x + "," + y + ")");
        } catch (Throwable t) {
            log("自动分享：点击失败 " + tag + " " + t);
        }
    }

    private static void hookAutoShareFlow(ClassLoader cl) {
        startNewFlow();
    }
    static void openTaskCenter() {
        try {
            android.content.Context ctx = (android.content.Context) Class.forName("android.app.AndroidAppHelper").getMethod("currentApplication").invoke(null);
            if (ctx == null) {
                log("自动领取：拿不到上下文");
                return;
            }
            String url = "https://h5-bj.ninebot.com/ninebotApp/#/taskCenter?immersed=1&statusbar=light&category=motor&language=zh&app_version=610114116&is_dark=0&androidStatusBarHeight=144";
            android.content.Intent in = new android.content.Intent();
            in.setClassName(ctx.getPackageName(), "cn.ninebot.support.web.WebActivity");
            in.putExtra("web_url", url);
            in.putExtra("title", "\u4efb\u52a1\u4e2d\u5fc3");
            in.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            ctx.startActivity(in);
            final android.os.Handler h2 = new android.os.Handler(android.os.Looper.getMainLooper());
            h2.postDelayed(new Runnable() {
                public void run() {
                    log("自动领取：等待脚本自行拉取成长任务");
                }
            }, 7000);
            log("自动领取：已打开任务中心 H5");
        } catch (Throwable t) {
            log("自动领取：打开失败 " + t);
        }
    }
    private static void hookWebIntent(ClassLoader cl) {
        try {
            XposedBridge.hookAllMethods(cl.loadClass("cn.ninebot.support.web.WebActivity"), "onCreate", new XC_MethodHook() {
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    try {
                        android.app.Activity a = (android.app.Activity) p.thisObject;
                        android.content.Intent in = a.getIntent();
                        android.os.Bundle b = in == null ? null : in.getExtras();
                        StringBuilder sb = new StringBuilder();
                        if (b != null) {
                            for (String k : b.keySet()) {
                                String v = String.valueOf(b.get(k));
                                sb.append(k).append('=').append(v.length() > 120 ? v.substring(0, 120) : v).append(" ; ");
                            }
                        }
                        log("H5页面参数：data=" + (in == null ? "" : in.getDataString()) + " extras=[" + sb + "]");
                    } catch (Throwable t) {
                    }
                }
            });
            XposedBridge.hookAllMethods(cl.loadClass("cn.ninebot.support.web.WebActivity"), "onResume", new XC_MethodHook() {
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    sWebAct = (android.app.Activity) p.thisObject;
                }
            });
            log("OK   WebActivity#onCreate(参数)");
        } catch (Throwable t) {
            log("NG   WebActivity#onCreate " + t);
        }
    }
static volatile boolean flowStarted;
    static volatile boolean ultraArmed;



    static String todayKey() {
        return new java.text.SimpleDateFormat("yyyyMMdd", java.util.Locale.US).format(new java.util.Date());
    }
    static boolean autoShareTodayDone() {
        try {
            File d = dataDir();
            if (d == null) return false;
            File ff = new File(d, "ninebot-autoshare-day.txt");
            if (!ff.exists()) return false;
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(new java.io.FileInputStream(ff), "UTF-8"));
            String ln = r.readLine();
            r.close();
            return todayKey().equals(ln == null ? "" : ln.trim());
        } catch (Throwable t) {
            return false;
        }
    }
    static void autoShareMarkToday() {
        try {
            File d = dataDir();
            if (d == null) return;
            File ff = new File(d, "ninebot-autoshare-day.txt");
            java.io.FileOutputStream o = new java.io.FileOutputStream(ff);
            o.write(todayKey().getBytes("UTF-8"));
            o.close();
        } catch (Throwable t) {
            log("写自动分享日期失败 " + t);
        }
    }

    private static void hookRnIntent(ClassLoader cl) {
        try {
            XposedBridge.hookAllMethods(cl.loadClass("cn.ninebot.react.NBReactActivity"), "onResume", new XC_MethodHook() {
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    try {
                        android.content.Intent in = ((android.app.Activity) p.thisObject).getIntent();
                        String route = in == null ? null : in.getStringExtra("route");
                        if (!"MomentDetail".equals(route) || ultraArmed) {
                            return;
                        }
                        if (!"1".equals(conf().get("autoShare"))) {
                            return;
                        }
                        ultraArmed = true;
                        log("自动分享：帖子页就绪，稍后点分享");
                        final android.os.Handler hu = new android.os.Handler(android.os.Looper.getMainLooper());
                        hu.postDelayed(new Runnable() { public void run() { tapStep(737, 2452, "分享"); } }, 2300);
                        hu.postDelayed(new Runnable() { public void run() { tapStep(456, 1877, "微信"); } }, 3300);
                        hu.postDelayed(new Runnable() { public void run() { try { openTaskCenter(); } catch (Throwable t) {} } }, 4300);
                    } catch (Throwable t) {
                    }
                }
            });
            note("OK   NBReactActivity#onResume(极速触发)");
        } catch (Throwable t) {
            note("NG   NBReactActivity " + t);
        }
    }
    private static void startNewFlow() {
        final android.os.Handler h = new android.os.Handler(android.os.Looper.getMainLooper());
        for (int i = 0; i < 20; i++) {
            final int n = i;
            h.postDelayed(new Runnable() {
                public void run() {
                    try {
                        if (!"1".equals(conf().get("autoShare"))) {
                            return;
                        }
                        if (autoShareTodayDone()) {
                            return;
                        }
                        if (sTopAct == null) {
                            return;
                        }
                        if (flowStarted) {
                            return;
                        }
                        flowStarted = true;
                        autoShareMarkToday();
                        log("自动分享：新流程启动");
                        openPostDirect(sTopAct);
                    } catch (Throwable t) {
                    }
                }
            }, i * 700);
        }
    }

    private static void openPostDirect(android.content.Context ctx) {
        try {
            String pid = conf().get("postId");
            if (pid == null || pid.length() < 3) {
                pid = "22716571";
            }
            android.content.Intent in = new android.content.Intent();
            in.setClassName(ctx.getPackageName(), "cn.ninebot.react.NBReactActivity");
            in.putExtra("module_name", "TimelineModule");
            in.putExtra("from_rn", "TimelineModule");
            in.putExtra("prePgId", "mts");
            in.putExtra("page_location", "2");
            in.putExtra("route", "MomentDetail");
            in.putExtra("circle_id", pid);
            in.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            ctx.startActivity(in);
            log("自动分享：直接打开帖子 circle_id=" + pid);
        } catch (Throwable t) {
            log("自动分享：打开帖子失败 " + t);
        }
    }
private static int copyTree(java.io.File src, java.io.File dst) throws java.io.IOException {
        java.io.File[] fs = src.listFiles();
        int n = 0;
        if (fs == null) {
            return 0;
        }
        for (java.io.File c : fs) {
            String p = c.getAbsolutePath();
            if (p.indexOf("/res/") >= 0) {
                continue;
            }
            java.io.File out = new java.io.File(dst, c.getName());
            if (c.isDirectory()) {
                out.mkdirs();
                n += copyTree(c, out);
                continue;
            }
            if (c.length() > 30L * 1024 * 1024) {
                continue;
            }
            java.io.FileInputStream in = new java.io.FileInputStream(c);
            java.io.FileOutputStream o = new java.io.FileOutputStream(out);
            byte[] buf = new byte[65536];
            int r;
            while ((r = in.read(buf)) > 0) {
                o.write(buf, 0, r);
            }
            in.close();
            o.close();
            n++;
        }
        return n;
    }
    private static final java.util.Set<String> dbSeen = new java.util.HashSet<String>();
private static volatile android.app.Activity sTopAct;

    private void hookAutoShare(final XC_LoadPackage.LoadPackageParam lp) {
        try {
            XposedHelpers.findAndHookMethod("android.app.Activity", lp.classLoader, "onResume", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        sTopAct = (android.app.Activity) p.thisObject;
                    } catch (Throwable ignored) {
                    }
                }
            });
            note("OK   Activity#onResume（自动分享定位）");
        } catch (Throwable t) {
            note("FAIL Activity#onResume（自动分享定位） -> " + t);
        }
        { if (true) { startNewFlow(); return; } }
        try {
            final android.os.Handler h = new android.os.Handler(android.os.Looper.getMainLooper());
            h.postDelayed(new Runnable() {
                public void run() {
                    try {
                        if (!"1".equals(conf().get("autoShare"))) {
                            return;
                        }
                        android.app.Activity a = sTopAct;
                        if (a == null) {
                            log("自动分享：没有前台 Activity，跳过");
                            return;
                        }
                        log("自动分享：开始，点底部「发现」");
                        h.postDelayed(new Runnable() {
                            public void run() {
                                tapStep(347, 2506, "发现");
                            }
                        }, 1000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                tapStep(322, 1096, "帖子");
                            }
                        }, 8000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                tapStep(737, 2452, "分享");
                            }
                        }, 16000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                tapStep(456, 1877, "微信");
                            }
                        }, 20000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                backToNinebot();
                            }
                        }, 22000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                backToNinebot();
                            }
                        }, 27000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                tapStep(1050, 2520, "我的");
                            }
                        }, 32000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                tapStep(625, 1927, "任务中心");
                            }
                        }, 36000);
                        h.postDelayed(new Runnable() {
                            public void run() {
                                tapStep(514, 808, "成长任务");
                            }
                        }, 47000);
                    } catch (Throwable t) {
                        log("自动分享失败：" + t);
                    }
                }
            }, 7000);
        } catch (Throwable ignored) {
        }
    }

    private static void backToNinebot() {
        try {
            android.content.Context ctx = null;
            try {
                ctx = (android.content.Context) XposedHelpers.callStaticMethod(
                        XposedHelpers.findClass("android.app.AndroidAppHelper", null),
                        "currentApplication");
            } catch (Throwable ignored) {
            }
            if (ctx == null) {
                android.app.Activity a0 = sTopAct;
                ctx = a0;
            }
            if (ctx == null) {
                log("自动分享：拉回九号失败（拿不到 Context）");
                return;
            }
            android.content.Intent i = ctx.getPackageManager()
                    .getLaunchIntentForPackage("cn.ninebot.ninebot");
            if (i == null) {
                log("自动分享：拉回九号失败（launch intent 为空）");
                return;
            }
            i.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                    | android.content.Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED);
            ctx.startActivity(i);
            log("自动分享：已把九号拉回前台");
        } catch (Throwable t) {
            log("自动分享：拉回九号失败 " + t);
        }
    }

    private static void tapStep(final int x, final int y, final String tag) {
        try {
            final android.app.Activity a = sTopAct;
            if (a == null) {
                log("自动分享：点" + tag + " 时没有前台 Activity");
                return;
            }
            final android.view.View dv = a.getWindow().getDecorView();
            long t = android.os.SystemClock.uptimeMillis();
            final android.view.MotionEvent d = android.view.MotionEvent.obtain(t, t,
                    android.view.MotionEvent.ACTION_DOWN, x, y, 0);
            final android.view.MotionEvent u = android.view.MotionEvent.obtain(t, t + 90,
                    android.view.MotionEvent.ACTION_UP, x, y, 0);
            d.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);
            u.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);
            boolean ok = dv.dispatchTouchEvent(d);
            dv.postDelayed(new Runnable() {
                public void run() {
                    dv.dispatchTouchEvent(u);
                }
            }, 90);
            log("自动分享：点" + tag + " (" + x + "," + y + ") => " + ok);
        } catch (Throwable t) {
            log("自动分享：点" + tag + " 失败 " + t);
        }
    }

    static volatile String sUid, sDeviceId, sClientVer, sPlatformVer, sRegionx, sLoginCountry;

    static String hdr(Object req, String name) {
        try {
            Object hdrs = XposedHelpers.callMethod(req, "headers");
            Object v = XposedHelpers.callMethod(hdrs, "get", name);
            return v == null ? null : String.valueOf(v);
        } catch (Throwable t) {
            return null;
        }
    }

    static String nz(String s, String d) {
        return s == null || s.isEmpty() ? d : s;
    }

    static byte[] readAllStream(java.io.InputStream is) throws java.io.IOException {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) > 0) {
            bo.write(buf, 0, n);
        }
        is.close();
        return bo.toByteArray();
    }
static String diagPost(String url, String body, String ctype) {
        try {
            java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            c.setRequestMethod("POST");
            c.setRequestProperty("Platform", "Android");
            c.setRequestProperty("Platform-Ver", nz(sPlatformVer, "16"));
            c.setRequestProperty("Client-Ver", nz(sClientVer, "610114116"));
            c.setRequestProperty("Service-Time", String.valueOf(System.currentTimeMillis()));
            c.setRequestProperty("Language", "zh");
            c.setRequestProperty("Sys-Language", "zh-cn");
            c.setRequestProperty("Request-Id", java.util.UUID.randomUUID().toString().replace("-", ""));
            c.setRequestProperty("Business-Type", "1");
            c.setRequestProperty("Regionx", nz(sRegionx, "bj"));
            c.setRequestProperty("Login-Country", nz(sLoginCountry, "CN"));
            c.setRequestProperty("Uid", nz(sUid, ""));
            c.setRequestProperty("Device-Id", nz(sDeviceId, ""));
            c.setRequestProperty("Content-Type", ctype);
            c.setRequestProperty("Accept", "application/json");
            byte[] b = body.getBytes("UTF-8");
            c.setDoOutput(true);
            c.setFixedLengthStreamingMode(b.length);
            java.io.OutputStream os = c.getOutputStream();
            os.write(b);
            os.flush();
            os.close();
            int code = c.getResponseCode();
            java.io.InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
            String r = is == null ? "" : new String(readAllStream(is), "UTF-8");
            return code + " " + (r.length() > 500 ? r.substring(0, 500) : r);
        } catch (Throwable t) {
            return "ERR " + t;
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
