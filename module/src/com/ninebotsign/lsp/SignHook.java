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

/**
 * 九号出行（cn.ninebot.ninebot）自动签到模块。
 *
 * 形态 B：打开 app 时自动签到。签到接口本身不在 APK 的原生代码里（已用自写 DEX 解析器
 * 全量核对：22 个 dex / 91.5 万条字符串 / 82,059 个类中不存在 user-sign、portal/api、
 * consecutiveDays 等任何签到痕迹；签到页是 H5/RN 远端页面），所以模块采用
 * 「进程内捕获凭据 -> 自己发请求」的做法：
 *
 *   1. 捕获 deviceId（BodyParametersProvider / NbHttpClient#setDeviceId）
 *   2. 捕获 token（NbHttpClient#setToken、CommonModule#syncToken 的 access_token）
 *   3. 捕获 app 真实使用的 Authorization（TokenInterceptor#intercept 里读请求头）
 *   4. 捕获 H5 的 JWT 载体（NbHttpClient#getH5BaseJwtUrl、NbH5UrlHelper#getJwtWholeUrl）
 *   5. 凭据齐了就把候选 Authorization 逐个拿去打签到接口，谁返回 code==0 就用谁
 *
 * 签到接口来自第三方开源脚本（waistu/Ninebot）：
 *   POST https://cn-cbu-gateway.ninebot.com/portal/api/user-sign/v2/sign
 *   body {"deviceId":"<deviceId>"}
 *   header 需要 Authorization / deviceId / language: zh / Origin+Referer: h5-bj.ninebot.com
 */
public class SignHook implements IXposedHookLoadPackage {

    static final String TAG = "NinebotSign: ";
    static final String PKG = "cn.ninebot.ninebot";

    static final String GW = "https://cn-cbu-gateway.ninebot.com";
    static final String URL_SIGN_V2 = GW + "/portal/api/user-sign/v2/sign";
    static final String URL_SIGN_V1 = GW + "/portal/api/user-sign/v1/sign";
    static final String URL_STATUS = GW + "/portal/api/user-sign/v2/status";

    /**
     * H5 页面的后端网关（assets/Server.json 里的 web_url_v1 → production api5-h5-app-bj）。
     * 2026-10 实测：这个主机同样提供 /portal/api/user-sign/v2/sign（无效 token 返回
     * code 1 system.error，假路径返回 404 对照），而且 status 端点用 POST 打会返回
     * code 4 "method error" —— 说明路径真实且只收 GET。所以它是 v1/v2 都失败后的最后一张牌。
     */
    static final String GW_H5 = "https://api5-h5-app-bj.ninebot.com";

    /** 第三方脚本实测可用的 H5 客户端 UA */
    static final String UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Segway v6 C 609033420";

    // ---------------- 运行时捕获到的凭据 ----------------
    static volatile Context appCtx;
    static volatile boolean isMainProcess;
    static volatile boolean appStarted;

    static volatile String deviceId;    // BodyParametersProvider / NbHttpClient#setDeviceId
    static volatile String uid;         // BodyParametersProvider#setUid

    static volatile String token;       // NbHttpClient#setToken（原生层保存的 access_token）
    static volatile String rnToken;     // CommonModule#syncToken 传给 RN 的 access_token
    static volatile String passportToken; // PassportApiClient#getAccessToken / saveToken（护照层 access_token）
    static volatile String authHeader;  // RealInterceptorChain#proceed 读到的「最终」Authorization
    static volatile String gwAuthHeader; // 同上，但只取目标是 ninebot 域名的请求（最贴近网关口径）

    static volatile String jwtBase;     // NbHttpClient#getH5BaseJwtUrl 返回值
    static volatile String jwtWhole;    // NbH5UrlHelper#getJwtWholeUrl 返回值
    static volatile String webUrl;      // WebView#loadUrl 打开的 H5 页面地址（含签到页）
    static final Set<String> seenWebUrls = new LinkedHashSet<String>();

    /** 当前前台 Activity 名（图片诊断用：判断这条图片是不是主页加载的） */
    static volatile String curActivity = "?";
    /** 图片诊断去重集合与总量上限（诊断用，不能把日志刷爆） */
    static final Set<String> seenImages = new LinkedHashSet<String>();
    static final int IMG_LOG_MAX = 300;

    // ---- 主页车辆图替换（第八轮第二步）----
    /** 车辆图 URL 的特征：Glide 从 oms-oss-public 的 device-config 拉车型图 */
    static final String VEH_IMG_KEY = "device-config";
    /** 配置文件里的开关 / 图片绝对路径（每 5 秒最多重读一次，改完不用重启 app） */
    static volatile boolean vehImgOn = false;
    static volatile String vehImgPath = null;
    static volatile long vehConfAt = 0L;
    /** 配置里写的源图路径；真正喂给 Glide 的是按内容命名的副本，见 effectiveVehPath */
    static volatile String vehSrcPath = null;

    /** 是否正有一次签到在跑（避免并发重复请求） */
    static final AtomicBoolean inFlight = new AtomicBoolean(false);
    /** 上次发起签到的毫秒时刻，用于限速（避免每次 onResume 都真的打接口） */
    static volatile long lastAttemptAt = 0L;
    /** 今天已确认「无需签到」，只提示/记录一次 */
    static volatile boolean quietToday = false;

    static final Set<String> hookLog = new LinkedHashSet<String>();

    // =========================================================================
    // 入口
    // =========================================================================
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

        // ---- deviceId / uid ----
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

        // ---- token ----
        hook(lp, "cn.ninebot.commonlibs.nbnet.NbHttpClient", "setToken",
                new Arg0Saver(new Sink() {
                    public void put(String v) { token = v; }
                }, "token(NbHttpClient#setToken)"));

        // ---- 护照层 token ----
        // PassportApiClient 内部有 accessToken/refreshToken 两个字段，getAccessToken() 是唯一的
        // 读取口（方法体里引用字符串常量 "access_token"），saveToken(String,String) 是写入口
        // （args[0] 就是 access_token）。generateAuthorizationHeaders(String, Map) 方法体里只引用
        // 了常量 "Authorization"，也就是说它把传进来的字符串**原样**放进请求头，九号自己的代码
        // 不加 "Bearer " 前缀（整个 APK 里 "Bearer " 只出现在华为 AGC SDK 里）。
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
                            // RN 没传 access_token 时会抛 NoSuchKey，属正常
                        }
                        maybeSign();
                    }
                });

        // ---- 出网请求真身：okhttp 的 RealInterceptorChain#proceed(Request) ----
        // 这是「请求头已经拼完、马上就要发出去」的那一刻，能直接读到最终 Authorization。
        // 比拦截单个 Interceptor 可靠：TokenInterceptor 是 newBuilder().header(...) 之后才
        // proceed 的，在它自己的 afterHookedMethod 里读 chain.request() 拿到的是「改之前的」
        // 原始请求，通常根本没有 Authorization。
        hook(lp, "okhttp3.internal.http.RealInterceptorChain", "proceed",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        try {
                            Object req = p.args[0];
                            Object h = XposedHelpers.callMethod(req, "header", "Authorization");
                            if (h instanceof String && ((String) h).length() > 0) {
                                String s = (String) h;
                                // 宿主里还跑着微信/QQ/微博/华为 AGC 这些 SDK，它们各自的
                                // Authorization（甚至 Bearer xxx）不是我们要的。只认目标是
                                // ninebot 域名的那份 —— 它跟签到走的同一个网关，口径最接近。
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

        // ---- 护照层自己生成的 Authorization（generateAuthorizationHeaders 返回 Map）----
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

        // ---- app 真实使用的 Authorization（最可靠的一手凭据）----
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

        // ---- H5 JWT 载体 ----
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

        // ---- H5 JS Bridge：用来发现签到页真正的接口路径（诊断用）----
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

        // ---- WebView 打开的 H5 页面地址 ----
        // 用户点开「签到」页时，这里能直接把那个页面的 URL 打出来。
        // 拿到 URL 就能在电脑上把那个页面的 JS 抓下来读，从而知道它到底调了哪个接口、
        // 怎么解析响应 —— 这是把「抄来的接口」换成「app 自己用的接口」的最短路径。
        // 只记前 15 个不同的 URL（不然每次 H5 跳转都写一行，日志会被刷爆）。
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

        // ---- hook 安装汇总 ----
        // 一次真机运行就能看出有没有哪个目标没挂上：九号版本一变/加固一换，
        // 这里会立刻变成 FAIL，而不是让模块静悄悄地什么都不做。
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

    /**
     * 拿到 Application 上下文，用于 Toast 与写日志文件；
     * 顺便挂一个延迟自检，hook 全部落空时能立刻从日志看出来。
     */
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

    /**
     * 形态 B 的关键：**每次「打开 app」都要有机会签到**，而不只是冷启动那一次。
     *
     * 只挂 Instrumentation#callApplicationOnCreate 的话，进程是从冷启动起来的才会触发；
     * 用户从后台切回来（暖启动）时什么都不会发生 —— 那就不是「每次打开 app 自动签到」了。
     * 所以再挂 Activity 的生命周期：每次有页面回到前台就试一次，由 maybeSign() 里的
     * 「当日已签到文件 + 120 秒限速」保证不会重复打接口。
     */
    private void hookLifecycle(final XC_LoadPackage.LoadPackageParam lp) {
        // Activity 回到前台 -> 再武装一次
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

        // Application#onCreate：万一 callApplicationOnCreate 没挂上，这里兜住上下文
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

    /** 当前进程名（读 /proc/self/cmdline），只为让日志能自证「这条来自哪个进程」 */
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

    // =========================================================================
    // 触发签到
    // =========================================================================
    /** 同一进程内两次真正尝试之间的最小间隔：失败后重开 app 会重试，但不会刷接口 */
    static final long RETRY_INTERVAL_MS = 120000L;

    static void maybeSign() {
        // 设置界面存下的配置优先落盘（写成九号那边的 ninebot-sign.conf），
        // 必须在下面任何读配置的动作之前；没保存过就什么都不做。
        syncUiConf();
        // 设置界面里的「自动签到」开关（配置文件的 signEnabled，缺省为开）
        if (!confOn("signEnabled", true)) {
            if (!signOffLogged) {
                signOffLogged = true;
                log("设置里关掉了自动签到，本轮不签");
            }
            return;
        }
        // 不限制进程：九号 app 有多个进程，凭据在哪个进程里初始化不确定。
        // 重复签到请求是无害的（接口幂等），而「因为跑错进程所以啥也不干」是致命的。
        if (deviceId == null || deviceId.length() == 0) {
            return;
        }
        if (token == null && authHeader == null && rnToken == null && passportToken == null) {
            return;
        }
        // 先做便宜的检查，最后才碰文件（onResume 是主线程调过来的）
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

            // 先查状态：确认「今天就别签了」就收工。
            // 只在响应明确可解析（HTTP 200 且 code==0 且 currentSignStatus==1）时才跳过，
            // 解析不出来就照签不误 —— 宁可多签一次，不可误判漏签。
            // 凭据优先级：真机日志（2026-10-14）证实「原生 setToken 抓到的裸 token」能让 status
            // 返回 code 0，所以它排第一；其余按可能性依次垫后。
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

            // 真机日志结论（2026-10-14）：同一个裸 token，不带前缀时 status 返 code 0、
            // v2/sign 返 540004「already signed in」；加上 "Bearer " 之后变成 code 1 系统错误。
            // 所以把所有裸 token 排在前面、Bearer 变体垫底：既不浪费请求，也不会让 Bearer 的
            // 失败把真结果盖住。
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
                    // 别把网关当靶子打：两次尝试之间缓一下，避免被限流误判成失败
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
                    // 服务端明说了「今天签过了」：这不是失败，别误报
                    log("服务端判定今日已签到（原文见上），按已签到处理");
                    markOkToday();
                    toast("九号签到：今日已签到");
                    return;
                }
            }

            String first = ordered.get(0);

            // v2 全失败，试老版本端点（老 app 走 v1）
            sleepQuiet(350);
            Resp r1 = http("POST", URL_SIGN_V1, json, first);
            log("v1 <- " + mask(first) + " : HTTP " + r1.httpCode + " | "
                    + explain(r1.body) + " | " + clip(r1.body, 400));
            if (respCode(r1.body) == 0) {
                report(true, r1.body, first);
                return;
            }

            // 还不行，换 H5 后端的网关再来一次（实测该主机同样提供这个接口）
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
                // 奖励读的是签到页自己 JS 用的真字段 data.rewardList[]（一手证据），
                // 早先按第三方脚本猜的 currency/nb/coin… 全是错的，已删除。
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

    // =========================================================================
    // 候选凭据
    // =========================================================================
    interface Sink {
        void put(String v);
    }

    /** 当前抓到的全部候选凭据（裸 token 与 Bearer 变体都在里面，顺序不保证） */
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

    /** 从带 JWT 的 URL 里把疑似 token 的查询参数抠出来 */
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

    // =========================================================================
    // HTTP
    // =========================================================================
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
            // device_id（下划线）是签到页自己的 JS 用的请求头名，deviceId（驼峰）是第三方
            // 脚本用的。两个都发，谁读都行 —— 见 README「一手证据」一节。
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

    // =========================================================================
    // 响应解析
    // =========================================================================
    static int respCode(String body) {
        try {
            return new JSONObject(body).optInt("code", -999);
        } catch (Throwable t) {
            return -999;
        }
    }

    /**
     * 解读网关响应的失败签名。下面这几条是用**无效 token 直接打线上网关**实测出来的
     * （2026-10，POST/GET 同一个 user-sign 端点 + 一个故意写错的路径做对照）：
     *
     *   {"code":2,"key":"response.params.error"}   带了 Authorization 但结构不被接受 / 缺参数
     *   {"code":1,"key":"response.system.error"}   凭据被服务器拒绝（真的走到了鉴权那一步）
     *   {"status":404,"error":"Not Found",...}     接口路径不存在（对照组的签名）
     *   code == 0                                  成功
     *
     * 关键的一条：**别把 code 2 说成「走得更远」。** 早先一轮用带两个点的假 JWT 做前缀对照，
     * 观察到裸 token 得 code 2、加 "Bearer " 得 code 1，当时解读成「裸 token 进到了参数校验」。
     * 后来用本文件这套代码（probe/HttpProbe.java）拿 probe-invalid-token 复跑，**两种写法都是
     * code 1**，差异复现不出来。而 params.error 更像参数/结构校验没过（通常发生在鉴权之前），
     * 所以那个「更远」的解读很可能一开始就是反的。结论：这个网关认哪种格式无法判定，
     * 模块对每个 token 都同时试裸版和 Bearer 版，谁 code==0 用谁。
     */
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
        // 下面两个码是签到页自己的 JS 里写死的分支（一手证据）：
        //   540004 —— 今日已签到（app 自己也是直接 return，当作正常）
        //   54019  —— 会话失效（app 的做法是 location.reload() 重新取 token）
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

    /**
     * 从签到/补签响应里读出真实奖励，拼成一句人话。
     *
     * 字段来自**签到页自己的 JS 代码**（一手证据，不是第三方脚本）：成功响应
     * data.rewardList[] = { rewardId, name, type, rewardType, rewardValue, medalName, medalUrl }
     * rewardType：1=经验值 2=N币(用 rewardValue) 3=勋章(用 medalName) 4=补签卡 5=商城兑换券
     * 签到页的弹窗就是对 rewardList 逐项 switch 显示这几种。
     */
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

    // =========================================================================
    // 当日去重
    // =========================================================================
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

    // =========================================================================
    // 图片诊断（给「自定义主页车辆图片」定位 hook 点用，不影响签到）
    // =========================================================================

    /**
     * 把 app 加载图片的调用记下来，回答一个静态分析答不了的问题：
     * **主页那张电动车图到底是谁加载的、从哪儿来的？**
     *
     * - 原生图片栈是 Glide（RequestBuilder#load 的所有重载）
     * - RN / Drawee 用 Fresco（SimpleDraweeView#setImageURI、ReactImageView#setSource）
     * - 再兜一层 ImageView#setImageResource / setImageBitmap / setImageDrawable：
     *   这两条能直接打出「哪个 view、哪个资源名」，是辨认主页那张图最有力的证据
     *
     * 每条（来源 + 值 + view）只记一次，总量上限 IMG_LOG_MAX，避免刷爆日志。
     * 如果主页那张图是 H5/WebView 里画的，这里什么都看不到 —— 那就说明得换思路。
     */
    private void hookImageDiag(final XC_LoadPackage.LoadPackageParam lp) {
        // 1) Glide：原生图片加载的入口
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
                        // 只把字符串换成 file://：参数类型不变（还是 String），Glide 会走本地文件加载
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

        // 2) Fresco / Drawee：RN 与部分原生控件用它
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

        // 3) RN 的 <Image>：它自己管 Fresco，不走上面的 setImageURI
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

        // 4) ImageView 层：直接打「view 名 + 资源名」
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

    /** 是不是主页那张车型图（Glide 从 device-config 拉的那张） */
    static boolean isVehicleImage(String s) {
        if (s == null || s.indexOf(VEH_IMG_KEY) < 0) {
            return false;
        }
        return s.indexOf("/category/") >= 0
                || s.indexOf(".png") >= 0
                || s.indexOf(".webp") >= 0
                || s.indexOf(".jpg") >= 0;
    }

    /**
     * 读「主页车辆图替换」配置，最多 5 秒重读一次（改完配置不用重启 app）。
     *
     * 配置文件 = app 私有目录下的 `ninebot-sign.conf`：
     *   vehicleImage=1                     开关（1/true/on 为开，其它为关）
     *   vehicleImagePath=/sdcard/…/x.png   图片绝对路径（缺省 = 同目录 vehicle.png）
     * 紧急关闭：同目录建一个名为 `vehicle-image-off` 的文件即可（无需改配置）。
     */
    static boolean vehImgEnabled() {
        long now = System.currentTimeMillis();
        if (now - vehConfAt > 5000L) {
            vehConfAt = now;
            boolean on = false;
            String path = null;
            String stamp = null;
            try {
                // 配置走 conf()（ninebot-sign.conf + 设置界面两条通道叠加）。只读文件是不行的：
                // 真机上 ninebot-sign.conf 根本写不进去（open failed: EACCES），开关永远是「关」——
                // 这就是 2026-10-15 19:42 日志里「车辆图配置：开关=关」的来由。
                Map<String, String> c = conf();
                on = confOn("vehicleImage", false);
                path = c.get("vehicleImagePath");
                stamp = c.get("vehicleImageStamp");
                File dir = dataDir();
                if (dir != null && new File(dir, "vehicle-image-off").exists()) {
                    on = false;   // 紧急关闭：建个同名文件即可，不用改配置
                }
                if (path == null || path.length() == 0) {
                    path = dir == null ? null : new File(dir, "vehicle.png").getAbsolutePath();
                }
            } catch (Throwable t) {
                log("读 vehicle 配置失败: " + t);
            }
            // 相册选的图优先（走内容提供者），其次才是手工路径
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

    /**
     * 相册选的图：从设置界面的内容提供者读回来，落到九号自己的私有目录。
     *
     * <p>文件名里带「戳」，戳变了就是换了图 —— 既是 Glide 的缓存 key（不换名字它会拿旧图，
     * 与 effectiveVehPath 同一个道理），也顺手把上一张的副本删掉。
     */
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

    /** 手工填的路径：同样复制进九号私有目录并按内容命名（外部路径注入进程多半读不到） */
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

    /**
     * 把源图复制成一个**按内容命名**的副本，再把副本路径喂给 Glide。
     *
     * 为什么必须这么做：Glide 的内存/磁盘缓存是按 model 算 key 的。源路径固定是 `vehicle.png` 时，
     * 就算你把文件换成第二张图，Glide 仍会命中第一张图的解码结果（现象：换了图还是旧的，开关
     * 关了再开也一样）。换个文件名（长度 + 修改时间）就等于换了 key，它才会重新解码。
     */
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

    /** app 私有目录（外部 files 优先，和日志同处） */
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

    /** 记一条图片加载；同一条只记一次，总量到顶就停 */
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

    // =========================================================================
    // 设置界面（SettingsActivity）→ 九号那边的配置文件
    // =========================================================================
    // 界面把配置写进模块自己的 SharedPreferences（name=PREF）；注入进九号进程后由
    // 这里把它落成 <九号数据目录>/ninebot-sign.conf，之后一切照旧读这个文件。
    // 绕这一圈的原因：Android 11+ 一个应用写不了别的应用的 Android/data，
    // 只有注入进九号进程的代码（就是这里）写得进去。
    static final String PREF = "ninebot_sign";
    /** 带这行表头就表示文件由设置界面接管：界面每次保存都会整份重写 */
    static final String CONF_HEADER = "# 由「九号自动签到」设置界面生成；想手动改配置就先删掉这一行";
    static volatile long uiConfAt = 0L;

    // ---- 读 ninebot-sign.conf（设置界面或手改都在这里）----
    static volatile long confAt = 0L;
    static volatile Map<String, String> confMap = null;
    /** 「设置里关掉了自动签到」只提示一次，避免每次回前台都刷日志 */
    static volatile boolean signOffLogged = false;

    /** 读配置文件的键值（5 秒缓存，读不到就给空表） */
    static Map<String, String> conf() {
        long now = System.currentTimeMillis();
        Map<String, String> cached = confMap;
        if (cached != null && now - confAt <= 5000L) {
            return cached;
        }
        Map<String, String> out = new LinkedHashMap<String, String>();
        // 1) 手改 / 老版本留下的 ninebot-sign.conf（能读到才合并）
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
        // 2) 设置界面盖在上面（优先级更高）。真机 Android 11+ 上 ninebot-sign.conf 常常
        //    写不进去（open failed: EACCES），所以不能只靠文件，直接读进程内能拿到的界面设置。
        Map<String, String> ui = uiConfMap();
        if (ui != null) {
            out.putAll(ui);
        }
        confMap = out;
        confAt = now;
        return out;
    }

    /** 把一行 key=value（或注释/空行）并进 out；null 安全 */
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

    /** 配置里的开关：1/true/on 为开，0/false/off 为关，没写就用默认值 */
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

    /** 界面的键值对 → 配置文件内容（纯函数，离线可测） */
    /**
     * 配置文件全文。真正的拼装逻辑在 {@link ConfText} 里：设置界面跑在模块自己的进程，
     * 那里没有 Xposed API，碰 SignHook 会 NoClassDefFoundError，所以两边共用纯文本类。
     */
    static String uiConfText(Map<String, String> m) {
        return ConfText.build(m);
    }

    /** 读设置界面写下的 SharedPreferences（LSPosed 的 XSharedPreferences）；没用过界面返回 null */
    static Map<String, String> uiPrefs() {
        try {
            de.robv.android.xposed.XSharedPreferences p =
                    new de.robv.android.xposed.XSharedPreferences("com.ninebotsign.lsp", PREF);
            p.reload();
            if (!"1".equals(p.getString("ui", ""))) {
                return null;
            }
            String[] keys = {"signEnabled", "vehicleImage", "vehicleImagePath",
                    "venergy"};
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

    /** 把界面设置全文解析成 key=value map（provider 返回的文本） */
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

    /** 界面的键值：优先内容提供者，其次 XSharedPreferences；读不到返回 null */
    static Map<String, String> uiConfMap() {
        String text = providerConfText();
        if (text != null) {
            return parseConfText(text);
        }
        return uiPrefs();
    }

    /** 内容提供者通道：模块 App 里的 ConfProvider 直接把配置全文给过来 */
    static String providerConfText() {
        // Android 11+ 上九号（targetSdk 34）看不到我们模块 App 的包，AMS 会直接拒绝：
        //   IllegalArgumentException: Unknown authority com.ninebotsign.lsp.conf
        // 真机上量过：adb shell 走 content call 拿得到，九号进程里拿不到 —— 这是包可见性
        // 限制（九号没声明 <queries>），改我们的代码绕不过去。失败三次就认，十分钟内不再
        // 试，改用 XSharedPreferences 那条通道（那条是好的）。
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

    /** 「读不到界面设置」这种话不要每 5 秒刷一遍 */
    static void logUiWarn(String s) {
        long now = System.currentTimeMillis();
        if (now - uiWarnAt < 60000L) {
            return;
        }
        uiWarnAt = now;
        log(s);
    }

    /** 每 5 秒最多一次：把界面设置落成 ninebot-sign.conf（内容没变就不写） */
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
            // 老版本或手动留下来的 ninebot-sign.conf 可能是 root:root 644（真机上就是，
            // 所以每次覆盖都 EACCES）。目录是九号自己的，删掉重建即可。
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
                    + (text.contains("venergy=") ? "，动能回收=" + conf().get("venergy") : "") + "）");
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

    /** 取 JSON 里某个字符串字段（不依赖 org.json，方便在 PC 上用真源码跑探针） */
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

    /** 取 JSON 里某个整数字段（同样不依赖 org.json） */
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

    // =========================================================================
    // hook 工具
    // =========================================================================
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

    // =========================================================================
    // 云配置抄写（2026-10-15 加）
    // 九号的页面/命令/功能配置是云端按车型下发的 .nb 文件，内容是**加密**的（base64 密文，
    // 见 /sdcard/.../files/dyncfg 里抄出来的 code/*.nb）。只有 App 自己解得了，所以换个位置下手：
    // App 解密之后要用 Gson 把 JSON 解析成模型，这里盯 Gson#fromJson 的**入参字符串**，
    // 命中「页面配置 / 命令表 / 功能表」就整段抄到外部目录 dyncfg_out/，adb 直接 pull。
    // 顺带记一条 DynamicConfigManager#decryptNbFile 的请求日志（哪个页面在解密）。
    // =========================================================================
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

    // =========================================================================
    // 车控命令诊断（2026-10-15 加）
    // 背景：九号的命令表是云端按车型下发的 JSON（APK 里没有编译期命令号，见 _ninebot\vehicle_cmds.md），
    // 所以「限速 / 定速巡航 / 校准 / 电池」实际的 cmd+index 只能在运行时看。这里记三件事：
    //   ① DynamicCommandFactory.getCommandConfig(name) —— 名字 → s_cmd/s_index/s_data/r_cmd/r_index（每名字一次）
    //   ② CommandExecutorImpl.execute(Command)        —— 真正下发的 cmd/index/target/data
    //   ③ NbBluetoothDevice.onCharacteristicChanged    —— 原始上行帧
    // 三个 hook 全部走 log()（同时进文件与 logcat）；同一条命令只记一次，总条数封顶 CMD_LOG_MAX。
    // 这几个类只存在于九号 App 里，找不到就只记一行失败、不影响别的功能。
    // =========================================================================
    static final java.util.Set<String> cmdNames = new java.util.LinkedHashSet<String>();
    static final java.util.Set<String> cmdFrames = new java.util.LinkedHashSet<String>();
    static int cmdLogCount = 0;
    static final int CMD_LOG_MAX = 600;

    private void hookVehicleCmds(final XC_LoadPackage.LoadPackageParam lp) {
        hostCl = lp.classLoader;   // 拿宿主的类（模块自己的 Class.forName 看不到九号的类）
        // ① 名字 → 命令号
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
                            // 只要有任意一页问过一次命令，就把整张表倒出来（不用一页页点着找）
                            dumpCommandMapOnce(p.thisObject);
                        } catch (Throwable t) {
                        }
                    }
                });

        // ② 下发
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

        // ③ 上行
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

        // ④ UI 功能 → 命令名：命令名本身来自云端表，所以「哪个页面发了哪个名字」对任何机型都通用。
        //    注意包名是 ...dynamic.viewHolder.BtDynamicViewHolder（不是 ...dynamic.BtDynamicViewHolder）。
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

        // ⑤ 建命令（名字 + 载荷）
        hook(lp, "cn.ninebot.library.bluetooth.dynamic.DynamicCommandFactory", "createCommand",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        dumpNameArgs("建命令", p.args);
                    }
                });

        // ⑥ 这次握手走哪一代协议（回答「这台车是 Protocol1/2/3 还是 Encryption2/3」，按机型分代）
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

        // 顺带把云下发的动态配置（files/dynamic_config_new 里的 JSON）导到外部目录，
        // 「动能回收」这类设置项的取值列表、以及还有哪些功能，都写在这份配置里；adb 直接 pull 出来看。
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

        // 车控发送的应急通道（配置里写 vcmd/venergy 就能发命令，先验证链路再上界面）
        try {
            startVehicleCmdWatch();
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

    // 整表倒出来：DynamicCommandFactory 的私有实例字段 commandConfigMap 就是云端下发的那张全表，
    // 拿到实例（getCommandConfig 的 thisObject）后反射遍历一次即可，无需一页页点着找功能。
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

    // =========================================================================
    // 车控命令直发（2026-10-15 22:3x）：让模块能真正往车上发命令
    // 走九号自己的发送链路（见 _ninebot/send_api.md，静态分析 + 字节码验证）：
    //   DynamicConfigManager.Companion.getInstance() → connectedDeviceList.get(0)
    //   → DynamicDevice#sendCommand(String, byte[], boolean, Function1)
    // Function1 用动态代理塞自己的回调，把车上回来的值打进日志。
    // =========================================================================
    private static java.lang.reflect.Method mDevSendBytes;
    private static java.lang.Class<?> clsFunction1;
    private static boolean vcmdWatchStarted;
    /** 宿主的 ClassLoader：模块自己的 Class.forName 看不见九号的类，必须用它 */
    static ClassLoader hostCl;

    static Class<?> hostClass(String name) throws ClassNotFoundException {
        ClassLoader cl = hostCl;
        if (cl == null) {
            throw new ClassNotFoundException(name + "（宿主 ClassLoader 还没拿到）");
        }
        return Class.forName(name, false, cl);
    }

    /** 当前已连接的车（DynamicDevice 实例）；没连上返回 null */
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

    /** kotlin.jvm.functions.Function1 的动态代理：只把回调参数打进日志 */
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

    /** 发一条命令（data 为 null 表示读）。返回 true＝已交给九号的发送链路 */
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

    /** "0,0" / "0x02" 之类 → byte[]；空串返回 null */
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

    /** 从回调参数里抠出字节：byte[] 直接用；Command 之类反射 getData() */
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

    /**
     * 动能回收：先读 rFunBool（index 125 的两字节寄存器），再把低 2 位改成 mode，写回 setFunBool。
     * 云配置里「动能回收」= rFunBool 的 toInt,0,2（低 2 位），标准=2、弱=1、关闭=0。
     * 其余位是别的开关（坐垫感应 bit9、低电量延长续航 bit3…），所以必须读-改-写，不能整条覆盖。
     */
    static boolean setEnergyRecovery(final int mode) {
        final Object dev = connectedVehicle();
        if (dev == null) {
            log("车控：没有已连接的车，改不了动能回收");
            return false;
        }
        try {
            final Class<?> f1 = hostClass("kotlin.jvm.functions.Function1");
            Object cb = java.lang.reflect.Proxy.newProxyInstance(f1.getClassLoader(), new Class<?>[] { f1 },
                    new java.lang.reflect.InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, java.lang.reflect.Method m, Object[] a) {
                            try {
                                byte[] b = bytesOf(a == null || a.length == 0 ? null : a[0]);
                                if (b != null && b.length >= 2) {
                                    int cur = (b[0] & 0xFF) | ((b[1] & 0xFF) << 8);
                                    int next = (cur & ~0x0003) | (mode & 0x0003);
                                    log("车控：动能回收 读到当前=0x" + Integer.toHexString(cur)
                                            + " → 写回=0x" + Integer.toHexString(next) + "（目标 " + mode + "）");
                                    sendVehicleCmd("setFunBool",
                                            new byte[] { (byte) (next & 0xFF), (byte) ((next >> 8) & 0xFF) });
                                } else {
                                    log("车控：动能回收 读回来解析不了 "
                                            + describe(a == null || a.length == 0 ? null : a[0]));
                                }
                            } catch (Throwable t) {
                                log("车控：改动能回收失败 " + t);
                            }
                            return null;
                        }
                    });
            if (mDevSendBytes == null) {
                mDevSendBytes = dev.getClass().getMethod("sendCommand", String.class, byte[].class,
                        boolean.class, hostClass("kotlin.jvm.functions.Function1"));
            }
            mDevSendBytes.invoke(dev, "rFunBool", null, Boolean.FALSE, cb);
            log("车控：动能回收 先读 rFunBool（目标 " + mode + "：0关/1弱/2标准）");
            return true;
        } catch (Throwable t) {
            log("车控：动能回收 发读命令失败 " + t);
            return false;
        }
    }

    /**
     * 配置里的应急发送通道：`vcmd=setFunBool:2,0`（写）或 `vcmd=rFunBool`（读）；
     * `venergy=0|1|2|off|weak|standard` 直接改动能回收。值一变就执行一次 ——
     * 这样在没做界面之前也能手动验证发送链路。
     */
    static void startVehicleCmdWatch() {
        if (vcmdWatchStarted) {
            return;
        }
        vcmdWatchStarted = true;
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                String last = "";
                String lastE = "";
                Object lastDev = null;
                while (true) {
                    try {
                        Thread.sleep(1500);
                        Map<String, String> c = conf();
                        String v = c.get("vcmd");
                        v = v == null ? "" : v.trim();
                        if (v.length() > 0 && !v.equals(last)) {
                            last = v;
                            int sep = v.indexOf(':');
                            if (sep < 0) {
                                sep = v.indexOf('=');
                            }
                            String name = sep < 0 ? v : v.substring(0, sep).trim();
                            String arg = sep < 0 ? "" : v.substring(sep + 1).trim();
                            sendVehicleCmd(name, parseBytesArg(arg));
                        }
                        String e = c.get("venergy");
                        e = e == null ? "" : e.trim().toLowerCase();
                        // 换了一台已连接的车（重连/换车）就把「已下发」标记清掉，重发一次；
                        // 否则这个开关只在进程启动那一瞬间生效，用户改完看不到反应。
                        Object devNow = connectedVehicle();
                        if (devNow != null && devNow != lastDev) {
                            lastDev = devNow;
                            lastE = "";
                            log("车控：车已连接，准备下发动能回收设置");
                        }
                        if (e.length() > 0 && !e.equals(lastE)) {
                            lastE = e;
                            int mode = -1;
                            if ("off".equals(e) || "0".equals(e) || "close".equals(e)) {
                                mode = 0;
                            } else if ("weak".equals(e) || "1".equals(e)) {
                                mode = 1;
                            } else if ("standard".equals(e) || "2".equals(e)) {
                                mode = 2;
                            }
                            if (mode >= 0) {
                                setEnergyRecovery(mode);
                            }
                        }
                    } catch (Throwable t2) {
                    }
                }
            }
        }, "NinebotSign-vcmd");
        t.setDaemon(true);
        t.start();
        log("车控：应急发送通道已启动（vcmd=命令名:字节,字节 / venergy=0关|1弱|2标准）");
    }

    // =========================================================================
    // 日志 / 提示
    // =========================================================================
    static void note(String s) {
        hookLog.add(s);
    }

    static void log(String msg) {
        String line = TAG + msg;
        try {
            XposedBridge.log(line);
        } catch (Throwable t) {
        }
        // 同时丢一份到 logcat：这样在电脑上 `adb logcat -s NinebotSign` 就能看到模块自己的
        // 诊断，不用让用户去 LSPosed 里导日志（导日志一次要来回好几轮）
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

    // =========================================================================
    // 杂项
    // =========================================================================
    static String str(Object[] args, int i) {
        if (args == null || i >= args.length || args[i] == null) {
            return "null";
        }
        return String.valueOf(args[i]);
    }

    static String firstNonNull(String a, String b) {
        return a != null ? a : b;
    }

    /** 睡一会儿，被打断也不抛（这个方法多半跑在后台线程里） */
    static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (Throwable ignored) {
        }
    }

    /**
     * 从响应体里认出「今天已经签过了」。
     *
     * 判定今日是否已签原本有两条路：签到接口返回 code == 0（刚签成功），
     * 或者 status 接口返回 code == 0 且 data.currentSignStatus == 1（早先签过）。
     * 但 status 的字段名是从第三方脚本抄来的、没有官方文档，万一字段名变了，
     * 一条无害的重复签到会被误报成失败，用户就分不清到底坏没坏。
     * 所以这里加第三重兜底：响应原文里明确出现「已签到 / already / repeat」，
     * 就按已签到处理。匹配故意收得很窄，正常报错（参数错、凭据过期）不会误命中。
     */
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

    /** 把候选列表按尝试顺序打成一行，方便从日志判断「到底试了哪几个」 */
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
