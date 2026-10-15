package com.ninebotsign.lsp;

import java.util.Map;

/**
 * 「设置界面 → ninebot-sign.conf」的文本生成。
 *
 * 单独一个类、而且**不引用 android.* 与 Xposed 的任何东西**是有原因的：
 * SettingsActivity 跑在模块自己的进程里，而 Xposed API（api-82.jar）只在编译期提供、
 * 不会打进 APK —— 只要在那个进程里碰 SignHook 就会
 * NoClassDefFoundError: Failed resolution of: Lcom/ninebotsign/lsp/SignHook; 直接闪退
 * （2026-10-15 真机日志，触发点 SettingsActivity.save → SignHook.uiConfText）。
 * 所以纯文本逻辑放这里，设置界面与注入端共用；PC 上的离线探针也直接编它。
 */
public final class ConfText {

    /** 带这行表头就表示文件由设置界面接管：界面每次保存都会整份重写 */
    public static final String HEADER = "# 由「九号自动签到」设置界面生成；想手动改配置就先删掉这一行";

    private ConfText() {
    }

    /** 把界面上的那份配置 Map 拼成配置文件全文 */
    public static String build(Map<String, String> m) {
        StringBuilder sb = new StringBuilder();
        sb.append(HEADER).append('\n');
        // 自动签到总开关：界面没写过这个键时按「开」处理（老配置兼容）
        String se = nz(m.get("signEnabled"));
        sb.append("signEnabled=").append(se.length() == 0 ? "1" : (on(se) ? "1" : "0")).append('\n');
        if (on(m.get("vehicleImage"))) {
            sb.append("vehicleImage=1\n");
            String p = nz(m.get("vehicleImagePath"));
            if (p.length() > 0 && !"vehicle.png".equals(p)) {
                sb.append("vehicleImagePath=").append(p).append('\n');
            }
            // 相册里选的那张图：图存在设置界面自己的私有目录，注入进程按这个「戳」走内容提供者
            // 取回来。戳变了（换了图）文件名就跟着变，Glide 的缓存 key 自然换新，不会拿到旧图。
            String st = nz(m.get("vehicleImageStamp"));
            if (st.length() > 0) {
                sb.append("vehicleImageStamp=").append(st).append('\n');
            }
        } else {
            sb.append("vehicleImage=0\n");
        }
        // 动能回收（车控）：off / weak / standard —— 注入端据此读-改-写 rFunBool 的低 2 位
        // （云配置里 0=关闭、1=弱、2=标准）。留空表示「模块不管这项」。
        String en = nz(m.get("venergy"));
        if (en.length() > 0) {
            sb.append("venergy=").append(en).append('\n');
        }
        return sb.toString();
    }

    /** 开关值：1/true/on 为开 */
    public static boolean on(String v) {
        if (v == null) {
            return false;
        }
        v = v.trim();
        return "1".equals(v) || "true".equalsIgnoreCase(v) || "on".equalsIgnoreCase(v);
    }

    /** 单行值：去掉首尾空白，换行会把 key=value 的格式撑破，直接拍掉 */
    public static String nz(String v) {
        if (v == null) {
            return "";
        }
        v = v.trim();
        if (v.indexOf('\n') < 0 && v.indexOf('\r') < 0) {
            return v;
        }
        return v.replace("\r", "").replace("\n", "");
    }
}
