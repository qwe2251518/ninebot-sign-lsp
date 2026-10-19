package com.ninebotsign.lsp;

import java.util.Map;

public final class ConfText {

    public static final String HEADER = "# 由「九号自动签到」设置界面生成；想手动改配置就先删掉这一行";

    private ConfText() {
    }

    public static String build(Map<String, String> m) {
        StringBuilder sb = new StringBuilder();
        sb.append(HEADER).append('\n');

        String se = nz(m.get("signEnabled"));
        sb.append("signEnabled=").append(se.length() == 0 ? "1" : (on(se) ? "1" : "0")).append('\n');
        if (on(m.get("vehicleImage"))) {
            sb.append("vehicleImage=1\n");
            String p = nz(m.get("vehicleImagePath"));
            if (p.length() > 0 && !"vehicle.png".equals(p)) {
                sb.append("vehicleImagePath=").append(p).append('\n');
            }

            String st = nz(m.get("vehicleImageStamp"));
            if (st.length() > 0) {
                sb.append("vehicleImageStamp=").append(st).append('\n');
            }
        } else {
            sb.append("vehicleImage=0\n");
        }

        String nv = nz(m.get("vnitro"));
        if (nv.length() > 0) {
            sb.append("vnitro=").append(nv).append('\n');
        }

        String so = nz(m.get("showEnergyOff"));
        if (so.length() > 0) {
        }
        String sn = nz(m.get("showNitro"));
        if (sn.length() > 0) {
        }


        sb.append("fakeExpiry=").append(on(m.get("fakeExpiry")) ? "1" : "0").append('\n');

        sb.append("autoShare=").append(on(m.get("autoShare")) ? "1" : "0").append('\n');
        sb.append("fakeShare=").append(on(m.get("fakeShare")) ? "1" : "0").append('\n');
        String pid0 = m.get("postId");
        sb.append("postId=").append(pid0 == null || pid0.trim().length() == 0 ? "22716571" : pid0.trim()).append('\n');
        return sb.toString();
    }

    public static boolean on(String v) {
        if (v == null) {
            return false;
        }
        v = v.trim();
        return "1".equals(v) || "true".equalsIgnoreCase(v) || "on".equalsIgnoreCase(v);
    }

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
