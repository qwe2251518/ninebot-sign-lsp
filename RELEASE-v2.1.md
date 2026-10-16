# 酷安发布文案 v2.1（短版，可直接复制）

## 标题

九号自动签到 v2.1｜去掉动能回收，包里更干净

## 正文

九号出行的 LSPosed 模块，**打开 App 就自动签到**，不用抓 token、不用挂脚本。

v2.1 变化：

- **去掉了「动能回收」车控功能**：绕过九号自己的设置页直接改车上寄存器，本来就不保证能用、也有风险，这一版整条链路都删掉了
- 自动签到、换主页电动车图片、设置界面都和 v2.0 一样，改完即存
- 包体更小：86 KB（v2.0 是 91 KB）

安装：装 APK → LSPosed 里启用 → 作用域只勾「九号出行」→ 强杀一次九号，完事。

- 适配九号出行 6.10.11，更高版本一般也能用
- 日志：`Android/data/cn.ninebot.ninebot/files/ninebot-sign.log`
- 风险自负，卸载即还原原样
- 开源：github.com/qwe2251518/ninebot-sign-lsp

## 配套

- versionName `2.1` / versionCode `210`，包名 `com.ninebotsign.lsp`
- APK：`NinebotSign.apk`
