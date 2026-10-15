# Ninebot auto-signin LSPosed module -- gradle-free build script.
# maven.google.com is unreachable on this machine (gradle cannot fetch AGP deps),
# so the APK is assembled by hand from build-tools (aapt2 / d8 / zipalign /
# apksigner) plus the JDK (javac / keytool).
#
# Output: <root>\NinebotSign.apk
# Key constraint: an Xposed module must ship a SINGLE classes.dex. AGP debug
# builds split into classes2.dex, which makes LSPosed skip injection. Building
# by hand keeps exactly one dex.

$ErrorActionPreference = 'Stop'

# 工具链目录：默认放在当前用户主目录下的 .ninebot-toolchain，
# 也可以用环境变量 NINEBOT_TOOLCHAIN 指到别处（避免把个人路径写进仓库）
$tc = $env:NINEBOT_TOOLCHAIN
if (-not $tc) { $tc = Join-Path $env:USERPROFILE '.ninebot-toolchain' }
$bt    = "$tc\buildtools\android-14"
$aj    = "$tc\platform\android-34\android.jar"
$apij  = "$tc\api-82.jar"
$root  = Split-Path -Parent $PSCommandPath
$mod   = "$root\module"
$build = "$root\build"
$ks    = "$root\debug.keystore"
$out   = "$root\NinebotSign.apk"

function Step($n, $msg) { Write-Host ""; Write-Host "== [$n] $msg" }
function Fail($msg) { Write-Host "!! $msg"; exit 1 }

# 工具链缺了就直接报错，别让 javac 抛出「程序包 android.app 不存在」这种看不懂的错
if (-not (Test-Path $aj)) { Fail "找不到 android.jar: $aj（用 NINEBOT_TOOLCHAIN 指到工具链目录）" }
if (-not (Test-Path $apij)) { Fail "找不到 api-82.jar: $apij" }
if (-not (Test-Path "$bt\aapt2.exe")) { Fail "找不到 aapt2: $bt\aapt2.exe" }

Step 1 "clean build dir"
if (Test-Path $build) { Remove-Item -Recurse -Force $build }
New-Item -ItemType Directory -Force -Path "$build\classes" | Out-Null
New-Item -ItemType Directory -Force -Path "$build\dex" | Out-Null

Step 2 "javac (source/target 8, cp = android.jar + api-82.jar)"
$srcs = @(Get-ChildItem "$mod\src" -Recurse -Filter *.java | ForEach-Object { $_.FullName })
Write-Host ("   sources: " + $srcs.Count)
& javac -source 8 -target 8 -encoding UTF-8 -nowarn -cp "$aj;$apij" -d "$build\classes" $srcs
if ($LASTEXITCODE -ne 0) { Fail "javac failed" }

Step 3 "d8 -> dex (--min-api 26)"
$classes = @(Get-ChildItem "$build\classes" -Recurse -Filter *.class | ForEach-Object { $_.FullName })
Write-Host ("   class files: " + $classes.Count)
& java -cp "$bt\lib\d8.jar" com.android.tools.r8.D8 --min-api 26 --lib "$aj" --output "$build\dex" $classes
if ($LASTEXITCODE -ne 0) { Fail "d8 failed" }

$dexs = @(Get-ChildItem "$build\dex" -Filter *.dex)
Write-Host ("   dex produced: " + (($dexs | ForEach-Object { $_.Name }) -join ', '))
if ($dexs.Count -ne 1 -or $dexs[0].Name -ne 'classes.dex') {
    Fail "an Xposed module needs exactly one classes.dex, got $($dexs.Count)"
}

Step 4 "aapt2 compile res (桌面图标)"
if (-not (Test-Path "$mod\res")) { Fail "找不到 res 目录: $mod\res（设置界面的图标在里面）" }
& "$bt\aapt2.exe" compile --dir "$mod\res" -o "$build\res.zip"
if ($LASTEXITCODE -ne 0) { Fail "aapt2 compile failed" }

Step 5 "aapt2 link -> base.apk (manifest + res)"
& "$bt\aapt2.exe" link -o "$build\base.apk" --manifest "$mod\AndroidManifest.xml" -I "$aj" -R "$build\res.zip" --min-sdk-version 26 --target-sdk-version 34
if ($LASTEXITCODE -ne 0) { Fail "aapt2 link failed" }

Step 6 "add classes.dex and assets/xposed_init into the apk"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$apkPath = (Resolve-Path "$build\base.apk").Path
$zip = [System.IO.Compression.ZipFile]::Open($apkPath, 'Update')
try {
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $zip, "$build\dex\classes.dex", 'classes.dex', [System.IO.Compression.CompressionLevel]::Optimal)
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $zip, "$mod\assets\xposed_init", 'assets/xposed_init', [System.IO.Compression.CompressionLevel]::Optimal)
} finally { $zip.Dispose() }

Step 7 "zipalign 4"
& "$bt\zipalign.exe" -f -p 4 "$build\base.apk" "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { Fail "zipalign failed" }

Step 8 "keystore (first run only)"
if (-not (Test-Path $ks)) {
    & keytool -genkeypair -v -keystore $ks -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android -dname "CN=NinebotSign, OU=Dev, O=Dev, L=NA, ST=NA, C=CN"
    if ($LASTEXITCODE -ne 0) { Fail "keytool failed" }
} else { Write-Host "   exists, skip" }

Step 9 "apksigner sign (v1+v2+v3)"
if (Test-Path $out) { Remove-Item -Force $out }
& "$bt\apksigner.bat" sign --ks $ks --ks-pass pass:android --key-pass pass:android --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true --out $out "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { Fail "apksigner failed" }

Step 10 "verify"
& "$bt\apksigner.bat" verify --print-certs -v $out

Write-Host ""
Write-Host "== DONE"
Write-Host ("   apk: {0}  ({1} bytes)" -f $out, (Get-Item $out).Length)
Write-Host "   entries:"
$z = [System.IO.Compression.ZipFile]::OpenRead($out)
$z.Entries | Sort-Object FullName | ForEach-Object {
    Write-Host ("     {0,10}  {1}" -f $_.Length, $_.FullName)
}
$z.Dispose()
