# Build applet, build bộ test, rồi chạy test trên simulator (jcsw.exe phải đang chạy).
# Dùng: .\scripts\test-applet.ps1                 (giai đoạn 1-4 và 6: sao lưu)
#       .\scripts\test-applet.ps1 -Stages 2,3
#       .\scripts\test-applet.ps1 -SimHost localhost:9026
# LƯU Ý: simulator chỉ phục vụ MỘT kết nối một lúc. Nếu console APDU trong Eclipse
# đang mở thì test sẽ đứng chờ - hãy đóng console đó, hoặc chạy simulator thứ hai ở cổng khác.
param([string]$Stages = '1,2,3,4,6', [string]$SimHost = 'localhost:9025', [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'

$root   = Split-Path -Parent $PSScriptRoot
$jcSim  = if ($env:JC_HOME_SIMULATOR) { $env:JC_HOME_SIMULATOR } else { 'C:\javacard\simulator' }
$libs   = "$jcSim\client\AMService\amservice.jar;$jcSim\client\COMService\socketprovider.jar"
$out    = Join-Path $root 'build\tester-classes'
$cap    = Join-Path $root 'build\cap\vault\javacard\vault.cap'
$props  = "$jcSim\samples\client.config.properties"

if (-not $SkipBuild) { & (Join-Path $PSScriptRoot 'build-applet.ps1') }

Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
$sources = Get-ChildItem -Recurse (Join-Path $root 'tester\src') -Filter *.java | ForEach-Object { $_.FullName }

Write-Host '== javac tester' -ForegroundColor Cyan
& javac -encoding UTF-8 -p $libs --add-modules ALL-MODULE-PATH -d $out $sources
if ($LASTEXITCODE -ne 0) { throw 'javac tester failed' }

Write-Host "== run stages $Stages" -ForegroundColor Cyan
& java "-Dsun.stdout.encoding=UTF-8" -p $libs --add-modules ALL-MODULE-PATH -cp $out vault.tester.AllTests "-cap=$cap" "-props=$props" "-host=$SimHost" "-stages=$Stages"
exit $LASTEXITCODE
