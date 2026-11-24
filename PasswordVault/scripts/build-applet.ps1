# Biên dịch VaultApplet và chuyển thành file CAP (không cần Eclipse).
# Kết quả: build\cap\vault\javacard\vault.cap
$ErrorActionPreference = 'Stop'

$root     = Split-Path -Parent $PSScriptRoot
$jcTools  = if ($env:JC_HOME_TOOLS) { $env:JC_HOME_TOOLS } else { 'C:\javacard\tools' }
$classes  = Join-Path $root 'build\applet-classes'
$capOut   = Join-Path $root 'build\cap'

$pkgAid    = '0x11:0x22:0x33:0x44:0x55:0x00'
$appletAid = '0x11:0x22:0x33:0x44:0x55:0x00:0x01'

Remove-Item -Recurse -Force $classes, $capOut -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $classes, $capOut | Out-Null

$api = "$jcTools\lib\api_classic-3.2.0.jar;$jcTools\lib\api_classic_annotations-3.2.0.jar"
$sources = Get-ChildItem -Recurse (Join-Path $root 'src') -Filter *.java | ForEach-Object { $_.FullName }

Write-Host '== javac' -ForegroundColor Cyan
& javac -g -encoding UTF-8 -source 10 -target 10 -Xlint:-options -cp $api -d $classes $sources
if ($LASTEXITCODE -ne 0) { throw 'javac lỗi' }

Write-Host '== converter' -ForegroundColor Cyan
& "$jcTools\bin\converter.bat" -i -classdir $classes `
    -applet $appletAid vault.VaultApplet `
    -out CAP JCA EXP -d $capOut -debug -target 3.2.0 `
    vault $pkgAid 1.0
if ($LASTEXITCODE -ne 0) { throw 'converter lỗi' }

$cap = Get-ChildItem -Recurse $capOut -Filter vault.cap | Select-Object -First 1
Write-Host "OK -> $($cap.FullName) ($($cap.Length) byte)" -ForegroundColor Green
