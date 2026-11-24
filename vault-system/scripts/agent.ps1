# Build và chạy Card Agent (cầu nối web quản trị <-> thẻ).
#   .\scripts\agent.ps1                         thẻ trên simulator localhost:9025
#   .\scripts\agent.ps1 -Reader socket:localhost:9026
#   .\scripts\agent.ps1 -Reader pcsc            đầu đọc thẻ thật
#   .\scripts\agent.ps1 -Dev                    bật nút "Nạp thẻ trắng" (nạp lại applet trên simulator)
# Agent dùng lại VaultCard.java của bộ test applet (PasswordVault\tester).
param(
    [string]$Reader = 'socket:localhost:9025',
    [string]$Server = 'http://127.0.0.1:8080',
    [int]$Port = 8765,
    [switch]$Dev,
    [switch]$BuildOnly
)
$ErrorActionPreference = 'Stop'

$root     = Split-Path -Parent $PSScriptRoot
$applet   = Join-Path (Split-Path -Parent $root) 'PasswordVault'
$jcSim    = if ($env:JC_HOME_SIMULATOR) { $env:JC_HOME_SIMULATOR } else { 'C:\javacard\simulator' }
$libs     = "$jcSim\client\AMService\amservice.jar;$jcSim\client\COMService\socketprovider.jar"
$out      = Join-Path $root 'agent\build'

$sources  = @(Get-ChildItem -Recurse (Join-Path $root 'agent\src') -Filter *.java | ForEach-Object { $_.FullName })
$sources += @('VaultCard', 'Hex', 'Simulator', 'BackupFile') | ForEach-Object { Join-Path $applet "tester\src\vault\tester\$_.java" }

Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
Write-Host '== javac agent' -ForegroundColor Cyan
& javac -encoding UTF-8 -p $libs --add-modules ALL-MODULE-PATH -d $out $sources
if ($LASTEXITCODE -ne 0) { throw 'javac agent failed' }
if ($BuildOnly) { return }

$cap   = Join-Path $applet 'build\cap\vault\javacard\vault.cap'
$props = "$jcSim\samples\client.config.properties"
$agentArgs = @("--port=$Port", "--server=$Server", "--reader=$Reader")
if ($Dev) {
    if (-not (Test-Path $cap)) { throw "Chưa có $cap - chạy PasswordVault\scripts\build-applet.ps1 trước" }
    $agentArgs += @('--dev', "--cap=$cap", "--props=$props")
}
& java "-Dsun.stdout.encoding=UTF-8" -p $libs --add-modules ALL-MODULE-PATH -cp $out vault.agent.CardAgent @agentArgs
