# Cài bản portable (giải nén zip) của Go, Node.js, MySQL vào C:\Users\<bạn>\tools
# Không cần quyền admin, không cài dịch vụ Windows. Gỡ: xoá thư mục tools và bỏ các dòng PATH.
# Chạy lại an toàn: công cụ nào đã có thì bỏ qua.
param(
    [string]$ToolsDir = (Join-Path $env:USERPROFILE 'tools'),
    [string]$GoVersion = '1.27.4',
    [string]$NodeVersion = 'v26.13.1',
    [string]$MySqlVersion = '8.4.9'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force $ToolsDir | Out-Null
$dl = Join-Path $ToolsDir '_downloads'
New-Item -ItemType Directory -Force $dl | Out-Null

function Get-File($url, $out, $sha256) {
    if (-not (Test-Path $out)) {
        Write-Host "  tải $url"
        Invoke-WebRequest $url -OutFile "$out.part"
        Move-Item "$out.part" $out
    }
    if ($sha256) {
        $h = (Get-FileHash $out -Algorithm SHA256).Hash
        if ($h -ne $sha256.ToUpper()) { Remove-Item $out; throw "Sai SHA-256: $out" }
        Write-Host '  SHA-256 khớp'
    }
}

function Expand-To($zip, $dest) {
    $tmp = "$dest.extract"
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    Expand-Archive $zip $tmp
    $inner = Get-ChildItem $tmp | Select-Object -First 1
    Move-Item $inner.FullName $dest
    Remove-Item -Recurse -Force $tmp
}

# ---------------- Go
$goDir = Join-Path $ToolsDir 'go'
if (-not (Test-Path "$goDir\bin\go.exe")) {
    Write-Host "== Go $GoVersion" -ForegroundColor Cyan
    $meta = (Invoke-RestMethod 'https://go.dev/dl/?mode=json&include=all') | Where-Object { $_.version -eq "go$GoVersion" }
    $f = $meta.files | Where-Object { $_.os -eq 'windows' -and $_.arch -eq 'amd64' -and $_.kind -eq 'archive' }
    $zip = Join-Path $dl $f.filename
    Get-File "https://go.dev/dl/$($f.filename)" $zip $f.sha256
    Expand-To $zip $goDir
}

# ---------------- Node.js
$nodeDir = Join-Path $ToolsDir 'node'
if (-not (Test-Path "$nodeDir\node.exe")) {
    Write-Host "== Node.js $NodeVersion" -ForegroundColor Cyan
    $name = "node-$NodeVersion-win-x64.zip"
    $sums = (Invoke-WebRequest "https://nodejs.org/dist/$NodeVersion/SHASUMS256.txt" -UseBasicParsing).Content
    $sha = ($sums -split "`n" | Where-Object { $_ -match " $([regex]::Escape($name))$" }) -replace '\s.*', ''
    $zip = Join-Path $dl $name
    Get-File "https://nodejs.org/dist/$NodeVersion/$name" $zip $sha
    Expand-To $zip $nodeDir
}

# ---------------- MySQL (bản ZIP "noinstall")
$mysqlDir = Join-Path $ToolsDir 'mysql'
if (-not (Test-Path "$mysqlDir\bin\mysqld.exe")) {
    Write-Host "== MySQL $MySqlVersion" -ForegroundColor Cyan
    $minor = ($MySqlVersion -split '\.')[0..1] -join '.'
    $name = "mysql-$MySqlVersion-winx64.zip"
    $zip = Join-Path $dl $name
    # Bản mới nhất nằm ở Downloads/, bản cũ hơn chuyển sang archives/
    try {
        Get-File "https://cdn.mysql.com/Downloads/MySQL-$minor/$name" $zip $null
    } catch {
        Get-File "https://cdn.mysql.com/archives/mysql-$minor/$name" $zip $null
    }
    Expand-To $zip $mysqlDir
}

# ---------------- PATH (biến môi trường của người dùng, không cần admin)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$add = @("$goDir\bin", $nodeDir, "$mysqlDir\bin", (Join-Path $env:USERPROFILE 'go\bin'))
$parts = @($userPath -split ';' | Where-Object { $_ })
$changed = $false
foreach ($p in $add) { if ($parts -notcontains $p) { $parts += $p; $changed = $true } }
if ($changed) {
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
    Write-Host 'Đã thêm vào PATH người dùng (mở terminal mới để có hiệu lực):' -ForegroundColor Yellow
    $add | ForEach-Object { Write-Host "  $_" }
}

& "$goDir\bin\go.exe" version
& "$nodeDir\node.exe" --version
& "$mysqlDir\bin\mysqld.exe" --version
