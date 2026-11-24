# Khởi động toàn bộ hệ thống để phát triển / demo. Mỗi thành phần mở trong một cửa sổ riêng.
#   .\scripts\start-dev.ps1                      thẻ trên simulator :9025 (simulator của Eclipse)
#   .\scripts\start-dev.ps1 -Reader pcsc         đầu đọc thẻ thật
#   .\scripts\start-dev.ps1 -Dev                 bật nút "Nạp thẻ trắng" trên trang Phát hành thẻ
#   .\scripts\start-dev.ps1 -WebDev              chạy thêm Vite (sửa giao diện, tự tải lại) ở :5173
# Mở web: http://127.0.0.1:8080 (bản build) hoặc http://localhost:5173 (khi -WebDev).
param(
    [string]$Reader = 'socket:localhost:9025',
    [switch]$Dev,
    [switch]$WebDev
)
$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $env:USERPROFILE 'tools'
$env:Path = "$tools\go\bin;$tools\node;$tools\mysql\bin;" + $env:Path

function Open-Window($title, $dir, $command) {
    $cmd = "`$Host.UI.RawUI.WindowTitle = '$title'; `$env:Path = '$env:Path'; Set-Location '$dir'; $command"
    Start-Process powershell -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $cmd
}

# 1. MySQL
& (Join-Path $PSScriptRoot 'mysql.ps1') start

# 2. Web: build nếu chưa có (server phục vụ web/dist)
$web = Join-Path $root 'web'
if (-not (Test-Path "$web\node_modules")) { Push-Location $web; npm install; Pop-Location }
if (-not (Test-Path "$web\dist\index.html")) { Push-Location $web; npm run build; Pop-Location }

# 3. Server Go
$server = Join-Path $root 'server'
Push-Location $server
go build -o vault-server.exe .
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'go build lỗi' }
Pop-Location
Open-Window 'Vault server :8080' $server '.\vault-server.exe'

# 4. Card Agent
$agentArgs = "-Reader '$Reader'"
if ($Dev) { $agentArgs += ' -Dev' }
Open-Window 'Card Agent :8765' $root "& '$PSScriptRoot\agent.ps1' $agentArgs"

# 5. Vite (tuỳ chọn)
if ($WebDev) { Open-Window 'Web dev :5173' $web 'npm run dev' }

Write-Host ''
Write-Host 'Đã khởi động. Mở web quản trị:' -ForegroundColor Green
Write-Host ('  ' + $(if ($WebDev) { 'http://localhost:5173' } else { 'http://127.0.0.1:8080' }))
Write-Host '  Tài khoản mặc định: admin / admin123 (đổi ở trang Tài khoản)'
Write-Host 'Lưu ý: simulator chỉ nhận 1 kết nối - nếu console APDU của Eclipse đang Connect, hãy Disconnect.'
