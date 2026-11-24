# Quản lý MySQL portable cho môi trường phát triển.
#   .\scripts\mysql.ps1 init     tạo thư mục dữ liệu, CSDL "vault" và user "vault" (chạy 1 lần)
#   .\scripts\mysql.ps1 start    chạy MySQL ngầm (chỉ nghe 127.0.0.1:3306)
#   .\scripts\mysql.ps1 stop     tắt MySQL
#   .\scripts\mysql.ps1 status
#   .\scripts\mysql.ps1 shell    mở mysql client vào CSDL vault
# Lưu ý: tài khoản root KHÔNG có mật khẩu và chỉ đăng nhập được từ máy này - chỉ dùng để phát triển.
param([ValidateSet('init', 'start', 'stop', 'status', 'shell')][string]$Action = 'status')
$ErrorActionPreference = 'Stop'
# Chương trình ngoài (mysqld, mysql) ghi log ra stderr; không coi đó là lỗi, chỉ dựa vào mã thoát.
$PSNativeCommandUseErrorActionPreference = $false

$tools   = Join-Path $env:USERPROFILE 'tools'
$mysql   = Join-Path $tools 'mysql'
$data    = Join-Path $tools 'mysql-data'
$ini     = Join-Path $tools 'mysql-vault.ini'
$port    = 3306
$dbUser  = 'vault'
$dbPass  = 'vault_dev_pw'

function Test-Up { [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) }

function Invoke-Sql($sql, $db = '') {
    $args = @('-u', 'root', '-h', '127.0.0.1', "-P$port", '--default-character-set=utf8mb4', '-e', $sql)
    if ($db) { $args += $db }
    $ErrorActionPreference = 'Continue'
    & "$mysql\bin\mysql.exe" @args 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw "Lệnh SQL lỗi: $sql" }
}

function Start-MySql {
    if (Test-Up) { Write-Host "MySQL đã chạy ở cổng $port"; return }
    Start-Process -FilePath "$mysql\bin\mysqld.exe" -ArgumentList "--defaults-file=`"$ini`"" -WindowStyle Hidden
    for ($i = 0; $i -lt 60 -and -not (Test-Up); $i++) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Up)) { throw "MySQL không khởi động được - xem $data\*.err" }
    Write-Host "MySQL đang chạy ở 127.0.0.1:$port" -ForegroundColor Green
}

switch ($Action) {
    'init' {
        if (Test-Path $data) { throw "Đã có $data - nếu muốn làm lại từ đầu, chạy stop rồi xoá thư mục này" }
        @"
[mysqld]
basedir=$($mysql -replace '\\','/')
datadir=$($data -replace '\\','/')
port=$port
bind-address=127.0.0.1
character-set-server=utf8mb4
collation-server=utf8mb4_unicode_ci
default-time-zone=+07:00
"@ | Set-Content -Encoding ASCII $ini
        $ErrorActionPreference = 'Continue'
        & "$mysql\bin\mysqld.exe" "--defaults-file=$ini" --initialize-insecure --console 2>&1 | ForEach-Object { "$_" }
        $ErrorActionPreference = 'Stop'
        if ($LASTEXITCODE -ne 0) { throw 'mysqld --initialize lỗi' }
        Start-MySql
        Invoke-Sql "CREATE DATABASE IF NOT EXISTS vault CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                    CREATE USER IF NOT EXISTS '$dbUser'@'localhost' IDENTIFIED BY '$dbPass';
                    CREATE USER IF NOT EXISTS '$dbUser'@'127.0.0.1' IDENTIFIED BY '$dbPass';
                    GRANT ALL PRIVILEGES ON vault.* TO '$dbUser'@'localhost';
                    GRANT ALL PRIVILEGES ON vault.* TO '$dbUser'@'127.0.0.1';
                    FLUSH PRIVILEGES;"
        Write-Host "Đã tạo CSDL vault, user $dbUser / $dbPass" -ForegroundColor Green
    }
    'start' { Start-MySql }
    'stop' {
        if (-not (Test-Up)) { Write-Host 'MySQL không chạy'; return }
        & "$mysql\bin\mysqladmin.exe" -u root -h 127.0.0.1 "-P$port" shutdown
        Write-Host 'Đã tắt MySQL'
    }
    'status' { if (Test-Up) { Write-Host "MySQL đang chạy ở cổng $port" } else { Write-Host 'MySQL không chạy' } }
    'shell' { & "$mysql\bin\mysql.exe" -u $dbUser "-p$dbPass" -h 127.0.0.1 "-P$port" --default-character-set=utf8mb4 vault }
}
