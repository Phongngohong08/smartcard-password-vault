# Tắt các thành phần đã bật bằng start-dev.ps1.
#   .\scripts\stop-dev.ps1               tắt server, agent, web dev (Vite) và MySQL
#   .\scripts\stop-dev.ps1 -KeepMySql    giữ MySQL chạy
#   .\scripts\stop-dev.ps1 -Simulators   tắt luôn mọi simulator jcsw.exe (kể cả cái Eclipse đã bật)
param([switch]$KeepMySql, [switch]$Simulators)
$ErrorActionPreference = 'Stop'

function Stop-Matching($label, $filter) {
    $procs = @(Get-CimInstance Win32_Process | Where-Object $filter)
    if ($procs.Count -eq 0) { Write-Host ("  {0,-22} không chạy" -f $label); return }
    foreach ($p in $procs) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Host ("  {0,-22} đã tắt (pid {1})" -f $label, $p.ProcessId) -ForegroundColor Green
    }
}

Write-Host 'Đang tắt hệ thống Vault...' -ForegroundColor Cyan
Stop-Matching 'Vault server :8080' { $_.Name -eq 'vault-server.exe' }
Stop-Matching 'Card Agent :8765'   { $_.Name -eq 'java.exe' -and $_.CommandLine -like '*vault.agent.CardAgent*' }
Stop-Matching 'Web dev (Vite) :5173' { $_.Name -eq 'node.exe' -and $_.CommandLine -like '*vault-system*web*vite*' }

if ($KeepMySql) {
    Write-Host '  MySQL :3306            giữ nguyên (-KeepMySql)'
} else {
    $tools = Join-Path $env:USERPROFILE 'tools'
    if (Get-NetTCPConnection -LocalPort 3306 -State Listen -ErrorAction SilentlyContinue) {
        # Tắt êm để MySQL ghi xong dữ liệu; không được thì mới buộc tắt
        & "$tools\mysql\bin\mysqladmin.exe" -u root -h 127.0.0.1 -P3306 shutdown 2>$null
        for ($i = 0; $i -lt 20 -and (Get-NetTCPConnection -LocalPort 3306 -State Listen -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
        if (Get-NetTCPConnection -LocalPort 3306 -State Listen -ErrorAction SilentlyContinue) {
            Stop-Matching 'MySQL :3306' { $_.Name -eq 'mysqld.exe' }
        } else {
            Write-Host '  MySQL :3306            đã tắt' -ForegroundColor Green
        }
    } else {
        Write-Host '  MySQL :3306            không chạy'
    }
}

if ($Simulators) { Stop-Matching 'Simulator (jcsw.exe)' { $_.Name -eq 'jcsw.exe' } }

# Đóng các cửa sổ PowerShell mà start-dev.ps1 đã mở (nhận ra qua tiêu đề đặt trong lệnh)
Stop-Matching 'Cửa sổ của start-dev' {
    $_.Name -eq 'powershell.exe' -and $_.ProcessId -ne $PID -and (
        $_.CommandLine -like "*WindowTitle = 'Vault server :8080'*" -or
        $_.CommandLine -like "*WindowTitle = 'Card Agent :8765'*" -or
        $_.CommandLine -like "*WindowTitle = 'Web dev :5173'*")
}

Write-Host 'Xong. Bật lại: .\scripts\start-dev.ps1 -Dev' -ForegroundColor Cyan
