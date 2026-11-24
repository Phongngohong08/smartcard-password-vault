# Kiểm thử end-to-end: Vault server + Card Agent (chế độ --dev) + thẻ trên simulator.
# Cần: MySQL, server (:8080), agent chạy với -Dev. Mỗi lần chạy sẽ nạp lại thẻ trắng.
#   .\scripts\e2e-test.ps1
param(
    [string]$Server = 'http://127.0.0.1:8080',
    [string]$Agent = 'http://127.0.0.1:8765',
    [string]$AdminUser = 'admin',
    [string]$AdminPassword = 'admin123'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$http = New-Object System.Net.Http.HttpClient
$http.Timeout = [TimeSpan]::FromSeconds(60)
$script:pass = 0; $script:fail = 0

function Call($method, $url, $body = $null, $token = $null, $origin = $null) {
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::new($method), $url)
    if ($token) { $req.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $token) }
    if ($origin) { $req.Headers.Add('Origin', $origin) }
    if ($null -ne $body) {
        $req.Content = New-Object System.Net.Http.StringContent(($body | ConvertTo-Json -Depth 6 -Compress), [Text.Encoding]::UTF8, 'application/json')
    }
    $resp = $http.SendAsync($req).Result
    $text = $resp.Content.ReadAsStringAsync().Result
    $json = $null
    if ($text) { try { $json = $text | ConvertFrom-Json } catch { } }
    [pscustomobject]@{ Status = [int]$resp.StatusCode; Json = $json; Text = $text }
}

function Check($name, $ok, $detail = '') {
    if ($ok) { $script:pass++; Write-Host "  [ĐẠT] $name" }
    else { $script:fail++; Write-Host "  [LỖI] $name  <-- $detail" -ForegroundColor Red }
}
function Expect($name, $r, $status) { Check $name ($r.Status -eq $status) "HTTP $($r.Status) $($r.Text)" }
function Section($s) { Write-Host "`n--- $s" -ForegroundColor Cyan }

function Sign($cardId, $tokenForLog) {
    $ch = Call POST "$Server/api/auth/challenge" @{ cardId = $cardId }
    $sg = Call POST "$Agent/card/sign" @{ challenge = $ch.Json.challenge }
    [pscustomobject]@{ Challenge = $ch.Json.challenge; Signature = $sg.Json.signature; ChallengeResp = $ch; SignResp = $sg }
}

# Phát hành một thẻ trắng từ đầu đến cuối, giống trang "Phát hành thẻ" trên web
function IssueCard($token, $ownerName, $replaces = '') {
    $blank = Call POST "$Agent/dev/blank-card"
    $id = (Call GET "$Server/api/cards/next-id" -token $token).Json.cardId
    $iss = Call POST "$Agent/card/issue" @{ cardId = $id; pin = '123456'; puk = '12345678'
        profile = @{ name = $ownerName; dob = '2004-05-17'; email = 'an@example.com'; phone = '0901234567' } } $token
    $reg = Call POST "$Server/api/cards" @{ cardId = $id; ownerName = $ownerName; ownerEmail = 'an@example.com'
        ownerPhone = '0901234567'; modulusHex = $iss.Json.modulusHex; exponentHex = $iss.Json.exponentHex; replacesCardId = $replaces } $token
    $s = Sign $id
    $act = Call POST "$Server/api/cards/$id/activate" @{ challenge = $s.Challenge; signature = $s.Signature } $token
    [pscustomobject]@{ Id = $id; Blank = $blank; Issue = $iss; Register = $reg; Activate = $act }
}

# ======================================================================
Section 'Agent và server'
$h = Call GET "$Agent/health"
Check 'Agent chạy ở chế độ dev' ($h.Status -eq 200 -and $h.Json.dev) $h.Text
Expect 'Server /api/health' (Call GET "$Server/api/health") 200
Expect 'Agent từ chối origin lạ (http://evil.example)' (Call GET "$Agent/card" -origin 'http://evil.example') 403
Expect 'Agent nhận origin web quản trị' (Call GET "$Agent/card" -origin 'http://localhost:5173') 200
$login = Call POST "$Server/api/admin/login" @{ username = $AdminUser; password = $AdminPassword }
Expect 'Admin đăng nhập' $login 200
$T = $login.Json.token
Expect 'API admin không có token -> 401' (Call GET "$Server/api/cards") 401
Expect 'Agent phát hành không có token -> 401' (Call POST "$Agent/card/issue" @{ cardId = 'SC999999'; pin = '123456'; puk = '12345678' }) 401

Section 'Phát hành thẻ'
$c1 = IssueCard $T 'Nguyễn Văn An'
$id = $c1.Id
Check "Nạp thẻ trắng -> UNISSUED" ($c1.Blank.Json.stateName -eq 'UNISSUED') $c1.Blank.Text
Check "Agent ISSUE $id, trả khoá công khai 256 byte" ($c1.Issue.Status -eq 200 -and $c1.Issue.Json.modulusHex.Length -eq 512) $c1.Issue.Text
Check 'Đăng ký khoá công khai -> PENDING' ($c1.Register.Status -eq 201 -and $c1.Register.Json.status -eq 'PENDING') $c1.Register.Text
Check 'Kiểm tra RSA -> ACTIVE' ($c1.Activate.Status -eq 200 -and $c1.Activate.Json.status -eq 'ACTIVE') $c1.Activate.Text
$card = Call GET "$Agent/card"
Check "Thẻ đang cắm: $id, Hoạt động" ($card.Json.cardId -eq $id -and $card.Json.stateName -eq 'ACTIVE') $card.Text
Expect 'Phát hành lại thẻ đã có dữ liệu -> 409' (Call POST "$Agent/card/issue" @{ cardId = 'SC999999'; pin = '123456'; puk = '12345678' } $T) 409
Expect 'Xin adminKey cho mã thẻ đã phát hành -> 409' (Call POST "$Server/api/cards/$id/issue-key" @{} $T) 409

Section 'Xác thực thẻ bằng RSA (luồng của app người dùng)'
$s = Sign $id
$v = Call POST "$Server/api/auth/verify" @{ cardId = $id; challenge = $s.Challenge; signature = $s.Signature }
Check 'Chữ ký đúng -> token thẻ' ($v.Status -eq 200 -and $v.Json.token) $v.Text
$CT = $v.Json.token
Expect 'Dùng lại challenge cũ -> 400' (Call POST "$Server/api/auth/verify" @{ cardId = $id; challenge = $s.Challenge; signature = $s.Signature }) 400
$s = Sign $id
$bad = $s.Signature.Substring(0, 510) + $(if ($s.Signature.EndsWith('00')) { '01' } else { '00' })
$v = Call POST "$Server/api/auth/verify" @{ cardId = $id; challenge = $s.Challenge; signature = $bad }
Check 'Chữ ký bị sửa (thẻ giả) -> 401 BAD_SIGNATURE' ($v.Status -eq 401 -and $v.Json.code -eq 'BAD_SIGNATURE') $v.Text
Expect 'Mã thẻ lạ -> 404' (Call POST "$Server/api/auth/challenge" @{ cardId = 'ZZ000000' }) 404

Section 'App: nhật ký, sao lưu'
Expect 'Ghi nhật ký LOGIN' (Call POST "$Server/api/app/logs" @{ action = 'LOGIN'; result = 'OK' } $CT) 201
Expect 'Action lạ -> 400' (Call POST "$Server/api/app/logs" @{ action = 'HACK'; result = 'OK' } $CT) 400
Expect 'Token thẻ không gọi được API admin -> 401' (Call GET "$Server/api/cards" -token $CT) 401
$vbk = [byte[]](@(0x56, 0x42, 0x4B, 0x31) + (1..48 | ForEach-Object { $_ }) + @(0))
$bk = Call POST "$Server/api/app/backups" @{ data = [Convert]::ToBase64String($vbk) } $CT
Expect 'Lưu bản sao lưu VBK1' $bk 201
Expect 'Dữ liệu không phải VBK1 -> 400' (Call POST "$Server/api/app/backups" @{ data = 'aGVsbG8=' } $CT) 400

Section 'Khoá / mở khoá trên thẻ'
$a = Call POST "$Agent/card/admin" @{ cardId = $id; action = 'LOCK' } $T
Check 'Agent: ADMIN_CHALLENGE -> server -> ADMIN_AUTH -> khoá' ($a.Status -eq 200 -and $a.Json.stateName -eq 'ADMIN_LOCKED') $a.Text
$r = Call POST "$Server/api/cards/$id/lock" @{ onCard = $true } $T
Check 'CSDL: LOCKED, không có thao tác chờ' ($r.Json.status -eq 'LOCKED' -and $r.Json.pendingAction -eq 'NONE') $r.Text
$s = Sign $id
$v = Call POST "$Server/api/auth/verify" @{ cardId = $id; challenge = $s.Challenge; signature = $s.Signature }
Check 'Thẻ bị khoá: RSA vẫn qua nhưng bị từ chối 403 CARD_LOCKED' ($v.Status -eq 403 -and $v.Json.code -eq 'CARD_LOCKED') $v.Text
Expect 'Khoá lần nữa -> 409' (Call POST "$Server/api/cards/$id/lock" @{ onCard = $true } $T) 409
$a = Call POST "$Agent/card/admin" @{ cardId = $id; action = 'UNLOCK' } $T
Check 'Agent mở khoá trên thẻ' ($a.Json.stateName -eq 'ACTIVE') $a.Text
$r = Call POST "$Server/api/cards/$id/unlock" @{ onCard = $true } $T
Check 'CSDL: ACTIVE' ($r.Json.status -eq 'ACTIVE') $r.Text
Expect 'Agent: mã thẻ không khớp thẻ đang cắm -> 409' (Call POST "$Agent/card/admin" @{ cardId = 'SC999999'; action = 'LOCK' } $T) 409

Section 'Khoá khi thẻ không cắm (chờ đồng bộ)'
$r = Call POST "$Server/api/cards/$id/lock" @{ onCard = $false } $T
Check 'CSDL: LOCKED, chờ LOCK' ($r.Json.status -eq 'LOCKED' -and $r.Json.pendingAction -eq 'LOCK') $r.Text
$s = Sign $id
$v = Call POST "$Server/api/auth/verify" @{ cardId = $id; challenge = $s.Challenge; signature = $s.Signature }
Check 'Thẻ kết nối: 403 kèm token "pending" để đồng bộ' ($v.Status -eq 403 -and $v.Json.pendingAction -eq 'LOCK' -and $v.Json.token) $v.Text
$PT = $v.Json.token
$pr = Call POST "$Server/api/cards/$id/pending/response" @{ challenge = '00112233445566778899aabbccddeeff' } $PT
Check 'Server trả phản hồi ADMIN_AUTH cho thao tác chờ' ($pr.Status -eq 200 -and $pr.Json.action -eq 'LOCK' -and $pr.Json.response.Length -eq 32) $pr.Text
Expect 'Token pending không ghi được nhật ký app -> 403' (Call POST "$Server/api/app/logs" @{ action = 'LOGIN'; result = 'OK' } $PT) 403
Expect 'Báo đã đồng bộ' (Call POST "$Server/api/cards/$id/pending/done" @{ action = 'LOCK'; cardState = 'ADMIN_LOCKED' } $PT) 200
$r = Call POST "$Server/api/cards/$id/unlock" @{ onCard = $false } $T
Check 'Mở khoá khi thẻ không cắm -> chờ UNLOCK' ($r.Json.pendingAction -eq 'UNLOCK') $r.Text
$r = Call POST "$Server/api/cards/$id/lock" @{ onCard = $false } $T
Check 'Khoá lại trước khi kịp đồng bộ -> hai thao tác triệt tiêu' ($r.Json.pendingAction -eq 'NONE') $r.Text
$r = Call POST "$Server/api/cards/$id/unlock" @{ onCard = $false } $T
Expect 'Đồng bộ UNLOCK' (Call POST "$Server/api/cards/$id/pending/done" @{ action = 'UNLOCK'; cardState = 'ACTIVE' } $PT) 200

Section 'Thu hồi và thẻ thay thế'
$a = Call POST "$Agent/card/admin" @{ cardId = $id; action = 'REVOKE' } $T
Check 'Agent thu hồi trên thẻ' ($a.Json.stateName -eq 'REVOKED') $a.Text
$r = Call POST "$Server/api/cards/$id/revoke" @{ onCard = $true; reason = 'Mất thẻ' } $T
Check 'CSDL: REVOKED' ($r.Json.status -eq 'REVOKED' -and $r.Json.revokedAt) $r.Text
$sg = Call POST "$Agent/card/sign" @{ challenge = ('00' * 32) }
Check 'Thẻ đã thu hồi không ký được nữa (SW 6985)' ($sg.Status -eq 422 -and $sg.Json.sw -eq '6985') $sg.Text
$c2 = IssueCard $T 'Nguyễn Văn An' $id
Check "Phát hành thẻ thay thế $($c2.Id) cho $id" ($c2.Activate.Json.status -eq 'ACTIVE' -and $c2.Activate.Json.replacesCardId -eq $id) $c2.Activate.Text
$s = Sign $c2.Id
$v = Call POST "$Server/api/auth/verify" @{ cardId = $c2.Id; challenge = $s.Challenge; signature = $s.Signature }
$bl = Call GET "$Server/api/app/backups" -token $v.Json.token
Check 'Thẻ mới thấy bản sao lưu của thẻ cũ' ($bl.Status -eq 200 -and @($bl.Json | Where-Object { $_.cardId -eq $id }).Count -ge 1) $bl.Text
$bget = Call GET "$Server/api/app/backups/$($bk.Json.id)" -token $v.Json.token
Check 'Tải được dữ liệu sao lưu của thẻ cũ' ($bget.Status -eq 200 -and $bget.Json.data -eq [Convert]::ToBase64String($vbk)) $bget.Text

Section 'Thống kê, nhật ký'
$st = Call GET "$Server/api/stats" -token $T
Check 'Thống kê có thẻ ACTIVE và REVOKED' ($st.Json.cards.byStatus.ACTIVE -ge 1 -and $st.Json.cards.byStatus.REVOKED -ge 1) $st.Text
Check 'Thống kê đếm RSA_AUTH thất bại 24h' ($st.Json.last24h.rsaFail -ge 1) ($st.Json.last24h | ConvertTo-Json -Compress)
$lg = Call GET "$Server/api/logs?cardId=$id&size=100" -token $T
$actions = @($lg.Json.items | ForEach-Object { "$($_.action)/$($_.result)" })
foreach ($x in 'ISSUE/OK', 'RSA_AUTH/FAIL', 'LOCK/OK', 'UNLOCK/OK', 'REVOKE/OK', 'BACKUP/OK', 'LOGIN/FAIL') {
    Check "Nhật ký thẻ $id có $x" ($actions -contains $x) ($actions -join ', ')
}
$det = Call GET "$Server/api/cards/$id" -token $T
Check 'Chi tiết thẻ: thay bởi thẻ mới, có bản sao lưu' ($det.Json.replacedBy -eq $c2.Id -and $det.Json.backups.Count -ge 1) $det.Text

Write-Host "`n==== KẾT QUẢ: $script:pass đạt, $script:fail lỗi ====" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $script:fail
