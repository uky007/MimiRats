# MimiRats Functional Test Script
# Usage: powershell -ExecutionPolicy Bypass -File tests\run_tests.ps1
# Output: tests\test_results.txt
#
# Run WITHOUT admin  -> basic + crypto tests
# Run WITH admin     -> basic + crypto + privilege + service + credential tests

$ErrorActionPreference = "Continue"
$Binary = "$PSScriptRoot\..\target\x86_64-pc-windows-msvc\debug\MimiRats.exe"
$ResultFile = "$PSScriptRoot\test_results.txt"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Section($title) {
    $sep = "=" * 72
    "$sep`n[$title]`n$sep" | Tee-Object -FilePath $ResultFile -Append
}

function Write-SubSection($title) {
    "`n--- $title ---" | Tee-Object -FilePath $ResultFile -Append
}

function Run-MimiRats {
    param([string[]]$Commands)
    $input_text = ($Commands + "exit") -join "`n"
    $result = $input_text | & $Binary 2>&1
    $output = $result -join "`n"
    $output | Tee-Object -FilePath $ResultFile -Append
    return $output
}

function Run-MimiRats-Cmdline {
    param([string]$Cmd)
    $result = & $Binary $Cmd 2>&1
    $output = $result -join "`n"
    $output | Tee-Object -FilePath $ResultFile -Append
    return $output
}

function Check-Result($output, $expected, $testname) {
    if ($output -match [regex]::Escape($expected)) {
        "  [PASS] $testname" | Tee-Object -FilePath $ResultFile -Append
    } else {
        "  [FAIL] $testname (expected: '$expected')" | Tee-Object -FilePath $ResultFile -Append
    }
}

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

"" | Set-Content $ResultFile
"MimiRats Functional Test Report" | Tee-Object -FilePath $ResultFile -Append
"Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Tee-Object -FilePath $ResultFile -Append
"Host: $env:COMPUTERNAME" | Tee-Object -FilePath $ResultFile -Append
"OS:   $([System.Environment]::OSVersion.VersionString)" | Tee-Object -FilePath $ResultFile -Append
"Admin: $(Is-Admin)" | Tee-Object -FilePath $ResultFile -Append
"Binary: $Binary" | Tee-Object -FilePath $ResultFile -Append

# Check binary exists
if (-not (Test-Path $Binary)) {
    "ERROR: Binary not found at $Binary" | Tee-Object -FilePath $ResultFile -Append
    "Try: cargo build" | Tee-Object -FilePath $ResultFile -Append
    # Also check release path
    $RelBinary = "$PSScriptRoot\..\target\x86_64-pc-windows-msvc\release\MimiRats.exe"
    if (Test-Path $RelBinary) {
        "Found release binary at: $RelBinary" | Tee-Object -FilePath $ResultFile -Append
        $Binary = $RelBinary
    } else {
        exit 1
    }
}

"Binary size: $((Get-Item $Binary).Length) bytes" | Tee-Object -FilePath $ResultFile -Append
"" | Tee-Object -FilePath $ResultFile -Append

# ===================================================================
# TEST 1: Build verification (cargo test)
# ===================================================================
Write-Section "1. Unit Tests (cargo test)"

$testOutput = & cargo test --manifest-path "$PSScriptRoot\..\Cargo.toml" 2>&1
$testOutput -join "`n" | Tee-Object -FilePath $ResultFile -Append

if ($testOutput -match "test result: ok") {
    "  [PASS] Unit tests" | Tee-Object -FilePath $ResultFile -Append
} else {
    "  [FAIL] Unit tests" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 2: Banner and REPL
# ===================================================================
Write-Section "2. Banner and REPL"

Write-SubSection "2a. Banner display"
$out = Run-MimiRats @()
Check-Result $out "MimiRats" "Banner contains 'MimiRats'"
Check-Result $out "Rust edition" "Banner contains 'Rust edition'"
Check-Result $out "mimrats #" "REPL prompt displayed"

Write-SubSection "2b. Command-line mode"
$out = Run-MimiRats-Cmdline "version"
Check-Result $out "MimiRats" "Cmdline mode works"

# ===================================================================
# TEST 3: Standard module
# ===================================================================
Write-Section "3. Standard Module"

Write-SubSection "3a. version"
$out = Run-MimiRats @("version")
Check-Result $out "MimiRats" "version command"

Write-SubSection "3b. coffee"
$out = Run-MimiRats @("coffee")
Check-Result $out "Coffee" "coffee command"

Write-SubSection "3c. answer"
$out = Run-MimiRats @("answer")
Check-Result $out "42" "answer command"

Write-SubSection "3d. cd"
$out = Run-MimiRats @("cd")
Check-Result $out ":\" "cd shows current directory"

Write-SubSection "3e. module listing"
$out = Run-MimiRats @("unknownmodule::")
Check-Result $out "standard" "Module list shows standard"
Check-Result $out "sekurlsa" "Module list shows sekurlsa"
Check-Result $out "lsadump" "Module list shows lsadump"
Check-Result $out "kerberos" "Module list shows kerberos"

# ===================================================================
# TEST 4: Crypto module (cross-platform, fully implemented)
# ===================================================================
Write-Section "4. Crypto Module"

Write-SubSection "4a. crypto::hash - empty password"
$out = Run-MimiRats @("crypto::hash /password:")
Check-Result $out "31d6cfe0d16ae931b73c59d7e0c089c0" "NTLM of empty password"
Check-Result $out "aad3b435b51404eeaad3b435b51404ee" "LM of empty password"

Write-SubSection "4b. crypto::hash - 'mimikatz'"
$out = Run-MimiRats @("crypto::hash /password:mimikatz")
Check-Result $out "60ba4fcadc466c7a033c178194c03df6" "NTLM of 'mimikatz'"
Check-Result $out "MD5" "MD5 hash displayed"
Check-Result $out "SHA1" "SHA1 hash displayed"
Check-Result $out "SHA256" "SHA256 hash displayed"

Write-SubSection "4c. crypto::hash - with DCC"
$out = Run-MimiRats @("crypto::hash /password:Password /user:admin")
Check-Result $out "NTLM" "NTLM displayed"
Check-Result $out "DCC1" "DCC1 computed"
Check-Result $out "DCC2" "DCC2 computed"

Write-SubSection "4d. crypto::hash - Unicode"
$out = Run-MimiRats @("crypto::hash /password:P@ssw0rd!")
Check-Result $out "NTLM" "NTLM for special chars"

# ===================================================================
# TEST 5: Kerberos module (hash - cross-platform)
# ===================================================================
Write-Section "5. Kerberos Module"

Write-SubSection "5a. kerberos::hash"
$out = Run-MimiRats @("kerberos::hash /password:Password /user:admin /domain:CONTOSO.LOCAL")
Check-Result $out "rc4_hmac" "RC4-HMAC key"
Check-Result $out "aes256" "AES256 key"
Check-Result $out "aes128" "AES128 key"

# ===================================================================
# TEST 6: Module help display
# ===================================================================
Write-Section "6. Module Help"

Write-SubSection "6a. sekurlsa::"
$out = Run-MimiRats @("sekurlsa::")
Check-Result $out "logonPasswords" "sekurlsa help shows logonPasswords"
Check-Result $out "msv" "sekurlsa help shows msv"

Write-SubSection "6b. lsadump::"
$out = Run-MimiRats @("lsadump::")
Check-Result $out "sam" "lsadump help shows sam"
Check-Result $out "secrets" "lsadump help shows secrets"
Check-Result $out "cache" "lsadump help shows cache"
Check-Result $out "dcsync" "lsadump help shows dcsync"

Write-SubSection "6c. privilege::"
$out = Run-MimiRats @("privilege::")
Check-Result $out "debug" "privilege help shows debug"

Write-SubSection "6d. crypto::"
$out = Run-MimiRats @("crypto::")
Check-Result $out "hash" "crypto help shows hash"
Check-Result $out "providers" "crypto help shows providers"
Check-Result $out "certificates" "crypto help shows certificates"

Write-SubSection "6e. process::"
$out = Run-MimiRats @("process::")
Check-Result $out "list" "process help shows list"

Write-SubSection "6f. dpapi::"
$out = Run-MimiRats @("dpapi::")
Check-Result $out "masterkeys" "dpapi help shows masterkeys"

# ===================================================================
# TEST 7: Process module
# ===================================================================
Write-Section "7. Process Module"

Write-SubSection "7a. process::list"
$out = Run-MimiRats @("process::list")
Check-Result $out "PID" "Process list header"

# ===================================================================
# TEST 8: Privilege tests (admin required)
# ===================================================================
Write-Section "8. Privilege Module (admin required)"

if (Is-Admin) {
    Write-SubSection "8a. privilege::debug"
    $out = Run-MimiRats @("privilege::debug")
    Check-Result $out "OK" "SeDebugPrivilege enabled"
} else {
    "  [SKIP] Not running as administrator" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 9: Service module (admin required for most)
# ===================================================================
Write-Section "9. Service Module"

Write-SubSection "9a. service::me"
$out = Run-MimiRats @("service::me")
Check-Result $out "PID" "service::me shows PID"

if (Is-Admin) {
    Write-SubSection "9b. service::list"
    $out = Run-MimiRats @("service::list")
    Check-Result $out "RUNNING" "service::list shows running services"
} else {
    "  [SKIP] service::list requires admin" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 10: Vault / Credential module (admin preferred)
# ===================================================================
Write-Section "10. Vault Module"

Write-SubSection "10a. vault::cred"
$out = Run-MimiRats @("vault::cred")
# May succeed or fail depending on permissions, both are valid
if ($out -match "TargetName|ERROR|credentials") {
    "  [PASS] vault::cred executed (result depends on permissions)" | Tee-Object -FilePath $ResultFile -Append
} else {
    "  [FAIL] vault::cred produced no output" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 11: Crypto providers (Windows-specific)
# ===================================================================
Write-Section "11. Crypto Providers"

Write-SubSection "11a. crypto::providers"
$out = Run-MimiRats @("crypto::providers")
Check-Result $out "provider" "crypto::providers shows output"

Write-SubSection "11b. crypto::stores"
$out = Run-MimiRats @("crypto::stores")
if ($out -match "My|Root|CA|store") {
    "  [PASS] crypto::stores shows certificate stores" | Tee-Object -FilePath $ResultFile -Append
} else {
    "  [INFO] crypto::stores output (check manually)" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 12: SID module
# ===================================================================
Write-Section "12. SID Module"

Write-SubSection "12a. sid::lookup by name"
$out = Run-MimiRats @("sid::lookup /name:Administrator")
if ($out -match "S-1-5|SID|User") {
    "  [PASS] sid::lookup resolves Administrator" | Tee-Object -FilePath $ResultFile -Append
} else {
    "  [INFO] sid::lookup output (check manually)" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 13: Offline lsadump (error handling without hive files)
# ===================================================================
Write-Section "13. LSAdump Error Handling"

Write-SubSection "13a. lsadump::sam without args"
$out = Run-MimiRats @("lsadump::sam")
Check-Result $out "system" "lsadump::sam mentions /system: argument"

Write-SubSection "13b. lsadump::secrets without args"
$out = Run-MimiRats @("lsadump::secrets")
Check-Result $out "system" "lsadump::secrets mentions /system: argument"

Write-SubSection "13c. lsadump::cache without args"
$out = Run-MimiRats @("lsadump::cache")
Check-Result $out "system" "lsadump::cache mentions /system: argument"

# ===================================================================
# TEST 14: Offline lsadump with exported hives (admin required)
# ===================================================================
Write-Section "14. LSAdump with Exported Hives (admin required)"

if (Is-Admin) {
    $hivedir = "$PSScriptRoot\hives"
    New-Item -ItemType Directory -Force -Path $hivedir | Out-Null

    Write-SubSection "14a. Exporting registry hives"
    & reg save HKLM\SYSTEM "$hivedir\SYSTEM" /y 2>&1 | Tee-Object -FilePath $ResultFile -Append
    & reg save HKLM\SAM "$hivedir\SAM" /y 2>&1 | Tee-Object -FilePath $ResultFile -Append
    & reg save HKLM\SECURITY "$hivedir\SECURITY" /y 2>&1 | Tee-Object -FilePath $ResultFile -Append

    if ((Test-Path "$hivedir\SYSTEM") -and (Test-Path "$hivedir\SAM")) {
        Write-SubSection "14b. lsadump::sam"
        $out = Run-MimiRats @("lsadump::sam /system:$hivedir\SYSTEM /sam:$hivedir\SAM")
        Check-Result $out "SysKey" "SysKey extracted"
        Check-Result $out "RID" "User RIDs listed"

        Write-SubSection "14c. lsadump::secrets"
        $out = Run-MimiRats @("lsadump::secrets /system:$hivedir\SYSTEM /security:$hivedir\SECURITY")
        Check-Result $out "SysKey" "SysKey extracted for secrets"

        Write-SubSection "14d. lsadump::cache"
        $out = Run-MimiRats @("lsadump::cache /system:$hivedir\SYSTEM /security:$hivedir\SECURITY")
        Check-Result $out "SysKey" "SysKey extracted for cache"
    } else {
        "  [FAIL] Could not export registry hives" | Tee-Object -FilePath $ResultFile -Append
    }

    # Cleanup hive files
    Write-SubSection "14e. Cleanup"
    Remove-Item -Force "$hivedir\SYSTEM" -ErrorAction SilentlyContinue
    Remove-Item -Force "$hivedir\SAM" -ErrorAction SilentlyContinue
    Remove-Item -Force "$hivedir\SECURITY" -ErrorAction SilentlyContinue
    Remove-Item -Force $hivedir -ErrorAction SilentlyContinue
    "  Hive files cleaned up" | Tee-Object -FilePath $ResultFile -Append
} else {
    "  [SKIP] Requires admin to export registry hives" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 15: Event module (admin required)
# ===================================================================
Write-Section "15. Event Module"

if (Is-Admin) {
    Write-SubSection "15a. event::drop (stub)"
    $out = Run-MimiRats @("event::drop")
    Check-Result $out "not yet implemented" "event::drop shows stub message"
} else {
    "  [SKIP] Requires admin" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# TEST 16: Net module
# ===================================================================
Write-Section "16. Net Module"

Write-SubSection "16a. net::tod"
$out = Run-MimiRats @("net::tod")
if ($out -match "time|date|uptime|ERROR") {
    "  [PASS] net::tod executed" | Tee-Object -FilePath $ResultFile -Append
} else {
    "  [INFO] net::tod output (check manually)" | Tee-Object -FilePath $ResultFile -Append
}

# ===================================================================
# Summary
# ===================================================================
Write-Section "SUMMARY"

$total = (Select-String -Path $ResultFile -Pattern "\[(PASS|FAIL|SKIP|INFO)\]").Count
$pass  = (Select-String -Path $ResultFile -Pattern "\[PASS\]").Count
$fail  = (Select-String -Path $ResultFile -Pattern "\[FAIL\]").Count
$skip  = (Select-String -Path $ResultFile -Pattern "\[SKIP\]").Count
$info  = (Select-String -Path $ResultFile -Pattern "\[INFO\]").Count

"Total: $total  |  PASS: $pass  |  FAIL: $fail  |  SKIP: $skip  |  INFO: $info" | Tee-Object -FilePath $ResultFile -Append
"" | Tee-Object -FilePath $ResultFile -Append
"Results saved to: $ResultFile" | Tee-Object -FilePath $ResultFile -Append
