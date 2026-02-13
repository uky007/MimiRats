# MimiRats Functional Test Script
# Usage: Place MimiRats.exe and this script in the same directory, then run:
#   powershell -ExecutionPolicy Bypass -File run_tests.ps1
# Output: test_results.txt (in current directory)
#
# Run WITHOUT admin  -> basic + crypto tests
# Run WITH admin     -> basic + crypto + privilege + service + credential tests

$ErrorActionPreference = "Continue"
$Binary = ".\MimiRats.exe"
$ResultFile = ".\test_results.txt"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Section($title) {
    $sep = "=" * 72
    "$sep`n[$title]`n$sep" | Out-Log
}

function Write-SubSection($title) {
    "`n--- $title ---" | Out-Log
}

function Out-Log {
    param([Parameter(ValueFromPipeline=$true)][string]$Text)
    process {
        if ($Text -ne $null) {
            Write-Host $Text
            [System.IO.File]::AppendAllText($ResultFile, "$Text`r`n")
        }
    }
}

function Run-MimiRats {
    param([string[]]$Commands)
    $input_text = ($Commands + "exit") -join "`n"
    $result = $input_text | & $Binary 2>&1
    $output = $result -join "`n"
    $output | Out-Log
    return $output
}

function Run-MimiRats-Cmdline {
    param([string]$Cmd)
    $result = & $Binary $Cmd "exit" 2>&1
    $output = $result -join "`n"
    $output | Out-Log
    return $output
}

function Check-Result($output, $expected, $testname) {
    if ($output -match [regex]::Escape($expected)) {
        "  [PASS] $testname" | Out-Log
    } else {
        "  [FAIL] $testname (expected: '$expected')" | Out-Log
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

[System.IO.File]::WriteAllText($ResultFile, "")
"MimiRats Functional Test Report" | Out-Log
"Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-Log
"Host: $env:COMPUTERNAME" | Out-Log
"OS:   $([System.Environment]::OSVersion.VersionString)" | Out-Log
"Admin: $(Is-Admin)" | Out-Log
"Binary: $Binary" | Out-Log

# Check binary exists
if (-not (Test-Path $Binary)) {
    "ERROR: MimiRats.exe not found in current directory" | Out-Log
    "Place MimiRats.exe in the same directory as this script" | Out-Log
    exit 1
}

"Binary size: $((Get-Item $Binary).Length) bytes" | Out-Log
"" | Out-Log

# ===================================================================
# TEST 1: Banner and REPL
# ===================================================================
Write-Section "1. Banner and REPL"

Write-SubSection "1a. Banner display"
$out = Run-MimiRats @()
Check-Result $out "MimiRats" "Banner contains 'MimiRats'"
Check-Result $out "Rust edition" "Banner contains 'Rust edition'"
Check-Result $out "mimrats #" "REPL prompt displayed"

Write-SubSection "1b. Command-line mode"
$out = Run-MimiRats-Cmdline "version"
Check-Result $out "MimiRats" "Cmdline mode works"

# ===================================================================
# TEST 2: Standard module
# ===================================================================
Write-Section "2. Standard Module"

Write-SubSection "2a. version"
$out = Run-MimiRats @("version")
Check-Result $out "MimiRats" "version command"

Write-SubSection "2b. coffee"
$out = Run-MimiRats @("coffee")
Check-Result $out "Coffee" "coffee command"

Write-SubSection "2c. answer"
$out = Run-MimiRats @("answer")
Check-Result $out "42" "answer command"

Write-SubSection "2d. cd"
$out = Run-MimiRats @("cd")
Check-Result $out ":\" "cd shows current directory"

Write-SubSection "2e. module listing"
$out = Run-MimiRats @("unknownmodule::")
Check-Result $out "standard" "Module list shows standard"
Check-Result $out "sekurlsa" "Module list shows sekurlsa"
Check-Result $out "lsadump" "Module list shows lsadump"
Check-Result $out "kerberos" "Module list shows kerberos"

# ===================================================================
# TEST 3: Crypto module (cross-platform, fully implemented)
# ===================================================================
Write-Section "3. Crypto Module"

Write-SubSection "3a. crypto::hash - empty password"
$out = Run-MimiRats @("crypto::hash /password:")
Check-Result $out "31d6cfe0d16ae931b73c59d7e0c089c0" "NTLM of empty password"
Check-Result $out "aad3b435b51404eeaad3b435b51404ee" "LM of empty password"

Write-SubSection "3b. crypto::hash - 'mimikatz'"
$out = Run-MimiRats @("crypto::hash /password:mimikatz")
Check-Result $out "60ba4fcadc466c7a033c178194c03df6" "NTLM of 'mimikatz'"
Check-Result $out "MD5" "MD5 hash displayed"
Check-Result $out "SHA1" "SHA1 hash displayed"
Check-Result $out "SHA256" "SHA256 hash displayed"

Write-SubSection "3c. crypto::hash - with DCC"
$out = Run-MimiRats @("crypto::hash /password:Password /user:admin")
Check-Result $out "NTLM" "NTLM displayed"
Check-Result $out "DCC1" "DCC1 computed"
Check-Result $out "DCC2" "DCC2 computed"

Write-SubSection "3d. crypto::hash - special chars"
$out = Run-MimiRats @("crypto::hash /password:P@ssw0rd!")
Check-Result $out "NTLM" "NTLM for special chars"

# ===================================================================
# TEST 4: Kerberos module (hash - cross-platform)
# ===================================================================
Write-Section "4. Kerberos Module"

Write-SubSection "4a. kerberos::hash"
$out = Run-MimiRats @("kerberos::hash /password:Password /user:admin /domain:CONTOSO.LOCAL")
Check-Result $out "rc4_hmac" "RC4-HMAC key"
Check-Result $out "aes256" "AES256 key"
Check-Result $out "aes128" "AES128 key"

# ===================================================================
# TEST 5: Module help display
# ===================================================================
Write-Section "5. Module Help"

Write-SubSection "5a. sekurlsa::"
$out = Run-MimiRats @("sekurlsa::")
Check-Result $out "logonPasswords" "sekurlsa help shows logonPasswords"
Check-Result $out "msv" "sekurlsa help shows msv"

Write-SubSection "5b. lsadump::"
$out = Run-MimiRats @("lsadump::")
Check-Result $out "sam" "lsadump help shows sam"
Check-Result $out "secrets" "lsadump help shows secrets"
Check-Result $out "cache" "lsadump help shows cache"
Check-Result $out "dcsync" "lsadump help shows dcsync"

Write-SubSection "5c. privilege::"
$out = Run-MimiRats @("privilege::")
Check-Result $out "debug" "privilege help shows debug"

Write-SubSection "5d. crypto::"
$out = Run-MimiRats @("crypto::")
Check-Result $out "hash" "crypto help shows hash"
Check-Result $out "providers" "crypto help shows providers"
Check-Result $out "certificates" "crypto help shows certificates"

Write-SubSection "5e. process::"
$out = Run-MimiRats @("process::")
Check-Result $out "list" "process help shows list"

Write-SubSection "5f. dpapi::"
$out = Run-MimiRats @("dpapi::")
Check-Result $out "masterkeys" "dpapi help shows masterkeys"

# ===================================================================
# TEST 6: Process module
# ===================================================================
Write-Section "6. Process Module"

Write-SubSection "6a. process::list"
$out = Run-MimiRats @("process::list")
Check-Result $out "PID" "Process list header"

# ===================================================================
# TEST 7: Privilege tests (admin required)
# ===================================================================
Write-Section "7. Privilege Module (admin required)"

if (Is-Admin) {
    Write-SubSection "7a. privilege::debug"
    $out = Run-MimiRats @("privilege::debug")
    Check-Result $out "OK" "SeDebugPrivilege enabled"
} else {
    "  [SKIP] Not running as administrator" | Out-Log
}

# ===================================================================
# TEST 8: Service module (admin required for most)
# ===================================================================
Write-Section "8. Service Module"

Write-SubSection "8a. service::me"
$out = Run-MimiRats @("service::me")
Check-Result $out "PID" "service::me shows PID"

if (Is-Admin) {
    Write-SubSection "8b. service::list"
    $out = Run-MimiRats @("service::list")
    Check-Result $out "RUNNING" "service::list shows running services"
} else {
    "  [SKIP] service::list requires admin" | Out-Log
}

# ===================================================================
# TEST 9: Vault / Credential module (admin preferred)
# ===================================================================
Write-Section "9. Vault Module"

Write-SubSection "9a. vault::cred"
$out = Run-MimiRats @("vault::cred")
if ($out -match "TargetName|ERROR|credentials") {
    "  [PASS] vault::cred executed (result depends on permissions)" | Out-Log
} else {
    "  [FAIL] vault::cred produced no output" | Out-Log
}

# ===================================================================
# TEST 10: Crypto providers (Windows-specific)
# ===================================================================
Write-Section "10. Crypto Providers"

Write-SubSection "10a. crypto::providers"
$out = Run-MimiRats @("crypto::providers")
Check-Result $out "provider" "crypto::providers shows output"

Write-SubSection "10b. crypto::stores"
$out = Run-MimiRats @("crypto::stores")
if ($out -match "My|Root|CA|store") {
    "  [PASS] crypto::stores shows certificate stores" | Out-Log
} else {
    "  [INFO] crypto::stores output (check manually)" | Out-Log
}

# ===================================================================
# TEST 11: SID module
# ===================================================================
Write-Section "11. SID Module"

Write-SubSection "11a. sid::lookup by name"
$out = Run-MimiRats @("sid::lookup /name:Administrator")
if ($out -match "S-1-5|SID|User") {
    "  [PASS] sid::lookup resolves Administrator" | Out-Log
} else {
    "  [INFO] sid::lookup output (check manually)" | Out-Log
}

# ===================================================================
# TEST 12: Offline lsadump (error handling without hive files)
# ===================================================================
Write-Section "12. LSAdump Error Handling"

Write-SubSection "12a. lsadump::sam without args"
$out = Run-MimiRats @("lsadump::sam")
Check-Result $out "system" "lsadump::sam mentions /system: argument"

Write-SubSection "12b. lsadump::secrets without args"
$out = Run-MimiRats @("lsadump::secrets")
Check-Result $out "system" "lsadump::secrets mentions /system: argument"

Write-SubSection "12c. lsadump::cache without args"
$out = Run-MimiRats @("lsadump::cache")
Check-Result $out "system" "lsadump::cache mentions /system: argument"

# ===================================================================
# TEST 13: Offline lsadump with exported hives (admin required)
# ===================================================================
Write-Section "13. LSAdump with Exported Hives (admin required)"

if (Is-Admin) {
    $hivedir = ".\hives"
    New-Item -ItemType Directory -Force -Path $hivedir | Out-Null

    Write-SubSection "13a. Exporting registry hives"
    & reg save HKLM\SYSTEM "$hivedir\SYSTEM" /y 2>&1 | Out-Log
    & reg save HKLM\SAM "$hivedir\SAM" /y 2>&1 | Out-Log
    & reg save HKLM\SECURITY "$hivedir\SECURITY" /y 2>&1 | Out-Log

    if ((Test-Path "$hivedir\SYSTEM") -and (Test-Path "$hivedir\SAM")) {
        Write-SubSection "13b. lsadump::sam"
        $out = Run-MimiRats @("lsadump::sam /system:$hivedir\SYSTEM /sam:$hivedir\SAM")
        Check-Result $out "SysKey" "SysKey extracted"
        Check-Result $out "RID" "User RIDs listed"

        Write-SubSection "13c. lsadump::secrets"
        $out = Run-MimiRats @("lsadump::secrets /system:$hivedir\SYSTEM /security:$hivedir\SECURITY")
        Check-Result $out "SysKey" "SysKey extracted for secrets"

        Write-SubSection "13d. lsadump::cache"
        $out = Run-MimiRats @("lsadump::cache /system:$hivedir\SYSTEM /security:$hivedir\SECURITY")
        Check-Result $out "SysKey" "SysKey extracted for cache"
    } else {
        "  [FAIL] Could not export registry hives" | Out-Log
    }

    # Cleanup hive files
    Write-SubSection "13e. Cleanup"
    Remove-Item -Force "$hivedir\SYSTEM" -ErrorAction SilentlyContinue
    Remove-Item -Force "$hivedir\SAM" -ErrorAction SilentlyContinue
    Remove-Item -Force "$hivedir\SECURITY" -ErrorAction SilentlyContinue
    Remove-Item -Force $hivedir -ErrorAction SilentlyContinue
    "  Hive files cleaned up" | Out-Log
} else {
    "  [SKIP] Requires admin to export registry hives" | Out-Log
}

# ===================================================================
# TEST 14: Event module (admin required)
# ===================================================================
Write-Section "14. Event Module"

if (Is-Admin) {
    Write-SubSection "14a. event::drop (stub)"
    $out = Run-MimiRats @("event::drop")
    Check-Result $out "not yet implemented" "event::drop shows stub message"
} else {
    "  [SKIP] Requires admin" | Out-Log
}

# ===================================================================
# TEST 15: Net module
# ===================================================================
Write-Section "15. Net Module"

Write-SubSection "15a. net::tod"
$out = Run-MimiRats @("net::tod")
if ($out -match "time|date|uptime|ERROR") {
    "  [PASS] net::tod executed" | Out-Log
} else {
    "  [INFO] net::tod output (check manually)" | Out-Log
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

"Total: $total  |  PASS: $pass  |  FAIL: $fail  |  SKIP: $skip  |  INFO: $info" | Out-Log
"" | Out-Log
"Results saved to: $ResultFile" | Out-Log
