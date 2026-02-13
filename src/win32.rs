//! Windows API utility functions.
//! This module is only compiled on Windows.
#[cfg(windows)]
#[allow(dead_code)]
pub mod api {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, GetTokenInformation, LookupAccountSidW,
        LookupPrivilegeNameW, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TokenStatistics, TokenUser, SID_NAME_USE,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        TOKEN_STATISTICS, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{PCWSTR, PWSTR};

    /// Well-known privilege IDs (matching mimikatz SE_* constants).
    pub const SE_CREATE_TOKEN: u32 = 2;
    pub const SE_ASSIGNPRIMARYTOKEN: u32 = 3;
    pub const SE_LOCK_MEMORY: u32 = 4;
    pub const SE_INCREASE_QUOTA: u32 = 5;
    pub const SE_TCB: u32 = 7;
    pub const SE_SECURITY: u32 = 8;
    pub const SE_TAKE_OWNERSHIP: u32 = 9;
    pub const SE_LOAD_DRIVER: u32 = 10;
    pub const SE_SYSTEM_PROFILE: u32 = 11;
    pub const SE_SYSTEMTIME: u32 = 12;
    pub const SE_INC_BASE_PRIORITY: u32 = 14;
    pub const SE_CREATE_PAGEFILE: u32 = 15;
    pub const SE_BACKUP: u32 = 17;
    pub const SE_RESTORE: u32 = 18;
    pub const SE_SHUTDOWN: u32 = 19;
    pub const SE_DEBUG: u32 = 20;
    pub const SE_AUDIT: u32 = 21;
    pub const SE_SYSTEM_ENVIRONMENT: u32 = 22;
    pub const SE_CHANGE_NOTIFY: u32 = 23;
    pub const SE_UNDOCK: u32 = 25;
    pub const SE_MANAGE_VOLUME: u32 = 28;
    pub const SE_IMPERSONATE: u32 = 29;
    pub const SE_CREATE_GLOBAL: u32 = 30;
    pub const SE_CREATE_SYMBOLIC_LINK: u32 = 35;

    /// Adjust a privilege on the current process token by privilege LUID.
    pub fn adjust_privilege(priv_luid: LUID) -> Result<(), String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .map_err(|e| format!("OpenProcessToken: {}", e))?;

            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                ..Default::default()
            };
            tp.Privileges[0].Luid = priv_luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            let result = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
            CloseHandle(token).ok();

            result.map_err(|e| format!("AdjustTokenPrivileges: {}", e))?;
            Ok(())
        }
    }

    /// Adjust a privilege by its numeric ID (SE_DEBUG=20, etc.).
    pub fn adjust_privilege_by_id(priv_id: u32) -> Result<(), String> {
        let luid = LUID {
            LowPart: priv_id,
            HighPart: 0,
        };
        adjust_privilege(luid)
    }

    /// Adjust a privilege by its name (e.g., "SeDebugPrivilege").
    pub fn adjust_privilege_by_name(name: &str) -> Result<(), String> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid = LUID::default();
        unsafe {
            LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid)
                .map_err(|e| format!("LookupPrivilegeValue: {}", e))?;
        }
        if luid.HighPart != 0 {
            return Err(format!("LUID high part is {}", luid.HighPart));
        }
        adjust_privilege(luid)
    }

    /// Get the privilege name from its LUID.
    pub fn privilege_name_from_luid(luid: &LUID) -> Option<String> {
        unsafe {
            let mut size = 0u32;
            let _ = LookupPrivilegeNameW(
                PCWSTR::null(),
                luid,
                PWSTR::null(),
                &mut size,
            );
            if size == 0 {
                return None;
            }
            let mut buf = vec![0u16; size as usize];
            LookupPrivilegeNameW(
                PCWSTR::null(),
                luid,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
            .ok()?;
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        }
    }

    /// Get username and domain from a process token.
    pub fn get_token_user_info(token: HANDLE) -> Result<(String, String), String> {
        unsafe {
            // First call: get buffer size
            let mut size = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
            if size == 0 {
                return Err("GetTokenInformation(size): failed".into());
            }

            // Second call: get actual data
            let mut buf = vec![0u8; size as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                size,
                &mut size,
            )
            .map_err(|e| format!("GetTokenInformation: {}", e))?;

            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid = user.User.Sid;

            // First call: get buffer sizes for name and domain
            let mut name_size = 0u32;
            let mut domain_size = 0u32;
            let mut sid_type = SID_NAME_USE::default();
            let _ = LookupAccountSidW(
                PCWSTR::null(),
                sid,
                PWSTR::null(),
                &mut name_size,
                PWSTR::null(),
                &mut domain_size,
                &mut sid_type,
            );

            // Second call: get actual name and domain
            let mut name_buf = vec![0u16; name_size as usize];
            let mut domain_buf = vec![0u16; domain_size as usize];
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_size,
                PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_size,
                &mut sid_type,
            )
            .map_err(|e| format!("LookupAccountSid: {}", e))?;

            let name = String::from_utf16_lossy(&name_buf[..name_size as usize]);
            let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);
            Ok((domain, name))
        }
    }

    /// Get token statistics (token type, impersonation level, etc.).
    pub fn get_token_statistics(token: HANDLE) -> Result<TOKEN_STATISTICS, String> {
        unsafe {
            let mut stats = TOKEN_STATISTICS::default();
            let mut size = 0u32;
            GetTokenInformation(
                token,
                TokenStatistics,
                Some(&mut stats as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_STATISTICS>() as u32,
                &mut size,
            )
            .map_err(|e| format!("GetTokenInformation(Statistics): {}", e))?;
            Ok(stats)
        }
    }
}
