use std::ffi::OsStr;
use winreg::enums::*;
use winreg::types::FromRegValue;
use winreg::RegKey;

pub struct RegConfig {
    hive: Option<RegKey>,
}

impl RegConfig {
    pub fn new() -> Self {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        match hklm.create_subkey_with_flags(
            "SYSTEM\\CurrentControlSet\\Control\\Lsa\\HIBPPwdFlt",
            KEY_READ,
        ) {
            Ok((h, _)) => Self { hive: Some(h) },
            _ => Self { hive: None },
        }
    }

    pub fn get_or<T: FromRegValue, N: AsRef<OsStr>>(&self, name: N, fallback: T) -> T {
        match self.hive {
            Some(ref h) => match h.get_value(name) {
                Ok(value) => value,
                Err(_) => fallback,
            },
            None => fallback,
        }
    }
}
