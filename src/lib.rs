#![cfg(windows)]

extern crate winapi;
extern crate md4;
extern crate winreg;

mod config;
mod chdb;
mod winctype;

use winapi::shared::ntdef::{BOOLEAN, PUNICODE_STRING};
use md4::{Md4, Digest};

use winctype::PunicodeExt;
use chdb::CompactHashDB;
use config::RegConfig;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "stdcall" fn PasswordFilter (account_name: PUNICODE_STRING, full_name: PUNICODE_STRING, password: PUNICODE_STRING, set_operation: BOOLEAN) -> BOOLEAN {
    let pwd = password.to_bytes();
    let result = password_filter(pwd, set_operation != 0);

    return result as BOOLEAN;
}

fn password_filter(password: &[u8], set_operation: bool) -> bool {
    let settings = RegConfig::new();
    let on_error: bool  = settings.get_or("RejectOnError", 0u32) == 0;
    let check_on_set: bool = settings.get_or("CheckOnSet", 0u32) != 0; 
    let db_path: String = settings.get_or("DBPath", String::from("C:\\Windows\\System32\\HIBPPwdFlt\\hibp.chdb"));

    if set_operation && !check_on_set {
        return true;
    }

    match CompactHashDB::open(&db_path) {
        Ok(mut db) => match db.find_hash(&Md4::digest(password)) {
            Ok(b) => !b,
            Err(_) => on_error
        },
        Err(_) => on_error
    }
}
