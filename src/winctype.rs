use std::slice;
use winapi::shared::ntdef::PUNICODE_STRING;

/*
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}
type PUNICODE_STRING = *mut UNICODE_STRING;
*/

pub trait PunicodeExt {
    fn to_bytes<'a>(self) -> &'a [u8];
}

impl PunicodeExt for PUNICODE_STRING {
    fn to_bytes<'a>(self) -> &'a [u8] {
        unsafe { slice::from_raw_parts_mut((*self).Buffer as *mut u8, (*self).Length as usize) }
    }
}
