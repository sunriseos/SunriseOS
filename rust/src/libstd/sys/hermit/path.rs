use crate::ffi::OsStr;
use crate::path::PrefixComponent;

#[inline]
pub fn is_sep_byte(b: u8) -> bool {
    b == b'/'
}

#[inline]
pub fn is_verbatim_sep(b: u8) -> bool {
    b == b'/'
}

pub fn parse_prefix(_: &OsStr) -> Option<PrefixComponent<'_>> {
    None
}

pub const MAIN_SEP_STR: &str = "/";
pub const MAIN_SEP: char = '/';
