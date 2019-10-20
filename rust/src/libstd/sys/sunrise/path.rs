use crate::path::{PrefixComponent, Prefix};
use crate::ffi::OsStr;

#[inline]
pub fn is_sep_byte(b: u8) -> bool {
    b == b'/'
}

#[inline]
pub fn is_verbatim_sep(b: u8) -> bool {
    b == b'/'
}

pub fn parse_prefix(path: &OsStr) -> Option<PrefixComponent<'_>> {
    if let Some(path_str) = path.to_str() {
        path_str.split('/').next()
            .and_then(|s| s.bytes().position(|v| v == b':'))
            .map(|idx| PrefixComponent::from_os_str_kind(OsStr::new(&path_str[..idx + 1]), Prefix::Disk(0)))
    } else {
        None
    }
}

pub const MAIN_SEP_STR: &'static str = "/";
pub const MAIN_SEP: char = '/';
