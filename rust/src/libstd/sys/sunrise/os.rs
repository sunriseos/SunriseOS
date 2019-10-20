use crate::os::sunrise::prelude::*;

use crate::error::Error as StdError;
use crate::ffi::{OsStr, OsString};
use crate::fmt;
use crate::iter;
use crate::io;
use crate::path::{self, PathBuf};
use crate::slice;
use crate::str;
use crate::sync::Mutex;
use crate::vec::Vec;
use crate::collections::HashMap;
use lazy_static::lazy_static;
pub fn errno() -> i32 {
    0
}

pub fn error_string(_errno: i32) -> String {
    "operation successful".to_string()
}

pub fn getcwd() -> io::Result<PathBuf> {
    Ok(crate::env::var_os("PWD").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("system:/")
    }))
}

pub fn chdir(path: &path::Path) -> io::Result<()> {
    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Entry not found"))
    }

    setenv(OsStr::new("PWD"), path.as_os_str())
}

pub struct SplitPaths<'a> {
    iter: iter::Map<slice::Split<'a, u8, fn(&u8) -> bool>,
                    fn(&'a [u8]) -> PathBuf>,
}

pub fn split_paths(unparsed: &OsStr) -> SplitPaths<'_> {
    fn bytes_to_path(b: &[u8]) -> PathBuf {
        PathBuf::from(<OsStr as OsStrExt>::from_bytes(b))
    }
    fn is_semicolon(b: &u8) -> bool { *b == b';' }
    let unparsed = unparsed.as_bytes();
    SplitPaths {
        iter: unparsed.split(is_semicolon as fn(&u8) -> bool)
                      .map(bytes_to_path as fn(&[u8]) -> PathBuf)
    }
}

impl<'a> Iterator for SplitPaths<'a> {
    type Item = PathBuf;
    fn next(&mut self) -> Option<PathBuf> { self.iter.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

#[derive(Debug)]
pub struct JoinPathsError;

pub fn join_paths<I, T>(paths: I) -> Result<OsString, JoinPathsError>
    where I: Iterator<Item=T>, T: AsRef<OsStr>
{
    let mut joined = Vec::new();
    let sep = b';';

    for (i, path) in paths.enumerate() {
        let path = path.as_ref().as_bytes();
        if i > 0 { joined.push(sep) }
        if path.contains(&sep) {
            return Err(JoinPathsError)
        }
        joined.extend_from_slice(path);
    }
    Ok(OsStringExt::from_vec(joined))
}

impl fmt::Display for JoinPathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "path segment contains separator `:`".fmt(f)
    }
}

impl StdError for JoinPathsError {
    fn description(&self) -> &str { "failed to join paths" }
}

pub fn current_exe() -> io::Result<PathBuf> {
    panic!("not supported on sunrise yet")
}

lazy_static! {
    /// Storage of all events of the current process.
    static ref ENVIRONMENT_STORAGE: Mutex<HashMap<OsString, OsString>> = Mutex::new(HashMap::new());
}

pub struct Env(Vec<(OsString, OsString)>, usize);

impl Iterator for Env {
    type Item = (OsString, OsString);
    fn next(&mut self) -> Option<(OsString, OsString)> {
        let res = self.0.get(self.1).map(|x| x.clone());
        self.1 += 1;

        res
    }
}

pub fn env() -> Env {
    let env: Vec<(OsString, OsString)> = ENVIRONMENT_STORAGE.lock().unwrap().iter().map(|x| (x.0.clone(), x.1.clone())).collect();
    Env(env, 0)
}

pub fn getenv(k: &OsStr) -> io::Result<Option<OsString>> {
    Ok(ENVIRONMENT_STORAGE.lock().unwrap().get(&k.to_os_string()).map(|v| v.to_os_string()))
}

pub fn setenv(k: &OsStr, v: &OsStr) -> io::Result<()> {
    ENVIRONMENT_STORAGE.lock().unwrap().insert(k.to_os_string(), v.to_os_string());
    Ok(())
}

pub fn unsetenv(k: &OsStr) -> io::Result<()> {
    ENVIRONMENT_STORAGE.lock().unwrap().remove(&k.to_os_string());
    Ok(())
}

pub fn temp_dir() -> PathBuf {
    crate::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("/tmp")
    })
}

pub fn home_dir() -> Option<PathBuf> {
    return crate::env::var_os("HOME").map(PathBuf::from);
}

pub fn exit(_code: i32) -> ! {
    // TODO(Sunrise): propagate the error code somehow
    sunrise_libuser::syscalls::exit_process()
}

pub fn getpid() -> u32 {
    panic!("not supported on sunrise yet")
}
