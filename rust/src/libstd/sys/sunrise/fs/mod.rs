use crate::ffi::OsString;
use crate::fmt;
use crate::io::{self, SeekFrom, IoSlice, IoSliceMut};
use crate::sys::time::{UNIX_EPOCH, SystemTime};
use crate::sys::unsupported;
use crate::time::Duration;
use crate::path::{Component, Path, PathBuf};

use crate::sync::Arc;
use crate::collections::HashMap;
use lazy_static::lazy_static;
use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType, FileTimeStampRaw, IDirectoryProxy, IFileSystemServiceProxy, IFileSystemProxy, IFileProxy};

use crate::sys::os::getcwd;
use crate::sync::Mutex;

use crate::io::{Error, ErrorKind};

use sunrise_libuser::error::{Error as LibUserError, FileSystemError};

pub use crate::sys_common::fs::remove_dir_all;

#[stable(feature = "rust1", since = "1.0.0")]
impl From<LibUserError> for Error {
    fn from(user_error: LibUserError) -> Error {
        match user_error {
            LibUserError::FileSystem(error, _) => {
                match error {
                    FileSystemError::Unknown => Error::new(ErrorKind::Other, "Unknown FileSystem IO Error."),
                    FileSystemError::PathNotFound | FileSystemError::FileNotFound | FileSystemError::DirectoryNotFound =>
                        Error::new(ErrorKind::NotFound, "The given resource couldn't be found."),
                    FileSystemError::PathExists => Error::new(ErrorKind::AlreadyExists, "A resource at the given path already exist."),
                    FileSystemError::InUse => Error::new(ErrorKind::Other, "Resource already in use."),
                    FileSystemError::NoSpaceLeft => Error::new(ErrorKind::Other, "There isn't enough space for a resource to be stored."),
                    FileSystemError::InvalidPartition => Error::new(ErrorKind::Other, "The partition wasn't used as it's invalid."),
                    FileSystemError::OutOfRange => Error::new(ErrorKind::Other, "Specified value is out of range."),
                    FileSystemError::WriteFailed => Error::new(ErrorKind::Other, "A write operation failed on the attached storage device."),
                    FileSystemError::ReadFailed => Error::new(ErrorKind::Other, "A read operation failed on the attached storage device."),
                    FileSystemError::PartitionNotFound => Error::new(ErrorKind::Other, "The given partition cannot be found."),
                    FileSystemError::InvalidInput => Error::new(ErrorKind::InvalidInput, "A parameter was incorrect."),
                    FileSystemError::PathTooLong => Error::new(ErrorKind::InvalidData, "The given path is too long to be resolved."),
                    FileSystemError::AccessDenied => Error::new(ErrorKind::PermissionDenied, "The operation lacked the necessary privileges to complete."),
                    FileSystemError::UnsupportedOperation => Error::new(ErrorKind::Other, "The requested operation isn't supported by the detail."),
                    FileSystemError::NotAFile => Error::new(ErrorKind::Other, "The given resource cannot be represented as a file."),
                    FileSystemError::NotADirectory => Error::new(ErrorKind::Other, "The given resource cannot be represented as a directory."),
                    FileSystemError::DiskNotFound => Error::new(ErrorKind::Other, "The given disk id doesn't correspond to a any known disk."),
                    _ => Error::new(ErrorKind::Other, "Unknown Libuser Filesystem Error.")
                }
            },
            _ => Error::new(ErrorKind::Other, "Unknown Libuser IO Error.")
        }
    }
}


lazy_static! {
    /// Registry of all filesystem prefix registered
    static ref SCHEMA_REGISTRY: Mutex<HashMap<&'static str, Arc<IFileSystemProxy>>> = Mutex::new(HashMap::new());
}

#[cfg(not(test))]
pub fn init() {
    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let system_filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();
    SCHEMA_REGISTRY.lock().unwrap().insert("system", Arc::new(system_filesystem));
}

fn get_filesystem(path: &Path) -> io::Result<(Arc<IFileSystemProxy>, &str, &Path)> {
    assert!(path.is_absolute(), "path is not absolute? {:?}", path);

    let mut iter = path.components();
    let prefix = match iter.next() {
        Some(Component::Prefix(prefix)) => prefix.as_os_str().to_str().unwrap().trim_end_matches(':'),
        _ => panic!("If path is absolute, it should start with prefix")
    };
    
    for (key, value) in SCHEMA_REGISTRY.lock().unwrap().iter() {
        if prefix == *key {
            return Ok((Arc::clone(&value), prefix, &iter.as_path()))
        }
    }

    unsupported()
}

pub struct File {
    inner: IFileProxy,
    offset: Mutex<u64>,
    path: PathBuf
}

#[derive(Clone, Debug)]
pub struct FileAttr(PathBuf, u64, FileType);


#[derive(Debug)]
pub struct ReadDir(IDirectoryProxy, String);

#[derive(Clone, Debug)]
pub struct DirEntry(DirectoryEntry, String);

#[derive(Clone, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FilePermissions;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct FileType(bool);

#[derive(Debug)]
pub struct DirBuilder { }

impl FileAttr {
    pub fn size(&self) -> u64 {
        self.1
    }

    pub fn perm(&self) -> FilePermissions {
        FilePermissions
    }

    pub fn file_type(&self) -> FileType {
        self.2
    }

    fn get_timestamp_raw(&self) -> io::Result<FileTimeStampRaw> {
        let path = getcwd()?.join(self.0.clone());
        let (fs, _, path) = get_filesystem(&path)?;
        let path_bytes = path.to_str().unwrap().as_bytes();
        let mut raw_path = [0x0; 0x300];
        raw_path[..path_bytes.len()].copy_from_slice(path_bytes);

        let res = fs.get_file_timestamp_raw(&raw_path)?;

        Ok(res)
    }

    pub fn modified(&self) -> io::Result<SystemTime> {
        let timestamp = self.get_timestamp_raw()?;
        let modified_timestamp = Duration::from_secs(timestamp.modified_timestamp);
        UNIX_EPOCH.checked_add_duration(&modified_timestamp).ok_or_else(|| Error::new(ErrorKind::Other, "Timestamp overflowed outside of SystemTime range"))
    }

    pub fn accessed(&self) -> io::Result<SystemTime> {
        let timestamp = self.get_timestamp_raw()?;
        let accessed_timestamp = Duration::from_secs(timestamp.accessed_timestamp);
        UNIX_EPOCH.checked_add_duration(&accessed_timestamp).ok_or_else(|| Error::new(ErrorKind::Other, "Timestamp overflowed outside of SystemTime range"))
    }

    pub fn created(&self) -> io::Result<SystemTime> {
        let timestamp = self.get_timestamp_raw()?;
        let creation_timestamp = Duration::from_secs(timestamp.creation_timestamp);
        UNIX_EPOCH.checked_add_duration(&creation_timestamp).ok_or_else(|| Error::new(ErrorKind::Other, "Timestamp overflowed outside of SystemTime range"))
    }
}

impl FilePermissions {
    pub fn readonly(&self) -> bool {
        // TODO(Sunrise): We don't have permissions on Sunrise.
        false
    }

    pub fn set_readonly(&mut self, _readonly: bool) {
        // TODO(Sunrise): We don't have permissions on Sunrise.
    }
}

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.0
    }

    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    pub fn is_symlink(&self) -> bool {
        false
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        let mut entries = [DirectoryEntry {
            path: [0; 0x300], attribute: 0,
            directory_entry_type: DirectoryEntryType::Directory, file_size: 0
        }; 1];

        let read_result = self.0.read(&mut entries);
        if let Err(error) = read_result {
            return Some(Err(error.into()));
        }

        let count = read_result.unwrap();
        
        if count == 0 {
            return None;
        }

        Some(Ok(DirEntry(entries[0], self.1.clone())))
    }
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        let s = crate::str::from_utf8(&self.0.path).expect("Invalid path for DirEntry").trim_matches('\0');
        let mut res = PathBuf::from(self.1.clone());
        res.push(s);

        res
    }

    pub fn file_name(&self) -> OsString {
        OsString::from(self.path().file_name().expect("No file_name availaible for the DirEntry path"))
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        Ok(FileAttr(self.path(), self.0.file_size, self.file_type()?))
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        Ok(FileType(self.0.directory_entry_type == DirectoryEntryType::Directory))
    }
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false
        }
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    pub fn create(&mut self, create: bool) {
        self.create = create;
        self.append(true);
    }
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
        self.append(true);
    }
}

impl File {
    pub fn open(p: &Path, opts: &OpenOptions) -> io::Result<File> {
        let path = getcwd()?.join(p);
        let (fs, _, path) = get_filesystem(&path)?;

        let path_bytes = path.to_str().unwrap().as_bytes();
        let mut raw_path = [0x0; 0x300];
        raw_path[..path_bytes.len()].copy_from_slice(path_bytes);

        let need_create = opts.create_new || opts.create;

        if need_create {
            let res = fs.create_file(0, 0, &raw_path);

            if res.is_err() && opts.create_new {
                let _ = res?;
            }
        }
        
        let mut flags = 0;

        if opts.read {
            flags |= 1;
        }

        if opts.write {
            flags |= 1 << 1;
        }

        if opts.append {
            flags |= 1 << 2;
        }

        Ok(File {
            path: path.to_path_buf(),
            inner: fs.open_file(flags, &raw_path)?,
            offset: Mutex::new(0)
        })
    }

    pub fn file_attr(&self) -> io::Result<FileAttr> {
        Ok(FileAttr(self.path.clone(), self.inner.get_size()?, FileType(false)))
    }

    pub fn fsync(&self) -> io::Result<()> {
        self.flush()
    }

    pub fn datasync(&self) -> io::Result<()> {
        self.flush()
    }

    pub fn truncate(&self, size: u64) -> io::Result<()> {
        self.inner.set_size(size)?;

        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offset = self.offset.try_lock().unwrap();

        let out = self.inner.read(0, *offset, buf.len() as u64, buf)?;

        *offset += out as u64;

        Ok(out as usize)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        crate::io::default_read_vectored(|buf| self.read(buf), bufs)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut offset = self.offset.try_lock().unwrap();

        self.inner.write(0, *offset, buf.len() as u64, buf)?;

        *offset += buf.len() as u64;

        Ok(buf.len())
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        crate::io::default_write_vectored(|buf| self.write(buf), bufs)
    }

    pub fn flush(&self) -> io::Result<()> {
        self.inner.flush()?;

        Ok(())
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let mut offset = self.offset.try_lock().unwrap();

        let newpos = match pos {
            SeekFrom::Current(pos) => {
                let newval = *offset as i64 + pos;

                if newval < 0 {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                } else {
                    *offset = newval as u64;
                }

                newval as u64
            }
            SeekFrom::Start(pos) => {
                *offset = pos;

                pos
            },
            SeekFrom::End(pos) => {
                let size = self.inner.get_size()?;

                let newpos = size as i64 + pos;

                if newpos < 0 {
                    Err(io::Error::from(io::ErrorKind::InvalidInput))?
                }

                *offset = newpos as u64;

                newpos as u64
            }
        };

        Ok(newpos)
    }

    pub fn duplicate(&self) -> io::Result<File> {
        // TODO(Sunrise): Used by try_clone()
        // BODY: Only insane people uses this.
        unsupported()
    }

    pub fn set_permissions(&self, _perm: FilePermissions) -> io::Result<()> {
        Ok(())
    }
}

impl DirBuilder {
    pub fn new() -> DirBuilder {
        DirBuilder { }
    }

    pub fn mkdir(&self, path: &Path) -> io::Result<()> {
        let path = getcwd()?.join(path);
        let (fs, _, path) = get_filesystem(&path)?;
        let path_bytes = path.to_str().unwrap().as_bytes();

        let mut path = [0x0; 0x300];
        path[..path_bytes.len()].copy_from_slice(path_bytes);

        fs.create_directory(&path)?;

        Ok(())
    }
}

impl fmt::Debug for File {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!();
    }
}

pub fn readdir(path: &Path) -> io::Result<ReadDir> {
    let path = getcwd()?.join(path);
    let (fs, prefix, path) = get_filesystem(&path)?;

    let path_bytes = path.to_str().unwrap().as_bytes();

    let mut path = [0x0; 0x300];
    path[..path_bytes.len()].copy_from_slice(path_bytes);

    let res = ReadDir(fs.open_directory(3, &path)?, String::from(prefix));

    Ok(res)
}

pub fn unlink(path: &Path) -> io::Result<()> {
    let path = getcwd()?.join(path);
    let (fs, _, path) = get_filesystem(&path)?;

    let path_bytes = path.to_str().unwrap().as_bytes();

    let mut path = [0x0; 0x300];
    path[..path_bytes.len()].copy_from_slice(path_bytes);

    fs.delete_file(&path)?;

    Ok(())
}

pub fn rename(old: &Path, new: &Path) -> io::Result<()> {
    let old = getcwd()?.join(old);
    let (old_fs, old_prefix, old) = get_filesystem(&old)?;

    let old_path_bytes = old.to_str().unwrap().as_bytes();
    let mut old_path = [0x0; 0x300];
    old_path[..old_path_bytes.len()].copy_from_slice(old_path_bytes);

    let new = getcwd()?.join(new);
    let (_, new_prefix, _) = get_filesystem(&new)?;

    let new_path_bytes = new.to_str().unwrap().as_bytes();
    let mut new_path = [0x0; 0x300];
    new_path[..new_path_bytes.len()].copy_from_slice(new_path_bytes);

    let is_dir = old.is_dir();

    if *old_prefix != *new_prefix {
        return Err(Error::new(ErrorKind::InvalidInput, "Not in the same filesystem"))
    }

    if is_dir {
        old_fs.rename_directory(&old_path, &new_path)?;
    } else {
        old_fs.rename_file(&old_path, &new_path)?;
    }

    Ok(())
}

pub fn set_perm(p: &Path, perm: FilePermissions) -> io::Result<()> {
    let mut opts = OpenOptions::new();

    opts.read(true);
    opts.write(true);

    let file = File::open(p, &opts)?;
    file.set_permissions(perm)
}

pub fn rmdir(path: &Path) -> io::Result<()> {
    let path = getcwd()?.join(path);
    let (fs, _, path) = get_filesystem(&path)?;

    let path_bytes = path.to_str().unwrap().as_bytes();

    let mut path = [0x0; 0x300];
    path[..path_bytes.len()].copy_from_slice(path_bytes);

    fs.delete_directory(&path)?;

    Ok(())
}

pub fn readlink(_p: &Path) -> io::Result<PathBuf> {
    // FIXME: found the error used for non symlink here.
    unsupported()
}

pub fn symlink(_src: &Path, _dst: &Path) -> io::Result<()> {
    // TODO(Sunrise): We don't have symlink support
    unsupported()
}

pub fn link(_src: &Path, _dst: &Path) -> io::Result<()> {
    // TODO(Sunrise): We don't have symlink support
    unsupported()
}

pub fn stat(path: &Path) -> io::Result<FileAttr> {
    let path = getcwd()?.join(path);
    let (_, _, path) = get_filesystem(&path)?;

    let parent_path = path.parent();

    let path = path.to_path_buf();

    if parent_path.is_none() {
        return Ok(FileAttr(path, 0, FileType(true)))
    } else {
        for entry in readdir(parent_path.unwrap())? {
            let entry = entry?;
            if entry.path() == path {
                return entry.metadata()
            }
        }
    }

    Err(Error::new(ErrorKind::NotFound, "The given resource couldn't be found."))
}

pub fn lstat(path: &Path) -> io::Result<FileAttr> {
    stat(path)
}

/// Splits a path at the first `/` it encounters.
///
/// Returns a tuple of the parts before and after the cut.
///
/// # Notes:
/// - The rest part can contain duplicates '/' in the middle of the path. This should be fine as you should call split_path to parse the rest part.
pub fn split_path(path: &str) -> (&str, Option<&str>) {
    let mut path_split = path.trim_matches('/').splitn(2, '/');

    // unwrap will never fail here
    let comp = path_split.next().unwrap();
    let rest_opt = path_split.next().and_then(|x| Some(x.trim_matches('/')));

    (comp, rest_opt)
}

/// Get an absolute path from an user path
fn get_absolute_path(path: &str) -> String {
    let mut path = path;
    let mut path_parts = Vec::new();

    loop {
        let (comp, rest_opt) = split_path(path);

        match comp {
            "." => {},
            ".." => {
                path_parts.pop();
            }
            _ => {
                let mut component = String::new();
                component.push('/');
                component.push_str(comp);

                path_parts.push(component);
            }
        }

        if rest_opt.is_none() {
            break;
        }

        path = rest_opt.unwrap();
    }

    let mut res = String::new();

    if path_parts.is_empty() {
        res.push('/');
    }

    for part in path_parts {
        res.push_str(part.as_str())
    }

    res
}

pub fn canonicalize(p: &Path) -> io::Result<PathBuf> {
    Ok(PathBuf::from(get_absolute_path(p.to_str().unwrap())))
}

pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    use crate::fs::File;

    if !from.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                              "the source path is not an existing regular file"))
    }

    let mut reader = File::open(from)?;
    let mut writer = File::create(to)?;
    let perm = reader.metadata()?.permissions();

    let ret = io::copy(&mut reader, &mut writer)?;
    writer.set_permissions(perm)?;
    Ok(ret)
}
