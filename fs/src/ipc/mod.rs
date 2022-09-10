//! IPC module
//! This contains all IPC interfaces definition of the filesystem.

use alloc::boxed::Box;

use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType, DiskId, FileSystemType, PartitionId, FileSystemPath, IFileSystem, IFileSystemProxy, IFile, IFileProxy, IDirectory, IDirectoryProxy, IStorageProxy};
use sunrise_libuser::fs::IStorage as IStorageServer;
use sunrise_libuser::twili::{IPipe, IPipeProxy};
use sunrise_libuser::error::Error;
use sunrise_libuser::error::FileSystemError;
use sunrise_libuser::syscalls;
use sunrise_libuser::futures::WorkQueue;
use sunrise_libuser::futures_rs::future::FutureObj;

use sunrise_libuser::ipc::server::new_session_wrapper;

use crate::LibUserResult;
use crate::detail;
use crate::interface;
use crate::interface::filesystem::{convert_path, DirectoryOperations, FileOperations, FileSystemOperations, FileModeFlags, DirFilterFlags};

use alloc::sync::Arc;
use spin::Mutex;

#[derive(Debug, Clone)]
/// This is the ipc interface for a raw device, usually a block device.
pub struct Storage {
    /// The detail implementation of this ipc interface.
    inner: Arc<Mutex<Box<dyn interface::storage::IStorage<Error = Error>>>>
}

impl Storage {
    /// Create a new instance of IStorage using a boxed detail.
    pub fn new(inner: Arc<Mutex<Box<dyn interface::storage::IStorage<Error = Error>>>>) -> Self {
        Storage {
            inner
        }
    }
}

impl IStorageServer for Storage {
    fn read(&mut self, _manager: WorkQueue<'static>, offset: u64, length: u64, out_buf: &mut [u8]) -> Result<(), Error> {
        if length == 0 {
            return Ok(())
        }

        let mut out_buffer = out_buf;

        if length as usize > out_buffer.len() {
            return Err(FileSystemError::OutOfRange.into());
        }

        out_buffer = &mut out_buffer[..length as usize];

        self.inner.lock().read(offset, out_buffer)
    }

    fn write(&mut self, _manager: WorkQueue<'static>, offset: u64, length: u64, in_buf: &[u8]) -> Result<(), Error> {
        if length == 0 {
            return Ok(())
        }

        let mut in_buffer = in_buf;

        if length as usize > in_buffer.len() {
            return Err(FileSystemError::OutOfRange.into());
        }

        in_buffer = &in_buffer[..length as usize];

        self.inner.lock().write(offset, in_buffer)
    }

    fn flush(&mut self, _manager: WorkQueue<'static>, ) -> Result<(), Error> {
        self.inner.lock().flush()
    }

    fn set_size(&mut self, _manager: WorkQueue<'static>, new_size: u64) -> Result<(), Error> {
        self.inner.lock().set_size(new_size)
    }

    fn get_size(&mut self, _manager: WorkQueue<'static>, ) -> Result<u64, Error> {
        self.inner.lock().len()
    }
}

#[derive(Debug, Default, Clone)]
/// Entry point of the file system interface.
///
/// Allows to interract with various filesytem via IPC.
pub struct FileSystemService {
    /// The detail implementation of this ipc interface.
    inner: detail::FileSystemProxy
}


impl sunrise_libuser::fs::IFileSystemService for FileSystemService {
    fn open_disk_partition(&mut self, manager: WorkQueue<'static>, disk_id: DiskId, partition_id: PartitionId) -> Result<IFileSystemProxy, Error> {
        self.inner.open_disk_partition(disk_id, partition_id).and_then(|instance| {
            let (server, client) = syscalls::create_session(false, 0)?;
            let wrapper = new_session_wrapper(manager.clone(), server, FileSystem::new(instance), IFileSystem::dispatch);
            manager.spawn(FutureObj::new(Box::new(wrapper)));
            Ok(IFileSystemProxy::from(client))
        })
    }

    fn open_disk_storage(&mut self, manager: WorkQueue<'static>, disk_id: DiskId) -> Result<IStorageProxy, Error> {
        self.inner.open_disk_storage(disk_id).and_then(|instance| {
            let (server, client) = syscalls::create_session(false, 0)?;
            let wrapper = new_session_wrapper(manager.clone(), server, Storage::new(instance), IStorageServer::dispatch);
            manager.spawn(FutureObj::new(Box::new(wrapper)));
            Ok(IStorageProxy::from(client))
        })
    }

    fn get_disks_count(&mut self, _manager: WorkQueue<'static>) -> Result<u32, Error> {
        self.inner.get_disks_count()
    }

    fn format_disk_partition(&mut self, _manager: WorkQueue<'static>, disk_id: DiskId, partition_id: PartitionId, filesystem_type: FileSystemType) -> Result<(), Error> {
        self.inner.format_disk_partition(disk_id, partition_id, filesystem_type)
    }

    fn initialize_disk(&mut self, _manager: WorkQueue<'static>, disk_id: DiskId) -> Result<(), Error> {
        self.inner.initialize_disk(disk_id)
    }
}

/// Represent a file in the IPC.
#[derive(Debug, Clone)]
pub struct Pipe {
    /// The detail implementation of this ipc interface.
    inner: Arc<Mutex<Box<dyn FileOperations>>>,
    /// Position from which to read/write in the file. Every read/write will
    /// automatically increment this cursor by the amount of bytes the operation
    /// successfully managed to read/write.
    cursor: u64
}

impl Pipe {
    /// Create a new pipe from the given file.
    pub fn new(inner: Box<dyn FileOperations>) -> Self {
        Pipe { inner: Arc::new(Mutex::new(inner)), cursor: 0 }
    }
}

impl IPipe for Pipe {
    fn read(&mut self, _manager: WorkQueue<'static>, out_buffer: &mut [u8]) -> Result<u64, Error> {
        if out_buffer.is_empty() {
            return Ok(0)
        }

        let read = self.inner.lock().read(self.cursor, out_buffer)?;

        self.cursor += read;

        Ok(self.cursor)
    }

    fn write(&mut self, _manager: WorkQueue<'static>, in_buffer: &[u8]) -> Result<(), Error> {
        if in_buffer.is_empty() {
            return Ok(())
        }

        self.inner.lock().write(self.cursor, in_buffer)?;

        self.cursor += in_buffer.len() as u64;

        Ok(())
    }
}

/// Represent a file in the IPC.
#[derive(Debug, Clone)]
pub struct File {
    /// The detail implementation of this ipc interface.
    inner: Arc<Mutex<Box<dyn FileOperations>>>
}

impl File {
    /// Create a new IFile instance from it's detail.
    pub fn new(inner: Box<dyn FileOperations>) -> Self {
        File { inner: Arc::new(Mutex::new(inner)) }
    }
}

impl IFile for File {
    fn read(&mut self, _manager: WorkQueue<'static>, _unknown_0: u32, offset: u64, length: u64, out_buffer: &mut [u8]) -> Result<u64, Error> {
        if length == 0 {
            return Ok(0)
        }

        if length as usize > out_buffer.len() {
            return Err(FileSystemError::OutOfRange.into());
        }

        self.inner.lock().read(offset, &mut out_buffer[..length as usize])
    }

    fn write(&mut self, _manager: WorkQueue<'static>, _unknown_0: u32, offset: u64, length: u64, in_buffer: &[u8]) -> Result<(), Error> {
        if length == 0 {
            return Ok(())
        }

        if length as usize > in_buffer.len() {
            return Err(FileSystemError::OutOfRange.into());
        }

        self.inner.lock().write(offset, &in_buffer[..length as usize])
    }

    fn flush(&mut self, _manager: WorkQueue<'static>) -> Result<(), Error> {
        self.inner.lock().flush()
    }

    fn set_size(&mut self, _manager: WorkQueue<'static>, new_size: u64) -> Result<(), Error> {
        self.inner.lock().set_len(new_size)
    }

    fn get_size(&mut self, _manager: WorkQueue<'static>) -> Result<u64, Error> {
        self.inner.lock().get_len()
    }
}

/// Represent a file in the IPC.
#[derive(Debug, Clone)]
pub struct Directory {
    /// The detail implementation of this ipc interface.
    inner: Arc<Mutex<Box<dyn DirectoryOperations>>>
}

impl Directory {
    /// Create a new IFile instance from it's detail.
    pub fn new(inner: Box<dyn DirectoryOperations>) -> Self {
        Directory { inner: Arc::new(Mutex::new(inner)) }
    }
}

impl sunrise_libuser::fs::IDirectory for Directory {
    fn read(&mut self, _manager: WorkQueue<'static>, out_buffer: &mut [DirectoryEntry]) -> Result<u64, Error> {
        if out_buffer.is_empty() {
            return Ok(0)
        }

        self.inner.lock().read(out_buffer)
    }

    fn get_entry_count(&mut self, _manager: WorkQueue<'static>) -> Result<u64, Error> {
        self.inner.lock().entry_count()
    }
}

/// Represent a filesystem in the IPC.
#[derive(Debug, Clone)]
pub struct FileSystem {
    /// The detail implementation of this ipc interface.
    inner: Arc<Mutex<Box<dyn FileSystemOperations>>>
}

impl FileSystem {
    /// Create a new FileSystem instance from it's detail.
    pub fn new(inner: Arc<Mutex<Box<dyn FileSystemOperations>>>) -> Self {
        FileSystem { inner }
    }
}

impl IFileSystem for FileSystem {
    fn create_file(&mut self, _manager: WorkQueue<'static>, _mode: u32, size: u64, path: &FileSystemPath) -> Result<(), Error> {
        FileSystemOperations::create_file(&**self.inner.lock(), convert_path(path)?, size)
    }

    fn delete_file(&mut self, _manager: WorkQueue<'static>, path: &FileSystemPath) -> Result<(), Error> {
        FileSystemOperations::delete_file(&**self.inner.lock(), convert_path(path)?)
    }

    fn create_directory(&mut self, _manager: WorkQueue<'static>, path: &FileSystemPath) -> Result<(), Error> {
        FileSystemOperations::create_directory(&**self.inner.lock(), convert_path(path)?)
    }

    fn delete_directory(&mut self, _manager: WorkQueue<'static>, path: &FileSystemPath) -> Result<(), Error> {
        FileSystemOperations::delete_directory(&**self.inner.lock(), convert_path(path)?)
    }

    fn rename_file(&mut self, _manager: WorkQueue<'static>, old_path: &FileSystemPath, new_path: &FileSystemPath) -> Result<(), Error> {
        FileSystemOperations::rename_file(&**self.inner.lock(), convert_path(old_path)?, convert_path(new_path)?)
    }

    fn rename_directory(&mut self, _manager: WorkQueue<'static>, old_path: &FileSystemPath, new_path: &FileSystemPath) -> Result<(), Error> {
        FileSystemOperations::rename_directory(&**self.inner.lock(), convert_path(old_path)?, convert_path(new_path)?)
    }

    fn open_file(&mut self, manager: WorkQueue<'static>, mode: u32, path: &sunrise_libuser::fs::FileSystemPath) -> Result<sunrise_libuser::fs::IFileProxy, Error> {
        let flags_res: LibUserResult<_> = FileModeFlags::from_bits(mode).ok_or_else(|| FileSystemError::InvalidInput.into());
        FileSystemOperations::open_file(&**self.inner.lock(), convert_path(path)?, flags_res?).and_then(|instance| {
            let (server, client) = syscalls::create_session(false, 0)?;
            let wrapper = new_session_wrapper(manager.clone(), server, File::new(instance), IFile::dispatch);
            manager.spawn(FutureObj::new(Box::new(wrapper)));
            Ok(IFileProxy::from(client))
        })
    }

    fn open_file_as_ipipe(&mut self, manager: WorkQueue<'static>, mode: u32, path: &sunrise_libuser::fs::FileSystemPath) -> Result<sunrise_libuser::twili::IPipeProxy, Error> {
        let flags_res: LibUserResult<_> = FileModeFlags::from_bits(mode).ok_or_else(|| FileSystemError::InvalidInput.into());
        FileSystemOperations::open_file(&**self.inner.lock(), convert_path(path)?, flags_res?).and_then(|instance| {
            let (server, client) = syscalls::create_session(false, 0)?;
            let wrapper = new_session_wrapper(manager.clone(), server, Pipe::new(instance), IPipe::dispatch);
            manager.spawn(FutureObj::new(Box::new(wrapper)));
            Ok(IPipeProxy::from(client))
        })
    }

    fn open_directory(&mut self, manager: WorkQueue<'static>, filter_flags: u32, path: &sunrise_libuser::fs::FileSystemPath) -> Result<sunrise_libuser::fs::IDirectoryProxy, Error> {
        let flags_ret: LibUserResult<_> = DirFilterFlags::from_bits(filter_flags).ok_or_else(|| FileSystemError::InvalidInput.into());
        FileSystemOperations::open_directory(&**self.inner.lock(), convert_path(path)?, flags_ret?).and_then(|instance| {
            let (server, client) = syscalls::create_session(false, 0)?;
            let wrapper = new_session_wrapper(manager.clone(), server, Directory::new(instance), IDirectory::dispatch);
            manager.spawn(FutureObj::new(Box::new(wrapper)));

            Ok(IDirectoryProxy::from(client))
        })
    }

    fn get_free_space_size(&mut self, _manager: WorkQueue<'static>, path: &sunrise_libuser::fs::FileSystemPath) -> Result<u64, Error> {
        FileSystemOperations::get_free_space_size(&**self.inner.lock(), convert_path(path)?)
    }

    fn get_total_space_size(&mut self, _manager: WorkQueue<'static>, path: &sunrise_libuser::fs::FileSystemPath) -> Result<u64, Error> {
        FileSystemOperations::get_total_space_size(&**self.inner.lock(), convert_path(path)?)
    }

    fn get_file_timestamp_raw(&mut self, _manager: WorkQueue<'static>, path: &sunrise_libuser::fs::FileSystemPath) -> Result<sunrise_libuser::fs::FileTimeStampRaw, Error> {
        FileSystemOperations::get_file_timestamp_raw(&**self.inner.lock(), convert_path(path)?)
    }

    fn get_entry_type(&mut self, _manager: WorkQueue<'static>, path: &FileSystemPath) -> Result<DirectoryEntryType, Error> {
        FileSystemOperations::get_entry_type(&**self.inner.lock(), convert_path(path)?)
    }

    fn get_filesystem_type(&mut self, _manager: WorkQueue<'static>) -> Result<FileSystemType, Error> {
        Ok(FileSystemOperations::get_filesystem_type(&**self.inner.lock()))
    }
}
