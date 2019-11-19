//! Subcommand to change the CWD.
//!
//! Takes a single directory argument. Sets the [`CURRENT_WORK_DIRECTORY`](static@crate::CURRENT_WORK_DIRECTORY)
//! to the absolute path this directory resolves to - if it exists.

use core::fmt::Write;

use sunrise_libuser::error::{Error, FileSystemError};
use sunrise_libuser::fs::IFileSystemServiceProxy;
use sunrise_libuser::twili::IPipeProxy;

/// Help string.
pub static HELP: &'static str = "cd <directory>: change the working directory";

/// Change the current working directory
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, args: &[&str]) -> Result<(), Error> {
    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();

    let path = match args.get(1) {
        Some(path) => path,
        None => {
            let _ = writeln!(&mut stdout, "usage: cd <directory>");
            return Ok(())
        }
    };

    let absolute_current_directory = crate::get_path_relative_to_current_directory(path);
    if absolute_current_directory.len() > 0x300 {
        return Err(FileSystemError::InvalidInput.into())
    }

    let mut ipc_path = [0x0; 0x300];
    ipc_path[..absolute_current_directory.as_bytes().len()].copy_from_slice(absolute_current_directory.as_bytes());


    filesystem.open_directory(3, &ipc_path)?;

    let mut current_directory = crate::CURRENT_WORK_DIRECTORY.lock();
    *current_directory = absolute_current_directory;
    Ok(())
}