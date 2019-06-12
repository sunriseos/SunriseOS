//! Disk initializer application
//! 
//! This app is in charge of generating a valid disk image from a file name, a size and a template directory (containing files that should be on the disk image)
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

use std::cell::RefCell;
use std::io::SeekFrom;

use storage_device::*;

use libfat;
use libfat::FatFileSystemResult;
use libfat::filesystem::FatFileSystem;
use libfat::FatFsType;
use libfat::directory::File as FatFile;

mod gpt;

use gpt::{PartitionIterator, PartitionManager};

/// A structure used to manipulate std::File as BlockDevice
#[derive(Debug)]
struct StdBlockDevice {
    /// The file backing the BlockDevice
    file: RefCell<File>,
}

impl StdBlockDevice {
    /// Create a new StdBlockDevice from a system path
    fn new<P>(device_name: P) -> StdBlockDevice
    where
        P: AsRef<Path>,
    {
        StdBlockDevice {
            file: RefCell::new(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(device_name)
                    .unwrap(),
            ),
        }
    }
}

impl BlockDevice for StdBlockDevice {
    fn read(&mut self, blocks: &mut [Block], index: BlockIndex) -> BlockResult<()> {
        /*trace!(
            "Reading block index 0x{:x} (0x{:x})",
            index.0,
            index.into_offset()
        );*/
        self.file
            .borrow_mut()
            .seek(SeekFrom::Start(index.into_offset()))
            .unwrap();
        for block in blocks.iter_mut() {
            self.file
                .borrow_mut()
                .read_exact(&mut block.contents)
                .unwrap();
        }
        Ok(())
    }

    fn write(&mut self, blocks: &[Block], index: BlockIndex) -> BlockResult<()> {
        self.file
            .borrow_mut()
            .seek(SeekFrom::Start(index.into_offset()))
            .unwrap();
        for block in blocks.iter() {
            self.file.borrow_mut().write_all(&block.contents).unwrap();
        }
        Ok(())
    }

    fn count(&mut self) -> BlockResult<BlockCount> {
        let num_blocks = self.file.borrow().metadata().unwrap().len() / (Block::LEN_U64);
        Ok(BlockCount(num_blocks))
    }
}

/// Write a std file to FAT filesystem.
fn write_file_to_filesystem<S>(
    fs: &FatFileSystem<S>,
    mut file: FatFile,
    path: &str,
) -> FatFileSystemResult<()>  where S: StorageDevice {
    let mut f = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .unwrap();

    let mut base_buffer = Vec::new();
    f.read_to_end(&mut base_buffer).unwrap();
    file.write(fs, 0, &base_buffer, true)?;

    Ok(())
}

/// Write the template directory content to a FAT fileystem
fn write_tempate_to_filesystem<S>(filesystem: &FatFileSystem<S>, dir: &Path, filesystem_path: &mut PathBuf) -> io::Result<()> where S: StorageDevice {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            let mut filesystem_entry_path = filesystem_path.clone();
            filesystem_entry_path.push(entry.file_name());

            let filesystem_entry_path_str = filesystem_entry_path.to_str().unwrap();
            if path.is_dir() {
                filesystem.create_directory(filesystem_entry_path_str).expect("Cannot create directory in the filesystem");
                write_tempate_to_filesystem(filesystem, &path, &mut filesystem_entry_path)?;
            } else {
                filesystem.create_file(filesystem_entry_path_str).expect("Cannot create file in the filesystem");
                let file = filesystem.open_file(filesystem_entry_path_str).expect("Cannot open file in the filesystem");
                write_file_to_filesystem(filesystem, file, path.to_str().unwrap()).expect("Cannot write file to filesystem");
            }
        }
    }
    Ok(())
}

fn main() {
    let file_name = env::args().nth(1).expect("File name is expected");
    let file_size = env::args().nth(2).expect("Disk size is expected");
    let template_path = env::args().nth(3).expect("Template path is expected");

    let file_size = u64::from_str_radix(file_size.as_str(), 10).expect("Cannot parse file size");
    let file = File::create(file_name.clone()).expect("Cannot create file");
    // Set the file size
    file.set_len(file_size).expect("Cannot set file size");

    let mut system_device = StorageBlockDevice::new(StdBlockDevice::new(file_name.clone()));

    let mut part_manager = PartitionManager::new(&mut system_device);

    // Initialize GPT header
    part_manager
        .initialize()
        .expect("Disk initialization failed");

    let mut partition_iterator = PartitionIterator::new(&mut system_device).expect("Invalid GPT");

    // Now get the first partition and format it to FAT32
    let partition_option = partition_iterator.nth(0).unwrap();

    let partition = partition_option.expect("Invalid partition while iterating");
    let partition_start = partition.first_lba * Block::LEN_U64;
    let partition_len = (partition.last_lba * Block::LEN_U64) - partition_start;

    libfat::format_partition(
        system_device,
        FatFsType::Fat32,
        partition_start,
        partition_len,
    )
    .expect("Format issue in libfat");

    // Now that the device have been dropped the filesystem has been written to disk
    // We reopen the file to feed it with the template we have.
    
    let system_device = StorageBlockDevice::new(StdBlockDevice::new(file_name));
    let filesystem = libfat::get_raw_partition_with_start(system_device, partition_start, partition_len).expect("Open issue in libfat");
    let mut filesystem_path = PathBuf::new();
    filesystem_path.push("/");

    write_tempate_to_filesystem(&filesystem, Path::new(&template_path), &mut filesystem_path).expect("Failed to write template to filesystem");
}
