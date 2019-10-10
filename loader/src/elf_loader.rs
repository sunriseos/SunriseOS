//! Loads Elfs.
//!
//! Loads the elf binaries.

use core::slice;
use xmas_elf::ElfFile;
use xmas_elf::program::{ProgramHeader, Type::Load, SegmentData};
use sunrise_libuser::syscalls::{self, map_process_memory};
use sunrise_libuser::types::Process;
use sunrise_libuser::mem::{find_free_address, PAGE_SIZE};
use sunrise_libkern::MemoryPermissions;
use sunrise_libutils::align_up;
use sunrise_libuser::error::{Error, LoaderError};

/// Turn a byte array into an ELF file.
///
/// # Errors
///
/// - `LoaderError::InvalidElf`
///   - The provided ELF file is invalid.
pub fn from_data(data: &[u8]) -> Result<ElfFile, Error> {
    ElfFile::new(&data[..]).or_else(|err| {
        error!("Invalid ELF: {}", err);
        Err(LoaderError::InvalidElf.into())
    })
}

/// Gets the size of the allocation necessary to load all the segments.
///
/// # Errors
///
/// - `LoaderError::InvalidElf`
///   - Unaligned addresses or size
///   - Overlapping segments.
pub fn get_size(elf: &ElfFile<'_>) -> Result<usize, Error> {
    let mut size = 0;
    let mut expected_next = None;
    for ph in elf.program_iter().filter(|ph|
        if let Ok(Load) = ph.get_type() { true } else { false })
    {
        let vaddr = ph.virtual_addr() as usize;
        let segment_size = align_up(ph.mem_size() as usize, PAGE_SIZE);
        if vaddr % PAGE_SIZE != 0 {
            error!("vaddr must be page-aligned");
            return Err(LoaderError::InvalidElf.into());
        }

        if let Some(expected_next) = expected_next {
            if expected_next < vaddr {
                debug!("VAddr has an offset of {} bytes", vaddr - expected_next);
                size += vaddr - expected_next;
            } else if expected_next > vaddr {
                error!("Overlapping segments: Expected segment start {:x}, got {:x}", expected_next, vaddr);
                return Err(LoaderError::InvalidElf.into());
            }
        }

        size += segment_size;
        expected_next = Some(vaddr + segment_size);
    }

    Ok(size)
}

/// Gets the desired kernel access controls for a process based on the
/// .kernel_caps section in its elf
pub fn get_kacs<'a>(elf: &'a ElfFile<'_>) -> Option<&'a [u8]> {
    elf.find_section_by_name(".kernel_caps")
        .map(|section| section.raw_data(&elf))
}

/// Loads the given executable into the given process/address space.
///
/// # Errors
///
/// - `InvalidElf`
///   - The entrypoint was not at the expected address.
///   - ELF is corrupted.
/// - `KernelError`
///   - A syscall failed while trying to map the remote process memory or set
///     the mappings' permissions.
pub fn load_file(process: &Process, elf: &ElfFile<'_>, base: usize) -> Result<(), Error> {
    // load all segments into the page_table we had above
    for ph in elf.program_iter().filter(|ph|
        if let Ok(Load) = ph.get_type() { true } else { false })
    {
        load_segment(process, ph, &elf, base)?;
    }

    // return the entry point
    let entry_point = elf.header.pt2.entry_point() as usize;
    if entry_point != 0 {
        error!("Non-zero entrypoint found: {:x}!", entry_point);
        return Err(LoaderError::InvalidElf.into())
    }

    Ok(())
}

/// Loads an elf segment by coping file_size bytes to the right address,
/// and filling remaining with 0s.
/// This is used by NOBITS sections (.bss), this way we initialize them to 0.
#[allow(clippy::match_bool)] // more readable
fn load_segment(process: &Process, segment: ProgramHeader<'_>, elf_file: &ElfFile, base: usize) -> Result<(), Error> {
    // Map the segment memory in the current process space
    let mem_size_total = align_up(segment.mem_size() as usize, PAGE_SIZE);

    // Map as readonly if specified
    let mut flags = MemoryPermissions::empty();
    if segment.flags().is_read() {
        flags |= MemoryPermissions::READABLE
    }
    if segment.flags().is_write() {
        flags |= MemoryPermissions::WRITABLE
    }
    if segment.flags().is_execute() {
        flags |= MemoryPermissions::EXECUTABLE
    }

    // Ensure the flags are admissible.
    flags.check()?;

    // Acquire segment data
    let elf_data = match segment.get_data(elf_file).or(Err(LoaderError::InvalidElf))?
    {
        SegmentData::Undefined(elf_data) => elf_data,
        x => {
            error!("Unexpected Segment data {:?}", x);
            return Err(LoaderError::InvalidElf.into());
        }
    };

    let virtual_addr = base + segment.virtual_addr() as usize;

    // Access the mapping in the remote process
    let addr = find_free_address(mem_size_total, 0x1000)?;
    map_process_memory(addr, process, virtual_addr, mem_size_total)?;

    {
        // Copy the ELF data in the remote process.
        let dest_ptr = addr as *mut u8;
        let dest = unsafe {
            // Safety: Guaranteed to be OK if the syscall returns successfully.
            slice::from_raw_parts_mut(dest_ptr, mem_size_total)
        };
        let (dest_data, dest_pad) = dest.split_at_mut(segment.file_size() as usize);

        // Copy elf data
        dest_data.copy_from_slice(elf_data);

        // Fill remaining with 0s
        for byte in dest_pad.iter_mut() {
            *byte = 0x00;
        }
    }

    // Maybe I should panic if this fails, cuz that'd be really bad.
    unsafe {
        // Safety: this memory was previously mapped and all pointers to it
        // should have been dropped already.
        syscalls::unmap_process_memory(addr, process, virtual_addr, mem_size_total)?;
    }

    syscalls::set_process_memory_permission(process, virtual_addr, mem_size_total, flags)?;

    info!("Loaded segment - VirtAddr {:#010x}, FileSize {:#010x}, MemSize {:#010x} {}{}{}",
        virtual_addr, segment.file_size(), segment.mem_size(),
        match segment.flags().is_read()    { true => 'R', false => ' '},
        match segment.flags().is_write()   { true => 'W', false => ' '},
        match segment.flags().is_execute() { true => 'X', false => ' '},
    );

    Ok(())
}