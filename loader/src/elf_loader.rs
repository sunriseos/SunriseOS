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

/// Turn a byte array into an ELF file.
pub fn from_data(data: &[u8]) -> ElfFile {
    ElfFile::new(&data[..]).unwrap()
}

/// Gets the size of the allocation necessary to load all the segments.
pub fn get_size(elf: &ElfFile<'_>) -> usize {
    let mut size = 0;
    let mut expected_next = None;
    for ph in elf.program_iter().filter(|ph|
        ph.get_type().expect("Failed to get type of elf program header") == Load)
    {
        let vaddr = ph.virtual_addr() as usize;
        let segment_size = align_up(ph.mem_size() as usize, PAGE_SIZE);
        assert_eq!(vaddr % PAGE_SIZE, 0, "vaddr must be page-aligned");

        if let Some(expected_next) = expected_next {
            if expected_next < vaddr {
                info!("VAddr has an offset of {} bytes", vaddr - expected_next);
                size += vaddr - expected_next;
            } else if expected_next > vaddr {
                panic!("Overlapping segments!");
            }
        }

        info!("Segment of {} bytes", segment_size);
        size += segment_size;
        expected_next = Some(vaddr + segment_size);
    }

    size
}

/// Gets the desired kernel access controls for a process based on the
/// .kernel_caps section in its elf
pub fn get_kacs<'a>(elf: &'a ElfFile<'_>) -> Option<&'a [u8]> {
    elf.find_section_by_name(".kernel_caps")
        .map(|section| section.raw_data(&elf))
}

/// Loads the given kernel built-in into the given page table.
/// Returns address of entry point
pub fn load_builtin(process: &Process, elf: &ElfFile<'_>, base: usize) -> usize {
    // load all segments into the page_table we had above
    for ph in elf.program_iter().filter(|ph|
        ph.get_type().expect("Failed to get type of elf program header") == Load)
    {
        load_segment(process, ph, &elf, base);
    }

    // return the entry point
    let entry_point = base + elf.header.pt2.entry_point() as usize;
    assert_eq!(entry_point, base, "Expected entry-point to be at 0");
    info!("Entry point : {:#x?}", entry_point);

    entry_point as usize
}

/// Loads an elf segment by coping file_size bytes to the right address,
/// and filling remaining with 0s.
/// This is used by NOBITS sections (.bss), this way we initialize them to 0.
#[allow(clippy::match_bool)] // more readable
fn load_segment(process: &Process, segment: ProgramHeader<'_>, elf_file: &ElfFile, base: usize) {
    // Map the segment memory in KernelLand
    let mem_size_total = align_up(segment.mem_size() as usize, PAGE_SIZE);

    // Map as readonly if specified
    let mut flags = MemoryPermissions::empty();
    if segment.flags().is_read() {
        flags |= MemoryPermissions::READABLE
    };
    if segment.flags().is_write() {
        flags |= MemoryPermissions::WRITABLE
    };
    if segment.flags().is_execute() {
        flags |= MemoryPermissions::EXECUTABLE
    }

    let virtual_addr = base + segment.virtual_addr() as usize;

    // Access the mapping in the remote process
    let addr = find_free_address(mem_size_total, 0x1000).unwrap();
    map_process_memory(addr, process, virtual_addr, mem_size_total)
        .expect("Cannot load segment");

    // Copy the segment data
    match segment.get_data(elf_file).expect("Error getting elf segment data")
    {
        SegmentData::Undefined(elf_data) =>
        {
            let dest_ptr = addr as *mut u8;
            let dest = unsafe { slice::from_raw_parts_mut(dest_ptr, mem_size_total) };
            let (dest_data, dest_pad) = dest.split_at_mut(segment.file_size() as usize);

            // Copy elf data
            dest_data.copy_from_slice(elf_data);

            // Fill remaining with 0s
            for byte in dest_pad.iter_mut() {
                *byte = 0x00;
            }
        },
        x => { panic ! ("Unexpected Segment data {:?}", x) }
    }

    syscalls::unmap_process_memory(addr, process, virtual_addr, mem_size_total)
        .expect("Cannot unload segment");

    syscalls::set_process_memory_permission(process, virtual_addr, mem_size_total, flags)
        .expect("Set memory permissions to go smoothly");

    info!("Loaded segment - VirtAddr {:#010x}, FileSize {:#010x}, MemSize {:#010x} {}{}{}",
        virtual_addr, segment.file_size(), segment.mem_size(),
        match segment.flags().is_read()    { true => 'R', false => ' '},
        match segment.flags().is_write()   { true => 'W', false => ' '},
        match segment.flags().is_execute() { true => 'X', false => ' '},
    );
}