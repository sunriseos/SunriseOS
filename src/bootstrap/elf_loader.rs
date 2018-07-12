//! Loads the kernel in high memory

use multiboot2::BootInformation;
use bootstrap_logging::Serial;
use core::fmt::Write;
use core::slice;
use xmas_elf::ElfFile;
use xmas_elf::program::{ProgramHeader, Type::Load, SegmentData};
use paging::{ACTIVE_PAGE_TABLES, PAGE_SIZE, PageTablesSet, EntryFlags};
use address::VirtualAddress;
use utils::align_up;

/// Loads the kernel in high memory
/// Returns address of entry point
pub fn load_kernel(multiboot_info: &BootInformation) -> usize {
    let module = multiboot_info.module_tags()
        .nth(0).expect("Multiboot module tag for kernel not found");

    let kernel_ptr = module.start_address() as *const u8;
    let kernel_len = (module.end_address() - module.start_address()) as usize;
    let kernel_elf = ElfFile::new(unsafe { slice::from_raw_parts(kernel_ptr, kernel_len) })
        .expect("Failed parsing multiboot module as elf");

    // load all segments
    for ph in kernel_elf.program_iter().filter(|ph|
        ph.get_type().expect("Failed to get type of elf program header") == Load)
    {
        load_segment(&ph, &kernel_elf);
    }

    // return the entry point
    let entry_point = kernel_elf.header.pt2.entry_point();
    writeln!(Serial, "Entry point : {:#x?}", entry_point);
    entry_point as usize

}

/// Loads an elf segment by coping file_size bytes to the right address,
/// and filling remaining with 0s.
/// This is used by NOBITS sections (.bss), this way we initialize them to 0.
fn load_segment(segment: &ProgramHeader, elf_file: &ElfFile) {

    // Map the segment memory
    let mem_size_total = align_up(segment.mem_size() as usize, PAGE_SIZE);
    ACTIVE_PAGE_TABLES.lock().map_range_allocate(
        VirtualAddress(segment.virtual_addr() as usize),
        mem_size_total / PAGE_SIZE,
        EntryFlags::WRITABLE
    );

    // Copy the segment data
    match segment.get_data(elf_file).expect("Error geting elf segment data")
    {
        SegmentData::Undefined(elf_data) =>
        {
            let dest_ptr = segment.virtual_addr() as usize as *mut u8;
            let mut dest = unsafe { slice::from_raw_parts_mut(dest_ptr, mem_size_total) };
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

    // Remap with the right flags
    let mut map_flags = EntryFlags::empty();
    if segment.flags().is_write() {
        map_flags |= EntryFlags::WRITABLE;
    }
    //if segment.flags().is_execute() {
    //    map_flags |= EntryFlags::EXECUTABLE;
    //}
    //TODO remap with the right flags

    writeln!(Serial, "Loaded segment - VirtAddr {:#010x}, FileSize {:#010x}, MemSize {:#010x} {}{}{}",
        segment.virtual_addr(), segment.file_size(), segment.mem_size(),
        match segment.flags().is_read()    { true => 'R', false => ' '},
        match segment.flags().is_write()   { true => 'W', false => ' '},
        match segment.flags().is_execute() { true => 'X', false => ' '},
    );
}
