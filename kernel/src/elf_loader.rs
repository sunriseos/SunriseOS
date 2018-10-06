//! Loads Kernel Built-ins.
//!
//! Loads the initial kernel binaries. The end-game goal is to have 5 kernel built-ins:
//!
//! - sm: The Service Manager. Plays a pivotal role for permission checking.
//! - pm: The Process Manager.
//! - loader: Loads ELFs into an address space.
//! - fs: Provides access to the FileSystem.
//! - boot: Controls the boot chain. Asks PM to start user services. Akin to the init.
//!
//! Because the 'normal' ELF loader lives in userspace in the Loader executable, kernel
//! built-ins require their own loading mechanism. On i386, we use GRUB modules to send
//! the built-ins to the kernel, and load them with a primitive ELF loader. This loader
//! does not do any dynamic loading or provide ASLR (though that is up for change)

use multiboot2::ModuleTag;
use core::fmt::Write;
use core::slice;
use xmas_elf::ElfFile;
use xmas_elf::program::{ProgramHeader, Type::Load, SegmentData};
use paging::{ACTIVE_PAGE_TABLES, PAGE_SIZE, PageTablesSet, EntryFlags, MappingType, InactivePageTables, KernelLand};
use i386::mem::{VirtualAddress, PhysicalAddress};
use utils::{self, align_up};

/// Loads the given kernel built-in into the given page table.
/// Returns address of entry point
pub fn load_builtin(page_table: &mut InactivePageTables, module: &ModuleTag) -> usize {
    let start_address_aligned = utils::align_down(module.start_address() as usize, PAGE_SIZE);
    // Use start_address_aligned to calculate the number of pages, to avoid an off-by-one.
    let module_len_pages = utils::div_round_up(module.end_address() as usize - start_address_aligned, PAGE_SIZE);

    // Temporarily map the modules, which live in physical mem, into current process virtual mem.
    let module_addr = {
        let mut page_table = ACTIVE_PAGE_TABLES.lock();
        let vaddr = page_table.find_available_virtual_space::<KernelLand>(module_len_pages)
            .expect(&format!("Unable to find available memory for module {}", module.name()));

        page_table.map_range(PhysicalAddress(start_address_aligned), vaddr, module_len_pages, EntryFlags::WRITABLE);

        vaddr
    };

    let module_len = module.end_address() - module.start_address();
    let kernel_elf = ElfFile::new(unsafe {
        slice::from_raw_parts((module_addr.addr() + (module.start_address() as usize % PAGE_SIZE)) as *const u8, module_len as usize)
    }).expect("Failed parsing multiboot module as elf");

    // load all segments into the page_table we had above
    for ph in kernel_elf.program_iter().filter(|ph|
        ph.get_type().expect("Failed to get type of elf program header") == Load)
    {
        load_segment(page_table, &ph, &kernel_elf);
    }

    // return the entry point
    let entry_point = kernel_elf.header.pt2.entry_point();
    info!("Entry point : {:#x?}", entry_point);

    // Unmap the modules from the current address space.
    {
        let mut page_table = ACTIVE_PAGE_TABLES.lock();
        page_table.unmap_range(module_addr, module_len_pages);
    }
    entry_point as usize

}

/// Loads an elf segment by coping file_size bytes to the right address,
/// and filling remaining with 0s.
/// This is used by NOBITS sections (.bss), this way we initialize them to 0.
fn load_segment(page_table: &mut InactivePageTables, segment: &ProgramHeader, elf_file: &ElfFile) {
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

    info!("Loaded segment - VirtAddr {:#010x}, FileSize {:#010x}, MemSize {:#010x} {}{}{}",
        segment.virtual_addr(), segment.file_size(), segment.mem_size(),
        match segment.flags().is_read()    { true => 'R', false => ' '},
        match segment.flags().is_write()   { true => 'W', false => ' '},
        match segment.flags().is_execute() { true => 'X', false => ' '},
    );

    // And now, map them in our page_table, and unmap them from current page table
    for addr in (segment.virtual_addr() as usize..(segment.virtual_addr() as usize) + mem_size_total).step_by(PAGE_SIZE) {
        let frame = ACTIVE_PAGE_TABLES.lock().unmap(VirtualAddress(addr)).unwrap();

        // Remap as readonly if specified
        let flags = if !segment.flags().is_write() {
            EntryFlags::USER_ACCESSIBLE
        } else {
            EntryFlags::WRITABLE | EntryFlags::USER_ACCESSIBLE
        };

        page_table.map_to(MappingType::Present(frame, flags), VirtualAddress(addr));
    }
}
