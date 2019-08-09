//! Memory
//!
//! Low-level helpers to assist memory mapping, MMIOs and DMAs.

use sunrise_libutils::{align_down, align_up};
use crate::syscalls;
use crate::error::{KernelError, LibuserError, Error};

/// The size of page. Used to interface with the kernel.
pub const PAGE_SIZE: usize = 4096;

/// Finds a free memory zone of the given size and alignment in the current
/// process's virtual address space. Note that the address space is not reserved,
/// a call to map_memory to that address space might fail if another thread
/// maps to it first. It is recommended to use this function and the map syscall
/// in a loop.
///
/// # Panics
///
/// Panics on underflow when size = 0.
///
/// Panics on underflow when align = 0.
pub fn find_free_address(size: usize, align: usize) -> Result<usize, Error> {

    // TODO: Use svcGetInfo to get the address space in find_free_address
    // BODY: We should use svcGetInfo to get the address space in
    // BODY: `find_free_address`. This is extremely important as the low
    // BODY: addresses (from 0 to ADDRESS_SPACE_MIN) are not usable, but are
    // BODY: marked as available by QueryMemory.
    // BODY:
    // BODY: Here's a sample implementation for when we'll have GetInfo impl'd.
    // BODY:
    // BODY: ```rust
    // BODY: lazy_static! {
    // BODY:     static ref ADDRESS_SPACE: (usize, usize) = {
    // BODY:         let addr_space_base = syscalls::get_info(Process::current(), 12, 0).unwrap();
    // BODY:         let addr_space_size = syscalls::get_info(Process::current(), 13, 0).unwrap();
    // BODY:         (addr_space_base, addr_space_base + addr_space_size)
    // BODY:     };
    // BODY: }
    // BODY: ```

    let mut addr = 0x00200000;
    // Go over the address space.
    loop {
        let (meminfo, _) = syscalls::query_memory(addr)?;
        if meminfo.memtype.ty() == sunrise_libkern::MemoryType::Unmapped {
            let alignedbaseaddr = sunrise_libutils::align_up_checked(meminfo.baseaddr, align).ok_or(LibuserError::AddressSpaceExhausted)?;

            let alignment = alignedbaseaddr - meminfo.baseaddr;
            if alignment.checked_add(size - 1).ok_or(LibuserError::AddressSpaceExhausted)? < meminfo.size {
                return Ok(alignedbaseaddr)
            }
        }
        addr = meminfo.baseaddr.checked_add(meminfo.size).ok_or(LibuserError::AddressSpaceExhausted)?;
    }
}

/// Maps a Mmio struct in the virtual memory of this process.
///
/// This function preserves the offset relative to `PAGE_SIZE`.
///
/// # Example
///
// no_run because map_mmio will return an error on linux
/// ```no_run
/// use sunrise_libutils::io::{Io, Mmio};
/// use sunrise_libuser::mem::map_mmio;
/// /// Found at physical address 0xabc00030
/// #[repr(packed)]
/// struct DeviceFoo {
///     header: Mmio<u32>,
///     version: Mmio<u32>,
///     field_a: Mmio<u16>,
///     field_b: Mmio<u16>,
/// }
///
/// let mapped_data: *mut DeviceFoo = map_mmio::<DeviceFoo>(0xabc00030).unwrap(); // = virtual address 0x7030
/// unsafe {
///     assert_eq!((*mapped_data).version.read(), 0x010200);
/// }
/// ```
pub fn map_mmio<T>(physical_address: usize) -> Result<*mut T, KernelError> {
    let aligned_phys_addr = align_down(physical_address, PAGE_SIZE);
    let full_size = align_up(aligned_phys_addr + ::core::mem::size_of::<T>(), PAGE_SIZE) - aligned_phys_addr;
    let virt_addr = find_free_address(full_size as _, 1).unwrap();
    syscalls::map_mmio_region(aligned_phys_addr as _, full_size as _, virt_addr, true)?;
    Ok((virt_addr + (physical_address % PAGE_SIZE)) as *mut T)
}

/// Gets the physical address of a structure from its virtual address, preserving offset in the page.
///
/// # Panics
///
/// * query_physical_address failed.
pub fn virt_to_phys<T>(virtual_address: *const T) -> usize {
    let (phys_region_start, _, _, phys_region_offset) = syscalls::query_physical_address(virtual_address as usize)
        .expect("syscall query_physical_memory failed");
    phys_region_start + phys_region_offset
}
