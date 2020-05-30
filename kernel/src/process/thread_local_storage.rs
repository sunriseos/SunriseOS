//! TLS manager
//!
//! # Abstract
//!
//! For each thread of a process, the kernel allocates a 0x200-bytes "Thread Local Storage"
//! memory region in UserLand. In this region resides the 0x100-bytes IPC command buffer,
//! which is used by the user for passing IPC arguments, and a pointer to the user-controlled
//! "thread context", which will likely be used for holding userspace thread local variables.
//!
//! Each thread in a process has its own private TLS, and from userspace its address can be found out
//! at anytime by reading an architecture-specific register (aarch64 uses `tpidrro_el0`, x86 uses the
//! `gs` segment selector).
//!
//! # Location
//!
//! The TLS content is defined by the [TLS] structure. It is a 0x200-bytes memory area that leaves
//! in UserLand so it can be accessed and modified by the user.
//! The user is allowed to access and modify the TLS of other thread from its process if it
//! manages to find the location of their TLS, but this is not advised, as it serves little purpose.
//!
//! Kernel-side, each thread holds a raw pointer to its TLS (`*mut TLS`) in its [ThreadStruct].
//! This pointer is used by the kernel to get the thread's `ipc_command_buffer` address,
//! and is restored as part of hardware context on every context-switch.
//!
//! # Allocation
//!
//! Each process holds a [TLSManager] in its ProcessStruct, which manages the TLSs for this process,
//! keeps track of which ones are in-use and which ones are free, and try to re-use free TLSs when
//! spawning a thread.
//!
//! When a thread is being created, it asks its process's `TLSManager` via [allocate_tls] to get a pointer
//! to its TLS, and saves it in the `ThreadStruct`.
//!
//! When a thread dies, it notifies its process's `TLSManager` via [free_tls], so its TLS can be re-used.
//!
//! TLSs are only 0x200 bytes, so the `TLSManager` groups them together to fit inside a page,
//! and will allocate a new page every time it is full and cannot satisfy a TLS allocation.
//!
//! [TLS]: sunrise_libkern::TLS
//! [TLSManager]: TLSManager
//! [ThreadStruct]: crate::process::ThreadStruct
//! [allocate_TLS]: TLSManager::allocate_tls
//! [free_TLS]: TLSManager::free_tls

use crate::VirtualAddress;
use crate::PAGE_SIZE;
use crate::paging::process_memory::ProcessMemory;
use crate::paging::MappingAccessRights;
use crate::error::KernelError;
use sunrise_libutils::bit_array_first_zero;
use sunrise_libkern::{MemoryType, TLS};
use core::mem::size_of;
use bit_field::BitArray;
use alloc::vec::Vec;

/// Manages a page containing 8 TLS
///
/// A TLS being only 0x200 bytes, the kernel aggregates the TLSs of a same process in groups of 8
/// so that they fit in one page.
///
/// # Memory leak
///
/// Dropping this struct will leak the page, until the process is killed and all its memory is freed.
/// See [TLSManager] for more on this topic.
#[derive(Debug)]
struct TLSPage {
    /// Address of the page, in UserLand.
    page_address: VirtualAddress,
    /// Bitmap indicating if the TLS is in use (`1`) or free (`0`).
    usage: [u8; PAGE_SIZE / size_of::<TLS>() / 8]
}

impl TLSPage {

    /// Allocates a new page holing 8 TLS.
    ///
    /// The page is user read-write, and its memory type is `ThreadLocal`.
    ///
    /// # Error
    ///
    /// Fails if the allocation fails.
    fn new(pmemory: &mut ProcessMemory) -> Result<Self, KernelError> {
        let addr = pmemory.find_available_space(PAGE_SIZE)?;
        pmemory.create_regular_mapping(addr, PAGE_SIZE, MemoryType::ThreadLocal, MappingAccessRights::u_rw())?;
        Ok(TLSPage {
            page_address: addr,
            usage: [0u8; PAGE_SIZE / size_of::<TLS>() / 8]
        })
    }

    /// Finds an available slot in the TLSPage, bzero it, marks it allocated, and gives back a pointer to it.
    ///
    /// If no slot was available, this function returns `None`.
    ///
    /// The returned TLS still has to be bzeroed, has it may contain the data of a previous thread.
    fn allocate_tls(&mut self) -> Option<VirtualAddress> {
        let index = bit_array_first_zero(&self.usage)?;
        self.usage.set_bit(index, true);
        Some(self.page_address + index * size_of::<TLS>())
    }

    /// Marks a TLS in this TLSPage as free so it can be used by the next spawned thread.
    ///
    /// # Panics
    ///
    /// Panics if `address` does not fall in this TLSPage, not a valid offset, or marked already free.
    fn free_tls(&mut self, address: VirtualAddress) {
        debug_assert!(address.floor() == self.page_address, "Freed TLS ptr is outside of TLSPage.");
        debug_assert!(address.addr() % size_of::<TLS>() == 0, "Freed TLS ptr is not TLS size aligned.");
        let index = (address - self.page_address) / size_of::<TLS>();
        debug_assert!(self.usage.get_bit(index), "Freed TLS was not marked occupied");
        self.usage.set_bit(index, false);
    }
}

// size_of::<TLS>() is expected to divide PAGE_SIZE evenly.
const_assert_eq!(PAGE_SIZE % size_of::<TLS>(), 0);

/// TLS allocator
///
/// Each process holds a `TLSManager` in its [ProcessStruct].
///
/// When a thread is being created, we ask the `TLSManager` to allocate a TLS for it, and when
/// it dies we give it back to the manager so it can be re-used the next time this process spawns a thread.
///
/// When all of its TLS are occupied, the `TLSManager` will expend its memory by allocating a new page.
///
/// # Memory leak
///
/// The `TLSManager` will never free the pages it manages, and they are leaked when the `TLSManager` is dropped.
/// They will become available again after the process dies and its [ProcessMemory] is freed.
///
/// A `TLSManager` will always be dropped at process's death, at the same time as the `ProcessMemory`.
/// This prevents a dependency in the order in which the `TLSManager` and the `ProcessMemory` are dropped.
///
/// [ProcessStruct]: crate::process::ProcessStruct
#[derive(Debug, Default)]
pub struct TLSManager {
    /// Vec of tracked pages. When all slots are occupied, we allocate a new page.
    tls_pages: Vec<TLSPage>
}

impl TLSManager {
    /// Allocates a new TLS.
    ///
    /// This function will try to re-use free TLSs, and will only allocate when all TLS are in use.
    ///
    /// The returned TLS still has to be bzeroed, has it may contain the data of a previous thread.
    ///
    /// # Error
    ///
    /// Fails if the allocation fails.
    pub fn allocate_tls(&mut self, pmemory: &mut ProcessMemory) -> Result<VirtualAddress, KernelError> {
        for tls_page in &mut self.tls_pages {
            if let Some(tls) = tls_page.allocate_tls() {
                return Ok(tls);
            }
        }
        // no free slot, we need to allocate a new page.
        let mut new_tls_page = TLSPage::new(pmemory)?;
        let tls = new_tls_page.allocate_tls().expect("Empty TLSPage can't allocate");
        self.tls_pages.push(new_tls_page);
        Ok(tls)
    }


    /// Mark this TLS as free, so it can be re-used by future spawned thread.
    ///
    /// # Safety
    ///
    /// The TLS will be reassigned, so it must never be used again after calling this function.
    ///
    /// # Panics
    ///
    /// Panics if the TLS is not managed by this TLSManager, doesn't have a valid offset, or is already marked free.
    pub unsafe fn free_tls(&mut self, tls: VirtualAddress) {
        // round down ptr to find out which page in belongs to.
        let tls_page_ptr = tls.floor();
        for tls_page in &mut self.tls_pages {
            if tls_page.page_address == tls_page_ptr {
                tls_page.free_tls(tls);
                return;
            }
        }
        panic!("Freed TLS {:?} is not in TLSManager.", tls);
    }
}
