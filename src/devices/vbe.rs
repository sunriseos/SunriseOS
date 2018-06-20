//! VESA Bios Extensions Framebuffer

use core::slice;
use utils;
use i386::paging::{self, EntryFlags, PageTablesSet};
use frame_alloc::PhysicalAddress;
use multiboot2::{BootInformation, FramebufferInfoTag};

pub struct Framebuffer {
    buf: &'static mut [u8],
    tag: &'static FramebufferInfoTag
}

impl Framebuffer {
    /// Creates an instance of the linear framebuffer from a multiboot2 BootInfo.
    ///
    /// # Safety
    ///
    /// This function should only be called once, to ensure there is only a
    /// single mutable reference to the underlying framebuffer.
    pub unsafe fn new(boot_info: &BootInformation) -> Framebuffer {
        let tag = boot_info.framebuffer_info_tag().expect("Framebuffer to be provided");
        let framebuffer_size = tag.framebuffer_bpp() as usize * tag.framebuffer_dimensions().0 as usize * tag.framebuffer_dimensions().1 as usize / 8;
        let framebuffer_size_pages = utils::align_up(framebuffer_size, paging::PAGE_SIZE) / paging::PAGE_SIZE;
        let mut page_tables = paging::ACTIVE_PAGE_TABLES.lock();

        let framebuffer_vaddr = page_tables.find_available_virtual_space::<paging::KernelLand>(framebuffer_size_pages).expect("Hopefully there's some space");
        page_tables.map_range(PhysicalAddress(tag.framebuffer_addr()), framebuffer_vaddr, framebuffer_size_pages, EntryFlags::PRESENT | EntryFlags::WRITABLE);

        Framebuffer {
            buf: slice::from_raw_parts_mut(framebuffer_vaddr.addr() as *mut u8, framebuffer_size),
            tag
        }
    }

    pub fn width(&self) -> usize {
        self.tag.framebuffer_dimensions().0 as usize
    }

    pub fn get_fb(&mut self) -> &mut [u8] {
        self.buf
    }
}
