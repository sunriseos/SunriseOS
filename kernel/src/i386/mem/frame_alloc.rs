//! A module implementing a physical memory manager that allocates and frees memory frames
//!
//! We define a frame as the same size as a page, to make things easy for us.
//! This module can only allocate and free whole frames.
//!
//! It keeps tracks of the allocated frames by mean of a giant bitmap mapping every
//! physical memory frame in the address space to a bit representing if it is free or not.
//! This works because the address space in 32 bits is only 4GB, so ~1 million frames only
//!
//! During init we initialize the bitmap by parsing the information that the bootloader gives us and
//! marking some physical memory regions as reserved, either because of BIOS or MMIO.
//!
//! We also reserve everything that is mapped in KernelLand, assuming the bootstrap mapped it there
//! for us, and we don't want to overwrite it.

use multiboot2::BootInformation;
use sync::SpinLock;
use bit_field::BitArray;
use utils::BitArrayExt;
use utils::bit_array_first_one;
use paging::{PAGE_SIZE, ACTIVE_PAGE_TABLES, PageTablesSet};
pub use super::PhysicalAddress;

/// A memory frame is the same size as a page
pub const MEMORY_FRAME_SIZE: usize = PAGE_SIZE;

const FRAME_OFFSET_MASK: usize = 0xFFF;              // The offset part in a frame
const FRAME_BASE_MASK:   usize = !FRAME_OFFSET_MASK; // The base part in a frame

const FRAME_BASE_LOG: usize = 12; // frame_number = addr >> 12

/// The size of the frames_bitmap (~128ko)
const FRAMES_BITMAP_SIZE: usize = usize::max_value() / MEMORY_FRAME_SIZE / 8 + 1;

/// Gets the frame number from a physical address
#[inline]
fn addr_to_frame(addr: usize) -> usize {
    addr >> FRAME_BASE_LOG
}

/// Gets the physical address from a frame number
#[inline]
fn frame_to_addr(frame: usize) -> usize {
    frame << FRAME_BASE_LOG
}

/// Rounds an address to its page address
#[inline]
pub fn round_to_page(addr: usize) -> usize {
    addr & FRAME_BASE_MASK
}

/// Rounds an address to the next page address except if its offset in that page is 0
#[inline] pub fn round_to_page_upper(addr: usize) -> usize {
    match addr & FRAME_OFFSET_MASK {
        0 => round_to_page(addr),
        _ => round_to_page(addr) + MEMORY_FRAME_SIZE
    }
}

/// Counts the number of pages `size` takes
#[inline] pub fn count_pages(size: usize) -> usize {
    round_to_page_upper(size) / PAGE_SIZE
}

/// A big bitmap denoting for every frame if it is free or not
///
/// 1 is free, 0 is already allocated/reserved
/// This may seem backward, but this way when we start the array is filled with 0(reserved)
/// and it can be put in the bss by the compiler
struct AllocatorBitmap {
    memory_bitmap: [u8; FRAMES_BITMAP_SIZE],
    initialized: bool,
}

const FRAME_FREE:     bool = true;
const FRAME_OCCUPIED: bool = false;

/// A big bitmap denoting for every frame if it is free or not
static FRAMES_BITMAP: SpinLock<AllocatorBitmap> = SpinLock::new(AllocatorBitmap {
    memory_bitmap: [0x00; FRAMES_BITMAP_SIZE],
    initialized: false,
});

/// A pointer to a physical frame
///
/// A frame is 4ko in size
///
/// Should only be used when paging is off
#[derive(Debug)]
pub struct Frame {
    physical_addr: usize,
    is_allocated: bool
}

impl Drop for Frame {
    fn drop(&mut self) {
        if self.is_allocated {
            FrameAllocator::free_frame(self);
        }
    }
}

impl Frame {
    /// Get the physical address of this Frame
    pub fn address(&self) -> PhysicalAddress { PhysicalAddress(self.physical_addr) }

    // TODO: this should be a private implementation detail of the paging stuff.
    /// Gets the current allocation state
    pub(super) fn is_allocated(&self) -> bool {
        self.is_allocated
    }

    /// Constructs a frame structure from a physical address
    ///
    /// This does not guaranty that the frame can be written to, or even exists at all
    ///
    /// # Panic
    ///
    /// Panics when the address is not framesize-aligned
    // TODO: This should almost certainly be unsafe.
    pub fn from_physical_addr(physical_addr: PhysicalAddress) -> Frame {
        assert_eq!(physical_addr.addr() % MEMORY_FRAME_SIZE, 0,
                   "Frame must be constructed from a framesize-aligned pointer");
        // TODO: Check that it falls in a Reserved zone ?
        Frame { physical_addr: physical_addr.addr(), is_allocated: false }
    }

    /// Constructs a frame structure from a physical address
    ///
    /// This does not guaranty that the frame can be written to, or even exists at all
    ///
    /// # Panic
    ///
    /// Panics when the address is not framesize-aligned
    ///
    /// # Safety
    ///
    /// This function should only be used on physical_addr that are reserved -
    /// that is, addresses that the frame allocator will never give. Otherwise,
    /// it is unsound.
    pub unsafe fn from_allocated_addr(physical_addr: PhysicalAddress) -> Frame {
        Frame { physical_addr: physical_addr.addr(), is_allocated: true }
    }
}

/// A physical memory manger to allocate and free memory frames
pub struct FrameAllocator;

impl FrameAllocator {

    /// Initialize the FrameAllocator by parsing the multiboot information
    /// and marking some memory areas as unusable
    pub fn init(boot_info: &BootInformation) {
        let mut frames_bitmap = FRAMES_BITMAP.lock();

        let memory_map_tag = boot_info.memory_map_tag()
            .expect("GRUB, you're drunk. Give us our memory_map_tag.");
        for memarea in memory_map_tag.memory_areas() {
            if memarea.start_address() > u32::max_value() as u64 || memarea.end_address() > u32::max_value() as u64 {
                continue;
            }
            FrameAllocator::mark_area_free(&mut frames_bitmap.memory_bitmap,
                                               memarea.start_address() as usize,
                                               memarea.end_address() as usize);
        }

        // Reserve everything mapped in KernelLand
        drop(frames_bitmap); // prevent deadlock
        ACTIVE_PAGE_TABLES.lock().reserve_kernel_land_frames();
        let mut frames_bitmap = FRAMES_BITMAP.lock(); // retake the mutex

        // Don't free the modules. We need to keep the kernel around so we get symbols in panics!
        for module in boot_info.module_tags() {
            FrameAllocator::mark_area_reserved(&mut frames_bitmap.memory_bitmap,
                                               module.start_address() as usize, module.end_address() as usize);
        }

        // Reserve the very first frame for null pointers when paging is off
        FrameAllocator::mark_area_reserved(&mut frames_bitmap.memory_bitmap,
                                            0x00000000,
                                           0x00000001);

        if log_enabled!(::log::Level::Info) {
            let mut cur = None;
            for (i, bitmap) in frames_bitmap.memory_bitmap.iter().enumerate() {
                for j in 0..8 {
                    let curaddr = (i * 8 + j) * ::paging::PAGE_SIZE;
                    if bitmap & (1 << j) != 0 {
                        // Area is available
                        match cur {
                            None => cur = Some((FRAME_FREE, curaddr)),
                            Some((FRAME_OCCUPIED, last)) => {
                                info!("{:#010x} - {:#010x} OCCUPIED", last, curaddr);
                                cur = Some((FRAME_FREE, curaddr));
                            },
                            _ => ()
                        }
                    } else {
                        // Area is occupied
                        match cur {
                            None => cur = Some((FRAME_OCCUPIED, curaddr)),
                            Some((FRAME_FREE, last)) => {
                                info!("{:#010x} - {:#010x} AVAILABLE", last, curaddr);
                                cur = Some((FRAME_OCCUPIED, curaddr));
                            },
                            _ => ()
                        }
                    }
                }
            }
            match cur {
                Some((FRAME_FREE, last)) => info!("{:#010x} - {:#010x} AVAILABLE", last, 0xFFFFFFFFu32),
                Some((FRAME_OCCUPIED, last)) => info!("{:#010x} - {:#010x} OCCUPIED", last, 0xFFFFFFFFu32),
                _ => ()
            }
        }
        frames_bitmap.initialized = true
    }

    /// Panics if the frames bitmap was not initialized
    fn check_initialized(bitmap: &AllocatorBitmap) {
        if bitmap.initialized == false {
            panic!("The frame allocator was not initialized");
        }
    }

    /// Marks a physical memory area as reserved and will never give it when requesting a frame.
    /// This is used to mark where memory holes are, or where the kernel was mapped
    ///
    /// # Panic
    ///
    /// Does not panic if it overwrites an existing reservation
    fn mark_area_reserved(bitmap: &mut [u8],
                          start_addr: usize,
                          end_addr: usize) {
        info!("Setting {:#010x}..{:#010x} to reserved", round_to_page(start_addr), round_to_page_upper(end_addr));
        bitmap.set_bits_area(
                addr_to_frame(round_to_page(start_addr))
                    ..
                addr_to_frame(round_to_page_upper(end_addr)),
            FRAME_OCCUPIED);
    }

    /// Marks a physical memory area as free for frame allocation
    ///
    /// # Panic
    ///
    /// Does not panic if it overwrites an existing reservation
    fn mark_area_free(bitmap: &mut [u8],
                      start_addr: usize,
                      end_addr: usize) {
        info!("Setting {:#010x}..{:#010x} to available", round_to_page(start_addr), round_to_page_upper(end_addr));
        bitmap.set_bits_area(
                addr_to_frame(round_to_page_upper(start_addr))
                    ..
                addr_to_frame(round_to_page(end_addr)),
            FRAME_FREE);
    }

    /// Marks a physical memory frame as already allocated
    /// Currently used during init when paging marks KernelLand frames as alloc'ed by bootstrap
    ///
    /// # Panic
    ///
    /// Panics if it overwrites an existing reservation
    pub fn mark_frame_bootstrap_allocated(addr: PhysicalAddress) {
        debug!("Setting {:#010x} to boostrap allocked", addr.addr());
        assert_eq!(addr.addr() & FRAME_OFFSET_MASK, 0x000);
        let bit = addr_to_frame(addr.addr());
        let mut frames_bitmap = FRAMES_BITMAP.lock();
        if frames_bitmap.memory_bitmap.get_bit(bit) != FRAME_FREE {
            panic!("Frame being marked reserved was already allocated");
        }
        frames_bitmap.memory_bitmap.set_bit(bit, FRAME_OCCUPIED);
    }

    /// Allocates a free frame
    ///
    /// # Panic
    ///
    /// Panics if it cannot find a free frame.
    /// This is fine for now when we have plenty of memory and should not happen,
    /// but in the future we should return an Error type
    pub fn alloc_frame() -> Frame {
        let mut frames_bitmap = FRAMES_BITMAP.lock();

        FrameAllocator::check_initialized(&*frames_bitmap);
        let frame = bit_array_first_one(&frames_bitmap.memory_bitmap)
            .expect("Cannot allocate frame: No available frame D:");
        frames_bitmap.memory_bitmap.set_bit(frame, FRAME_OCCUPIED);
        debug!("Alloc'ed frame P {:#010x}", frame_to_addr(frame));
        Frame {
            physical_addr: frame_to_addr(frame),
            is_allocated: true
        }
    }

    /// Frees an allocated frame.
    ///
    /// # Panic
    ///
    /// Panics if the frame was not allocated
    fn free_frame(frame: &Frame) {
        debug!("Freeing frame P {:#010x}", frame.address().addr());
        let mut frames_bitmap = FRAMES_BITMAP.lock();
        FrameAllocator::check_initialized(&*frames_bitmap);

        // Check addr is a multiple of MEMORY_FRAME_SIZE
        assert_eq!(frame.physical_addr & FRAME_OFFSET_MASK, 0x000);
        let frame = addr_to_frame(frame.physical_addr);
        if frames_bitmap.memory_bitmap.get_bit(frame) == FRAME_FREE {
            panic!("Frame being freed was not allocated");
        }
        frames_bitmap.memory_bitmap.set_bit(frame, FRAME_FREE);
    }
}
