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
//! marking some physical memory regions as reserved, either because of BIOS, MMIO
//! or simply because our kernel is loaded in it

use multiboot2::BootInformation;
use spin::Mutex;
use bit_field::BitArray;
use utils::BitArrayExt;
use utils::bit_array_first_one;
use paging::PAGE_SIZE;

/// Represents a Physical address
///
/// Should only be used when paging is off
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalAddress(pub usize);
/// Represents a Virtual address
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualAddress(pub usize);

impl VirtualAddress  { pub fn addr(&self) -> usize { self.0 } }
impl PhysicalAddress { pub fn addr(&self) -> usize { self.0 } }

impl ::core::ops::Add<usize> for VirtualAddress {
    type Output = VirtualAddress;

    fn add(self, other: usize) -> VirtualAddress {
        VirtualAddress(self.0 + other)
    }
}

impl ::core::ops::Add<usize> for PhysicalAddress {
    type Output = PhysicalAddress;

    fn add(self, other: usize) -> PhysicalAddress {
        PhysicalAddress(self.0 + other)
    }
}

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
unsafe fn frame_to_addr(frame: usize) -> Frame {
    let addr = frame << FRAME_BASE_LOG;
    Frame {
        physical_addr: addr,
    }
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
static FRAMES_BITMAP: Mutex<AllocatorBitmap> = Mutex::new(AllocatorBitmap {
    memory_bitmap: [0x00; FRAMES_BITMAP_SIZE],
    initialized: false,
});

/// A pointer to a physical frame
///
/// A frame is 4ko in size
///
/// Should only be used when paging is off
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    physical_addr: usize,
}

impl Frame {
    /// Get the physical address of this Frame
    pub fn address(&self) -> PhysicalAddress { PhysicalAddress(self.physical_addr) }

    /// Constructs a frame structure from a physical address
    ///
    /// This does not guaranty that the frame can be written to, or even exists at all
    ///
    /// # Panic
    ///
    /// Panics when the address is not framesize-aligned
    ///
    pub fn from_physical_addr(physical_addr: PhysicalAddress) -> Frame {
        assert_eq!(physical_addr.addr() % MEMORY_FRAME_SIZE, 0,
                   "Frame must be constructed from a framesize-aligned pointer");
        Frame { physical_addr: physical_addr.addr() }
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
        let elf_sections_tag = boot_info.elf_sections_tag()
            .expect("GRUB, you're drunk. Give us our elf_sections_tag.");
        for section in elf_sections_tag.sections() {
            FrameAllocator::mark_area_reserved(&mut frames_bitmap.memory_bitmap,
                                    section.start_address() as usize,
                                    section.end_address() as usize);
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
        unsafe {
            frame_to_addr(frame)
        }
    }

    /// Frees an allocated frame.
    ///
    /// # Panic
    ///
    /// Panics if the frame was not allocated
    pub fn free_frame(frame: Frame) {
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
