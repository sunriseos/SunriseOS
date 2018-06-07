///! A module to allocate and free whole frames
///! A frame is 4ko in size

use multiboot2::BootInformation;
use spin::Mutex;
use bit_field::BitArray;
use utils::BitArrayExt;
use utils::bit_array_first_zero;

/// Represents a Physical address
/// Can only be used when paging is off
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalAddress(pub usize);
/// Represents a Virtual address
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualAddress(pub usize);

impl VirtualAddress  { pub fn addr(&self) -> usize { self.0 } }
impl PhysicalAddress { pub fn addr(&self) -> usize { self.0 } }

pub const MEMORY_FRAME_SIZE: usize = 4096;

const FRAME_OFFSET_MASK: usize = 0xFFF;              // The offset part in a frame
const FRAME_BASE_MASK:   usize = !FRAME_OFFSET_MASK; // The base part in a frame

const FRAME_BASE_LOG: usize = 12; // frame_number = addr >> 12

const FRAMES_BITMAP_SIZE: usize = usize::max_value() / MEMORY_FRAME_SIZE / 8 + 1;

#[inline]
fn addr_to_frame(addr: usize) -> usize {
    addr >> FRAME_BASE_LOG
}

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
#[inline]
pub fn round_to_page_upper(addr: usize) -> usize {
    match addr & FRAME_OFFSET_MASK {
        0 => round_to_page(addr),
        _ => round_to_page(addr) + MEMORY_FRAME_SIZE
    }
}

struct AllocatorBitmap {
    memory_bitmap: [u8; FRAMES_BITMAP_SIZE],
    initialized: bool,
}

static FRAMES_BITMAP: Mutex<AllocatorBitmap> = Mutex::new(AllocatorBitmap {
    memory_bitmap: [0x00; FRAMES_BITMAP_SIZE],
    initialized: false,
});

#[derive(Debug, Clone, Copy)]
pub struct Frame {
    physical_addr: usize,
}

impl Frame {
    /// This should only be called before the page table is setup.
    pub fn dangerous_as_physical_ptr(&self) -> *mut [u8] {
        unsafe { ::core::slice::from_raw_parts_mut(self.physical_addr as *mut u8, MEMORY_FRAME_SIZE) as _ }
    }

    pub fn from_physical_addr(physical_addr: PhysicalAddress) -> Frame {
        assert_eq!(physical_addr.addr() % MEMORY_FRAME_SIZE, 0,
                   "Frame must be constructed from a framesize-aligned pointer");
        Frame { physical_addr: physical_addr.addr() }
    }

    pub fn address(&self) -> PhysicalAddress { PhysicalAddress(self.physical_addr) }
}

/// A struct to allocate and free memory frames
/// A frame is 4ko in size
pub struct FrameAllocator;

impl FrameAllocator {

    /// Initialize the FrameAllocator by parsing the multiboot informations
    /// and marking some memory areas as unusable
    pub fn init(boot_info: &BootInformation) {
        let mut frames_bitmap = FRAMES_BITMAP.lock();

        let memory_map_tag = boot_info.memory_map_tag()
            .expect("GRUB, you're drunk. Give us our memory_map_tag.");
        for memarea in memory_map_tag.memory_areas() {
            FrameAllocator::mark_area_free(&mut frames_bitmap.memory_bitmap,
                                               memarea.start_address(),
                                               memarea.end_address());
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
        frames_bitmap.initialized = true
    }

    /// Panics if the frames bitmap was not initialized
    fn check_initialized(bitmap: &AllocatorBitmap) {
        if bitmap.initialized == false {
            panic!("The frame allocator was not initialized");
        }
    }

    /// Does not panic if it overwrites an existing reservation
    fn mark_area_reserved(bitmap: &mut [u8],
                          start_addr: usize,
                          end_addr: usize) {
        bitmap.set_bits_area(
                addr_to_frame(round_to_page(start_addr))
                    ..
                addr_to_frame(round_to_page_upper(end_addr)),
            true);
    }

    /// Does not panic if it overwrites an existing reservation
    fn mark_area_free(bitmap: &mut [u8],
                      start_addr: usize,
                      end_addr: usize) {
        bitmap.set_bits_area(
                addr_to_frame(round_to_page_upper(start_addr))
                    ..
                addr_to_frame(round_to_page(end_addr)),
            false);
    }

    /// Allocates a free frame
    pub fn alloc_frame() -> Frame {
        let mut frames_bitmap = FRAMES_BITMAP.lock();

        FrameAllocator::check_initialized(&*frames_bitmap);
        let frame = bit_array_first_zero(&frames_bitmap.memory_bitmap);
        if frame == frames_bitmap.memory_bitmap.len() {
            panic!("Cannot allocate frame: No available frame D:")
        }
        frames_bitmap.memory_bitmap.set_bit(frame, true);
        unsafe {
            frame_to_addr(frame)
        }
    }

    /// Frees an allocated frame.
    /// Panics if the frame was not allocated
    pub fn free_frame(frame: Frame) {
        let mut frames_bitmap = FRAMES_BITMAP.lock();
        FrameAllocator::check_initialized(&*frames_bitmap);

        // Check addr is a multiple of MEMORY_FRAME_SIZE
        assert_eq!(frame.physical_addr & FRAME_OFFSET_MASK, 0x000);
        let frame = addr_to_frame(frame.physical_addr);
        if frames_bitmap.memory_bitmap.get_bit(frame) == false {
            panic!("Frame being freed was not allocated");
        }
        frames_bitmap.memory_bitmap.set_bit(frame, false);
    }
}
