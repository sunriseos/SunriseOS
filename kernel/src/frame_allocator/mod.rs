//! Physical memory manager.
//!
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
//!
//! We do not distinguish between reserved and occupied frames.

use alloc::vec::Vec;
use crate::error::KernelError;
use crate::paging::PAGE_SIZE;
use crate::utils::{check_aligned, check_nonzero_length};
use crate::utils::AtomicBitmap;
use crate::mem::PhysicalAddress;
use crate::mem::{round_to_page, round_to_page_upper};
use crate::paging::kernel_memory::get_kernel_memory;
use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use failure::Backtrace;

pub mod physical_mem_region;
pub use self::physical_mem_region::{PhysicalMemRegion, PhysicalMemRegionIter};

/// The offset part in a [PhysicalAddress].
/// ```
/// let phys_address = PhysicalAddress(0xccccc567);
///
/// let offset_in_frame = phys_address & FRAME_OFFSET_MASK;
/// assert_eq!(offset_in_frame, 0x567);
/// ```
const FRAME_OFFSET_MASK: usize = 0xFFF;
/// The frame part in [PhysicalAddress].
/// ```
/// let phys_address = PhysicalAddress(0xccccc567);
///
/// let frame_addr = phys_address & FRAME_BASE_MASK;
/// assert_eq!(offset_in_frame, 0xccccc000);
/// ```
const FRAME_BASE_MASK:   usize = !FRAME_OFFSET_MASK;
/// The right shift to perform to a Physical address to get its frame id.
/// ```
/// let phys_address = PhysicalAddress(0xabcde567);
///
/// let frame_id = phys_address >> FRAME_BASE_LOG;
/// assert_eq!(frame_id, 0xabcde);
/// ```
const FRAME_BASE_LOG: usize = 12;

/// The size of the frames_bitmap in bits (~128ko)
#[cfg(not(test))]
const FRAMES_BITMAP_BITSIZE: usize = usize::max_value() / PAGE_SIZE - 1;

/// For unit tests we use a much smaller array.
#[cfg(test)]
const FRAMES_BITMAP_BITSIZE: usize = 32;

/// The size of the frames_bitmap in number of atomic elements.
const FRAMES_BITMAP_ARRSIZE: usize = FRAMES_BITMAP_BITSIZE / (core::mem::size_of::<AtomicUsize>() * 8);

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


/// The physical memory manager.
///
/// Serves physical memory in atomic blocks of size [PAGE_SIZE](crate::paging::PAGE_SIZE), called frames.
///
/// An allocation request returns a [PhysicalMemRegion], which represents a list of
/// physically adjacent frames. When this returned `PhysicalMemRegion` is eventually dropped
/// the frames are automatically freed and can be re-served by the FrameAllocator.
///
/// Up to 32 physically continuous frames may be allocated at a time.
pub struct InternalFrameAllocator {
    /// A big bitmap denoting for every frame if it is free or not
    ///
    /// 1 is free, 0 is already allocated/reserved
    /// This may seem backward, but this way when we start the array is filled with 0(reserved)
    /// and it can be put in the bss by the compiler
    memory_bitmap: [AtomicUsize; FRAMES_BITMAP_ARRSIZE],

    /// All operations have to check that the Allocator has been initialized
    initialized: AtomicBool
}

/// In the the bitmap, 1 means the frame is free.
const FRAME_FREE:     bool = true;
/// In the the bitmap, 0 means the frame is occupied.
const FRAME_OCCUPIED: bool = false;

/// A physical memory manger to allocate and free memory frames
// When running tests, each thread has its own view of the `FRAME_ALLOCATOR`.
static FRAME_ALLOCATOR : InternalFrameAllocator = InternalFrameAllocator::new();

impl InternalFrameAllocator {
    /// Called to initialize the [FRAME_ALLOCATOR] global.
    pub const fn new() -> Self {
        // Dumb workaround to initialize a huge array of AtomicUsize in const fn context.
        #[doc(hidden)]
        union ZeroedBuilder {
            atomic: [AtomicUsize; FRAMES_BITMAP_ARRSIZE],
            nonatomic: [usize; FRAMES_BITMAP_ARRSIZE],
        }

        #[doc(hidden)]
        const unsafe fn zeroed() -> [AtomicUsize; FRAMES_BITMAP_ARRSIZE] {
            ZeroedBuilder {
                nonatomic: [0; FRAMES_BITMAP_ARRSIZE]
            }.atomic
        }

        InternalFrameAllocator {
            // 0 is allocated/reserved. This is terrible and I feel bad.
            memory_bitmap: unsafe { zeroed() },
            initialized: AtomicBool::new(false),
        }
    }
}

impl InternalFrameAllocator {
    /// Frees an allocated physical region.
    ///
    /// # Panic
    ///
    /// * Panics if the frame was not allocated.
    /// * Panics if FRAME_ALLOCATOR was not initialized.
    pub fn free_region(&self, region: &PhysicalMemRegion) {
        // Don't do anything for empty regions. Those can be temporarily created
        // in allocate_frames_fragmented.
        if region.frames != 0 {
            debug!("Freeing {:?}", region);
            assert!(self.check_is_allocated(region.address(), region.size()), "PhysMemRegion beeing freed was not allocated");
            assert!(self.initialized.load(Ordering::SeqCst), "The frame allocator was not initialized");
            self.memory_bitmap.store_bits_nonatomic(
                addr_to_frame(region.address().addr())
                    ..
                    addr_to_frame(region.address().addr() + region.size()),
                FRAME_FREE);
        }
    }

    /// Checks that a physical region is marked allocated.
    ///
    /// Rounds address and length.
    ///
    /// # Panic
    ///
    /// * Panics if FRAME_ALLOCATOR was not initialized.
    pub fn check_is_allocated(&self, address: PhysicalAddress, length: usize) -> bool {
        assert!(self.initialized.load(Ordering::SeqCst), "The frame allocator was not initialized");
        (address.floor()..(address + length).ceil()).step_by(PAGE_SIZE).all(|frame| {
            let frame_index = addr_to_frame(frame.addr());
            self.memory_bitmap.load_bit(frame_index, Ordering::SeqCst) == FRAME_OCCUPIED
        })
    }

    /// Checks that a physical region is marked reserved.
    /// This implementation does not distinguish between allocated and reserved frames,
    /// so for us it's equivalent to `check_is_allocated`.
    ///
    /// Rounds address and length.
    ///
    /// # Panic
    ///
    /// * Panics if FRAME_ALLOCATOR was not initialized.
    pub fn check_is_reserved(&self, address: PhysicalAddress, length: usize) -> bool {
        // we have no way to distinguish between 'allocated' and 'reserved'
        self.check_is_allocated(address, length)
    }

    /// Prints the layout of the frame allocator.
    pub fn print(&self) {
        if log_enabled!(log::Level::Info) {
            info!("{:#?}", self)
        }
    }

    /// Allocates a single [PhysicalMemRegion].
    /// Frames are physically consecutive.
    ///
    /// # Error
    ///
    /// * Error if `length` == 0.
    /// * Error if `length` is not a multiple of [PAGE_SIZE].
    /// * Error if `length` is bigger than `size_of::<usize> * 8 * PAGE_SIZE`.
    ///
    /// # Panic
    ///
    /// * Panics if FRAME_ALLOCATOR was not initialized.
    #[allow(clippy::match_bool)]
    pub fn allocate_region(&self, length: usize) -> Result<PhysicalMemRegion, KernelError> {
        check_nonzero_length(length)?;
        check_aligned(length, PAGE_SIZE)?;
        let nr_frames = length / PAGE_SIZE;
        assert!(self.initialized.load(Ordering::SeqCst), "The frame allocator was not initialized");

        if let Some(start_index) = self.memory_bitmap.set_n_bits(nr_frames, FRAME_OCCUPIED) {
            let allocated = PhysicalMemRegion {
                start_addr: frame_to_addr(start_index),
                frames: nr_frames,
                should_free_on_drop: true
            };
            debug!("Allocated physical region: {:?}", allocated);
            return Ok(allocated);
        }
        info!("Failed physical allocation for {} consecutive frames", nr_frames);
        Err(KernelError::PhysicalMemoryExhaustion { backtrace: Backtrace::new() })
    }

    /// Allocates physical frames, possibly fragmented across several physical regions.
    ///
    /// # Error
    ///
    /// * Error if `length` == 0.
    /// * Error if `length` is not a multiple of [PAGE_SIZE].
    ///
    /// # Panic
    ///
    /// * Panics if FRAME_ALLOCATOR was not initialized.
    pub fn allocate_frames_fragmented(&self, length: usize) -> Result<Vec<PhysicalMemRegion>, KernelError> {
        check_nonzero_length(length)?;
        check_aligned(length, PAGE_SIZE)?;
        let requested = length / PAGE_SIZE;

        assert!(self.initialized.load(Ordering::SeqCst), "The frame allocator was not initialized");

        let mut collected_frames = 0;
        let mut collected_regions = Vec::new();
        let mut current_hole = PhysicalMemRegion { start_addr: 0, frames: 0, should_free_on_drop: true };
        // while requested is still obtainable.
        while addr_to_frame(current_hole.start_addr) + (requested - collected_frames) <= self.memory_bitmap.len() * core::mem::size_of::<AtomicUsize>() {
            while current_hole.frames < requested - collected_frames {
                // compute current hole's size
                let considered_frame = addr_to_frame(current_hole.start_addr) + current_hole.frames;
                if self.memory_bitmap.compare_and_swap(considered_frame, FRAME_FREE, FRAME_OCCUPIED, Ordering::SeqCst).is_ok() {
                    // expand current hole
                    current_hole.frames += 1;
                } else {
                    // we reached current hole's end
                    break;
                }
            }

            // make a copy, we're about to move the PhysMemRegion to the vec.
            let cur_hole_addr   = current_hole.start_addr;
            let cur_hole_frames = current_hole.frames;

            if current_hole.frames > 0 {
                // add it to our collected regions

                collected_frames += current_hole.frames;
                collected_regions.push(current_hole);
                if collected_frames == requested {
                    // we collected enough frames ! Succeed
                    info!("Allocated physical regions: {:?}", collected_regions);
                    return Ok(collected_regions)
                }
            }
            // advance the cursor
            current_hole = PhysicalMemRegion {
                start_addr: match cur_hole_addr.checked_add((cur_hole_frames + 1) * PAGE_SIZE) {
                    Some(sum_addr) => sum_addr,
                    None => break
                    // if it was the last frame, and the last to be considered:
                    // - it was free, and we already returned Ok.
                    // - it was occupied, we arrived here, and the add would overflow. We break and return PhysicalMemoryExhaustion.
                },
                frames: 0,
                should_free_on_drop: true
            };
        }
        info!("Failed physical allocation for {} non consecutive frames", requested);
        // collected_regions is dropped, marking them free again
        Err(KernelError::PhysicalMemoryExhaustion { backtrace: Backtrace::new() })
    }

    /// Marks a physical memory area as reserved and will never give it when requesting a frame.
    /// This is used to mark where memory holes are, or where the kernel was mapped
    ///
    /// # Panic
    ///
    /// Does not panic if it overwrites an existing reservation
    pub fn mark_area_reserved(&self,
                          start_addr: usize,
                          end_addr: usize) {
        // TODO: Fix tests.
        //assert!(!self.initialized.load(Ordering::SeqCst), "The frame allocator was already initialized");
        info!("Setting {:#010x}..{:#010x} to reserved", round_to_page(start_addr), round_to_page_upper(end_addr));
        self.memory_bitmap.store_bits_nonatomic(
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
    fn mark_area_free(&self,
                      start_addr: usize,
                      end_addr: usize) {
        //assert!(!self.initialized.load(Ordering::SeqCst), "The frame allocator was already initialized");
        info!("Setting {:#010x}..{:#010x} to available", round_to_page(start_addr), round_to_page_upper(end_addr));
        self.memory_bitmap.store_bits_nonatomic(
            addr_to_frame(round_to_page(start_addr))
                ..
                addr_to_frame(round_to_page_upper(end_addr)),
            FRAME_FREE);
    }
}

impl core::fmt::Debug for InternalFrameAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut cur = None;
        let mut f = f.debug_list();
        for (i, bit) in self.memory_bitmap.bit_iter().enumerate() {
            let curaddr = i * crate::paging::PAGE_SIZE;
            if bit == FRAME_FREE {
                // Area is available
                match cur {
                    None => cur = Some((FRAME_FREE, curaddr)),
                    Some((FRAME_OCCUPIED, last)) => {
                        f.entry(&format_args!("{:#010x} - {:#010x} OCCUPIED", last, curaddr));
                        cur = Some((FRAME_FREE, curaddr));
                    },
                    _ => ()
                }
            } else {
                // Area is occupied
                match cur {
                    None => cur = Some((FRAME_OCCUPIED, curaddr)),
                    Some((FRAME_FREE, last)) => {
                        f.entry(&format_args!("{:#010x} - {:#010x} AVAILABLE", last, curaddr));
                        cur = Some((FRAME_OCCUPIED, curaddr));
                    },
                    _ => ()
                }
            }
        }
        match cur {
            Some((FRAME_FREE, last)) => { f.entry(&format_args!("{:#010x} - {:#010x} AVAILABLE", last, 0xFFFFFFFFu32)); },
            Some((FRAME_OCCUPIED, last)) => { f.entry(&format_args!("{:#010x} - {:#010x} OCCUPIED", last, 0xFFFFFFFFu32)); },
            _ => ()
        }
        f.finish()
    }
}

/// Proxy to [InternalFrameAllocator]. Should be removed.
#[derive(Debug)]
pub struct FrameAllocator;

impl FrameAllocator {
    /// See [InternalFrameAllocator::allocate_region].
    pub fn allocate_region(length: usize) -> Result<PhysicalMemRegion, KernelError> {
        FRAME_ALLOCATOR.allocate_region(length)
    }

    /// See [InternalFrameAllocator::allocate_frames_fragmented].
    pub fn allocate_frames_fragmented(length: usize) -> Result<Vec<PhysicalMemRegion>, KernelError> {
        FRAME_ALLOCATOR.allocate_frames_fragmented(length)
    }

    /// Allocates a single frame. See [InternalFrameAllocator::allocate_region].
    pub fn allocate_frame() -> Result<PhysicalMemRegion, KernelError> {
        FRAME_ALLOCATOR.allocate_region(PAGE_SIZE)
    }

    /// See [InternalFrameAllocator::free_region].
    pub fn free_region(region: &PhysicalMemRegion) {
        FRAME_ALLOCATOR.free_region(region)
    }

    /// See [InternalFrameAllocator::check_is_allocated].
    pub fn check_is_allocated(address: PhysicalAddress, length: usize) -> bool {
        FRAME_ALLOCATOR.check_is_allocated(address, length)
    }

    /// See [InternalFrameAllocator::check_is_reserved].
    pub fn check_is_reserved(address: PhysicalAddress, length: usize) -> bool {
        FRAME_ALLOCATOR.check_is_reserved(address, length)
    }
}

/// Initialize the [FrameAllocator] by parsing the multiboot information
/// and marking some memory areas as unusable
#[cfg(not(test))]
pub fn init() {
    let boot_info = crate::arch::i386::multiboot::get_boot_information();
    let allocator = &FRAME_ALLOCATOR;

    info!("Accessing bootinfo");
    let memory_map_tag = boot_info.memory_map_tag()
        .expect("GRUB, you're drunk. Give us our memory_map_tag.");

    info!("Setting free memareas as free");
    for memarea in memory_map_tag.memory_areas() {
        if memarea.start_address() > u64::from(u32::max_value()) || memarea.end_address() > u64::from(u32::max_value()) {
            continue;
        }
        allocator.mark_area_free(memarea.start_address() as usize,
                                 memarea.end_address() as usize);
    }

    info!("Reserving everything mapped in KernelLand");
    // Reserve everything mapped in KernelLand
    get_kernel_memory().reserve_kernel_land_frames(&allocator);

    info!("Reserving the modules");
    // Don't free the modules. We need to keep the kernel around so we get symbols in panics!
    for module in boot_info.module_tags() {
        allocator.mark_area_reserved(module.start_address() as usize, module.end_address() as usize);
    }

    info!("Reserving the first page");
    // Reserve the very first frame for null pointers when paging is off
    allocator.mark_area_reserved(0x00000000,
                                 0x00000001);

    allocator.print();

    allocator.initialized.store(true, Ordering::SeqCst);
}

#[cfg(test)]
pub use self::test::init;

#[cfg(test)]
mod test {
    use super::*;

    const ALL_MEMORY: usize = FRAMES_BITMAP_BITSIZE * PAGE_SIZE;

    /// Initializes the `FrameAllocator` for testing.
    ///
    /// Every test that makes use of the `FrameAllocator` must call this function,
    /// and drop its return value when it is finished.
    pub fn init() -> FrameAllocatorInitialized {
        let mut allocator = &FRAME_ALLOCATOR;
        assert_eq!(allocator.initialized.load(Ordering::SeqCst), false, "frame_allocator::init() was called twice");

        // make it all available
        allocator.mark_area_free(0, ALL_MEMORY);

        // reserve one frame, in the middle, just for fun
        allocator.mark_area_reserved(PAGE_SIZE * 3, PAGE_SIZE * 3 + 1);

        allocator.initialized.store(true, Ordering::SeqCst);

        FrameAllocatorInitialized(())
    }

    /// Because tests are run in the same binary, a test might forget to re-initialize the frame allocator,
    /// which will cause it to run on the previous test's frame allocator state.
    ///
    /// We prevent that by returning a special structure that every test must keep in its scope.
    /// When the test finishes, it is dropped, and it automatically marks the frame allocator uninitialized again.
    #[must_use]
    pub struct FrameAllocatorInitialized(());

    impl ::core::ops::Drop for FrameAllocatorInitialized {
        fn drop(&mut self) { FRAME_ALLOCATOR.initialized.store(false, Ordering::SeqCst); }
    }

    /// The way you usually use it.
    #[test]
    #[ignore]
    fn ok() {
        let _f = crate::frame_allocator::init();

        let a = FrameAllocator::allocate_frame().unwrap();
        let b = FrameAllocator::allocate_region(2 * PAGE_SIZE).unwrap();
        let c_vec = FrameAllocator::allocate_frames_fragmented(3 * PAGE_SIZE).unwrap();

        drop(a);
        drop(b);
        drop(c_vec);
    }


    #[test]
    #[ignore]
    fn fragmented() {
        let _f = crate::frame_allocator::init();
        // make it all available
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_free(0, ALL_MEMORY);

        // reserve some frames in the middle
        allocator.mark_area_reserved(2 * PAGE_SIZE, 7 * PAGE_SIZE);
        drop(allocator);

        // force a fragmented allocation
        let frames = FrameAllocator::allocate_frames_fragmented(5 * PAGE_SIZE).unwrap();

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].address(), PhysicalAddress(0x00000000));
        assert_eq!(frames[0].size(), 2 * PAGE_SIZE);
        assert_eq!(frames[1].address(), PhysicalAddress(7 * PAGE_SIZE));
        assert_eq!(frames[1].size(), 3 * PAGE_SIZE);
    }

    /// You can't give it a size of 0.
    #[test]
    fn zero() {
        let _f = crate::frame_allocator::init();
        FrameAllocator::allocate_region(0).unwrap_err();
        FrameAllocator::allocate_frames_fragmented(0).unwrap_err();
    }

    #[test] #[should_panic] fn no_init_frame() { let _ = FrameAllocator::allocate_frame(); }
    #[test] #[should_panic] fn no_init_region() { let _ = FrameAllocator::allocate_region(PAGE_SIZE); }
    #[test] #[should_panic] fn no_init_fragmented() { let _ = FrameAllocator::allocate_frames_fragmented(PAGE_SIZE); }

    /// Allocation fails if Out Of Memory.
    #[test]
    fn physical_oom_frame() {
        let _f = crate::frame_allocator::init();
        // make it all reserved
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_reserved(0, ALL_MEMORY);
        drop(allocator);

        match FrameAllocator::allocate_frame() {
            Err(KernelError::PhysicalMemoryExhaustion { .. }) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        }
    }

    #[test]
    fn physical_oom_frame_threshold() {
        let _f = crate::frame_allocator::init();
        // make it all reserved
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_reserved(0, ALL_MEMORY);
        // leave only the last frame
        allocator.mark_area_free(ALL_MEMORY - PAGE_SIZE, ALL_MEMORY);
        drop(allocator);

        FrameAllocator::allocate_frame().unwrap();
    }

    #[test]
    fn physical_oom_region() {
        let _f = crate::frame_allocator::init();
        // make it all reserved
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_reserved(0, ALL_MEMORY);
        // leave only the last 3 frames
        allocator.mark_area_free(ALL_MEMORY - 3 * PAGE_SIZE,
                                 ALL_MEMORY);
        drop(allocator);

        match FrameAllocator::allocate_region(4 * PAGE_SIZE) {
            Err(KernelError::PhysicalMemoryExhaustion { .. }) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        }
    }

    #[test]
    fn physical_oom_region_threshold() {
        let _f = crate::frame_allocator::init();
        // make it all reserved
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_reserved(0, ALL_MEMORY);
        // leave only the last 3 frames
        allocator.mark_area_free(ALL_MEMORY - 3 * PAGE_SIZE,
                                 ALL_MEMORY);
        drop(allocator);

        FrameAllocator::allocate_region(3 * PAGE_SIZE).unwrap();
    }

    #[test]
    fn physical_oom_fragmented() {
        let _f = crate::frame_allocator::init();
        // make it all available
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_free(0, ALL_MEMORY);
        drop(allocator);

        match FrameAllocator::allocate_frames_fragmented(ALL_MEMORY + PAGE_SIZE) {
            Err(KernelError::PhysicalMemoryExhaustion { .. }) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        }
    }

    #[test]
    #[ignore]
    fn physical_oom_threshold_fragmented() {
        let _f = crate::frame_allocator::init();
        // make it all available
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_free(0, ALL_MEMORY);
        drop(allocator);

        FrameAllocator::allocate_frames_fragmented(ALL_MEMORY).unwrap();
    }

    #[test]
    #[ignore]
    fn allocate_last_frame() {
        let _f = crate::frame_allocator::init();
        // make it all available
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_free(0, ALL_MEMORY);

        // reserve all but last frame
        allocator.mark_area_reserved(0, ALL_MEMORY - PAGE_SIZE);
        drop(allocator);

        // check with allocate_frame
        let frame = FrameAllocator::allocate_frame().unwrap();
        drop(frame);

        // check with allocate_region
        let frame = FrameAllocator::allocate_region(PAGE_SIZE).unwrap();
        drop(frame);

        // check with allocate_frames_fragmented
        let frame = FrameAllocator::allocate_frames_fragmented(PAGE_SIZE).unwrap();
        drop(frame);

        // check we had really allocated *all* of it
        let frame = FrameAllocator::allocate_frame().unwrap();
        match FrameAllocator::allocate_frame() {
            Err(KernelError::PhysicalMemoryExhaustion {..} ) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        };
        drop(frame);
    }

    #[test]
    fn oom_hard() {
        let _f = crate::frame_allocator::init();
        // make it all reserved
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_reserved(0, ALL_MEMORY);

        // free only 1 frame in the middle
        allocator.mark_area_free(2 * PAGE_SIZE, 3 * PAGE_SIZE);
        drop(allocator);

        // check with allocate_region
        match FrameAllocator::allocate_region(2 * PAGE_SIZE) {
            Err(KernelError::PhysicalMemoryExhaustion { .. }) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        }

        // check with allocate_frame_fragmented
        match FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE) {
            Err(KernelError::PhysicalMemoryExhaustion { .. }) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        }

        // check we can still take only one frame
        let frame = FrameAllocator::allocate_frame().unwrap();
        match FrameAllocator::allocate_frame() {
            Err(KernelError::PhysicalMemoryExhaustion { .. }) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        }
        drop(frame);
    }

    /// This test checks the considered frames marked allocated by [allocate_frame_fragmented]
    /// are marked free again when the function fails.
    ///
    /// The function has a an optimisation checking at every point if the requested length is
    /// still obtainable, otherwise it want even bother marking the frames and fail directly.
    ///
    /// But we **do** want to mark the frames allocated, so our check has too be smart and work
    /// around this optimization.
    ///
    /// We do this by allocating the end of the bitmap, so [allocate_frame_fragmented] will
    /// realize it's going to fail only by the time it's half way through,
    /// and some frames will have been marked allocated.
    #[test]
    #[ignore]
    fn physical_oom_doesnt_leak() {
        let _f = crate::frame_allocator::init();
        // make it all available
        let mut allocator = &FRAME_ALLOCATOR;
        allocator.mark_area_free(0, ALL_MEMORY);
        drop(allocator);

        // allocate it all
        let half_left = FrameAllocator::allocate_region(ALL_MEMORY / 2).unwrap();
        let half_right = FrameAllocator::allocate_region(ALL_MEMORY / 2).unwrap();

        // check we have really allocated *all* of it
        match FrameAllocator::allocate_frame() {
            Err(KernelError::PhysicalMemoryExhaustion {..} ) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        };

        // free only the left half
        drop(half_left);

        // attempt to allocate more than the available half
        match FrameAllocator::allocate_frames_fragmented(ALL_MEMORY / 2 + PAGE_SIZE) {
            Err(KernelError::PhysicalMemoryExhaustion {..} ) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        };

        // we should be able to still allocate after an oom recovery.
        let half_left = FrameAllocator::allocate_frames_fragmented(  ALL_MEMORY / 2).unwrap();

        // and now memory is fully allocated again
        match FrameAllocator::allocate_frame() {
            Err(KernelError::PhysicalMemoryExhaustion {..} ) => (),
            unexpected_err => panic!("test failed: {:#?}", unexpected_err)
        };

        drop(half_left);
        drop(half_right);
    }
}
