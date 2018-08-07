//! Virtual heap allocator.
//!
//! A simple wrapper around linked_list_allocator. We catch the OomError, and
//! try to expand the heap with more pages in that case.
use core::alloc::{GlobalAlloc, Layout, AllocErr};
use spin::{Mutex, Once};
use core::ops::Deref;
use core::ptr::NonNull;
use linked_list_allocator::{Heap, align_up};
use paging::{self, EntryFlags, ACTIVE_PAGE_TABLES, PageTablesSet, VirtualAddress};

pub struct Allocator(Once<Mutex<Heap>>);

// 512MB. Should be a multiple of PAGE_SIZE.
const RESERVED_HEAP_SIZE : usize = 512 * 1024 * 1024;

impl Allocator {
    /// Safely expands the heap if possible.
    fn expand(&self, by: usize) {
        let heap = self.0.call_once(Self::init);
        let heap_top = heap.lock().top();
        let heap_bottom = heap.lock().bottom();
        let new_heap_top = align_up(by, paging::PAGE_SIZE) + heap_top;

        assert!(new_heap_top - heap_bottom < RESERVED_HEAP_SIZE, "New heap grows over reserved heap size");

        info!("EXTEND {:#010x}", new_heap_top);

        for new_page in (heap_top..new_heap_top).step_by(paging::PAGE_SIZE) {
            let mut active_pages = paging::ACTIVE_PAGE_TABLES.lock();
            active_pages.unmap(VirtualAddress(new_page));
            active_pages.map_allocate_to(VirtualAddress(new_page), EntryFlags::WRITABLE);
        }
        unsafe {
            // Safety: We just allocated the area.
            heap.lock().extend(align_up(by, paging::PAGE_SIZE));
        }
    }

    fn init() -> Mutex<Heap> {
        let mut active_pages = ACTIVE_PAGE_TABLES.lock();
        // Reserve 512MB of virtual memory for heap space. Don't actually allocate it.
        let heap_space = active_pages.find_available_virtual_space::<paging::KernelLand>(RESERVED_HEAP_SIZE / paging::PAGE_SIZE).expect("Kernel should have 512MB of virtual memory");
        active_pages.map_allocate_to(heap_space, EntryFlags::WRITABLE);
        active_pages.map_range_page_guard(VirtualAddress(heap_space.addr() + paging::PAGE_SIZE), (RESERVED_HEAP_SIZE / paging::PAGE_SIZE) - 1);
        info!("Reserving {} pages at {:#010x}", RESERVED_HEAP_SIZE / paging::PAGE_SIZE - 1, heap_space.addr() + paging::PAGE_SIZE);
        unsafe {
            // Safety: Size is of 0, and the address is freshly guard-paged.
            Mutex::new(Heap::new(heap_space.addr(), paging::PAGE_SIZE))
        }
    }

    /// Creates a new heap based off of loader settings.
    pub const fn new() -> Allocator {
        Allocator(Once::new())
    }
}

impl Deref for Allocator {
    type Target = Mutex<Heap>;

    fn deref(&self) -> &Mutex<Heap> {
        &self.0.call_once(Self::init)
    }
}

unsafe impl<'a> GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // TODO: Race conditions.
        let allocation = self.0.call_once(Self::init).lock().allocate_first_fit(layout);
        let size = layout.size();
        // If the heap is exhausted, then extend and attempt the allocation another time.
        let alloc = match allocation {
            Err(AllocErr) => {
                self.expand(size); // TODO: how much should I *really* expand by?
                self.0.call_once(Self::init).lock().allocate_first_fit(layout)
            }
            _ => allocation
        }.ok().map_or(0 as *mut u8, |allocation| allocation.as_ptr());

        info!("ALLOC  {:#010x?}, size {:#x}", alloc, layout.size());
        alloc
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        info!("FREE   {:#010x?}, size {:#x}", ptr, layout.size());
        if cfg!(debug_assertions) {
            let p = ptr as usize;
            for i in p..(p + layout.size()) {
                *(i as *mut u8) = 0x7F;
            }
        }
        self.0.call_once(Self::init).lock().deallocate(NonNull::new(ptr).unwrap(), layout)
    }
}

// required: define how Out Of Memory (OOM) conditions should be handled
// *if* no other crate has already defined `oom`
#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_: Layout) -> ! {
    panic!("OOM")
}
