//! Userspace library
//!
//! Provides an allocator, various lang items.

#![no_std]
#![feature(asm, start, lang_items, panic_implementation, core_intrinsics)]

pub mod syscalls;


extern crate linked_list_allocator;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// Let's grant ourselves 10MB of heap
static mut ALLOCATOR_BUF: [u8; 10_000_000] = [0; 10_000_000];

fn init_heap() {
    unsafe {
        let heap_start = ALLOCATOR_BUF.as_ptr() as usize;
        let heap_size = ALLOCATOR_BUF.len();
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

use core::panic::PanicInfo;


#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

#[cfg(target_os = "none")]
#[panic_implementation] #[no_mangle]
pub extern fn panic_fmt(p: &::core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("HLT"); } }
}

use core::alloc::Layout;

// required: define how Out Of Memory (OOM) conditions should be handled
// *if* no other crate has already defined `oom`
#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_: Layout) -> ! {
    panic!("OOM")
}

#[cfg(target_os = "none")]
#[no_mangle]
pub unsafe extern fn start() -> ! {
    asm!("
        // Memset the bss. Hopefully memset doesn't actually use the bss...
        mov eax, BSS_END
        sub eax, BSS_START
        push eax
        push 0
        push BSS_START
        call memset
        add esp, 12
        " : : : : "intel", "volatile");

    extern {
        fn main(argc: isize, argv: *const *const u8) -> i32;
    }

    init_heap();
    main(0, core::ptr::null());

    // TODO: Exit
    loop {}
}

#[lang = "termination"]
trait Termination {
    fn report(self) -> i32;
}

impl Termination for () {
    #[inline]
    fn report(self) -> i32 { 0 }
}

#[lang = "start"]
fn main<T: Termination>(main: fn(), argc: isize, argv: *const *const u8) {
    main()
}
