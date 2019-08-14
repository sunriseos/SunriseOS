//! Thread Local Storage on x86
//!
//! # Usage
//!
//! You declare a thread-local using the [#\[thread_local\] attribute] :
//!
//! ```
//! #[thread_local]
//! static MY_THREAD_LOCAL: core::cell::Cell<u8> = core::cell::Cell::new(42);
//! ```
//!
//! and access it as if it was a regular static, only that each thread will have its own view of
//! the static.
//!
//! The compiler is responsible for generating code that will access the right address, provided
//! we configured TLS correctly.
//!
//! ##### Early startup
//!
//! Note that you can't access a thread-local static before [`init_main_thread`] is called, because
//! the thread-local area for the main thread isn't initialized yet, and this will likely result to
//! a page fault or UB.
//!
//! # Inner workings
//!
//! We implement the TLS according to conventions laid out by [Ulrich Drepper's paper on TLS] which
//! is followed by LLVM and most compilers.
//!
//! Since we're running on i386, we're following variant II.
//!
//! Each thread's `gs` segment points to a thread local memory area where thread-local statics live.
//! thread-local statics are simply accessed through an offset from `gs`.
//!
//! The linker is in charge of creating an ELF segment of type `PT_TLS` where an initialization image
//! for cpu local regions can be found, and is meant to be copy-pasted for every thread we create.
//!
//! ##### on SunriseOS
//!
//! On Surnise, the area where `gs` points to is per-thread and user-controlled, we set it at the
//! startup of every thread with the [`set_thread_area`] syscall.
//!
//! The TLS initialisation image is supposed to be retrieved from our own program headers, which is
//! a really weird design.
//! Since we don't have access to our program headers, we instead use the linker to expose the following
//! symbols:
//!
//! * [`__tls_init_image_addr__`], `p_vaddr`: the address of our TLS initialisation image.
//! * [`__tls_file_size__`], `p_filesz`: the size of our TLS initialisation image.
//! * [`__tls_mem_size__`], `p_memsz`: the total size of our TLS segment.
//! * [`__tls_align__`], `p_align`: the alignment of our TLS segment.
//!
//! Those symbols are the addresses of the initialization in our `.tdata`, so it can directly be copied.
//!
//! ##### dtv and `__tls_get_addr`
//!
//! Since we don't do dynamic loading (yet ?), we know our TLS model will be static (either
//! Initial Exec or Local Exec).
//! Those models always access thread-locals directly via `gs`, and always short-circuit the dtv.
//!
//! So we don't even bother allocating a dtv array at all. Neither do we define a `__tls_get_addr`
//! function.
//!
//! This might change in the future when we will want to support dynamic loading.
//!
//! [`init_main_thread`]: crate::threads::init_main_thread
//! [`ARE_CPU_LOCALS_INITIALIZED_YET`]: self::cpu_locals::ARE_CPU_LOCALS_INITIALIZED_YET
//! [Ulrich Drepper's paper on TLS]: https://web.archive.org/web/20190710135250/https://akkadia.org/drepper/tls.pdf
//! [`set_thread_area`]: crate::syscalls::set_thread_area
//! [#\[thread_local\] attribute]: https://github.com/rust-lang/rust/issues/10310
//! [`__tls_init_image_addr__`]: self::thread_local_storage::__tls_init_image_addr__
//! [`__tls_file_size__`]: self::thread_local_storage::__tls_file_size__
//! [`__tls_mem_size__`]: self::thread_local_storage::__tls_mem_size__
//! [`__tls_align__`]: self::thread_local_storage::__tls_align__

use crate::syscalls;
use sunrise_libutils::div_ceil;
use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::mem::{align_of, size_of};
use core::fmt::Debug;

extern "C" {
    /// The address of the start of the TLS initialisation image in our `.tdata`.
    ///
    /// Because we don't want to read our own `P_TLS` program header,
    /// the linker provides a symbol for the start of the init image.
    ///
    /// This is an **absolute symbol**, which means its "address" is actually its value,
    /// i.e. to get a pointer do:
    ///
    /// ```ignore
    /// let tls_init_image_addr: *const u8 = unsafe { &__tls_init_image_addr__ as *const u8 };
    /// ```
    static __tls_init_image_addr__: u8;
    /// The size of the TLS initialisation image in our `.tdata`.
    ///
    /// Because we don't want to read our own `P_TLS` program header,
    /// the linker provides a symbol for the size of the init image.
    ///
    /// This is an **absolute symbol**, which means its "address" is actually its value,
    /// i.e. to get its value do:
    ///
    /// ```ignore
    /// let tls_init_image_size: usize = unsafe { &__tls_file_size__ as *const _ as usize };
    /// ```
    static __tls_file_size__: usize;
    /// The total memsize of the TLS segment: .tdata + .tbss
    ///
    /// Because we don't want to read our own `P_TLS` program header,
    /// the linker provides a symbol for the memsize of the TLS segment.
    ///
    /// This is an **absolute symbol**, which means its "address" is actually its value,
    /// i.e. to get its value do:
    ///
    /// ```ignore
    /// let tls_block_size = unsafe { &__tls_mem_size__ as *const _ as usize };
    /// ```
    static __tls_mem_size__: usize;
    /// The alignment of the TLS segment.
    ///
    /// Because we don't want to read our own `P_TLS` program header,
    /// the linker provides a symbol for the alignment it used.
    ///
    /// This is an **absolute symbol**, which means its "address" is actually its value,
    /// i.e. to get its value do:
    ///
    /// ```ignore
    /// let tls_align = unsafe { &__tls_align__ as *const _ as usize };
    /// ```
    static __tls_align__: usize;
}

/// The Thread Local Storage manager for a thread
///
/// We allocate one for every thread we create, and store it in the thread's context.
/// When it is dropped, all allocated memory is freed.
#[derive(Debug)]
pub struct TlsElf {
    /// The array of static module blocks + TCB
    static_region: ThreadLocalStaticRegion,
    // no dtv, no dynamics regions for now
}

impl TlsElf {
    /// Allocates and initializes the static region, including TCB.
    ///
    /// Finds out the location of the initialization image from linker defined symbols.
    pub fn allocate() -> Self {
        // copy tls static area
        let init_image_addr = unsafe {
            // safe: set by linker
            &__tls_init_image_addr__ as *const u8
        };
        let file_size = unsafe {
            // safe: set by the linker
            &__tls_file_size__ as *const _ as usize
        };
        let init_image = unsafe {
            // safe: - the initialization image will never be accessed mutably,
            //       - it lives in our .data so its lifetime is &'static,
            //       - u8 is POD and always aligned,
            //       => creating a const slice is ok.
            core::slice::from_raw_parts(init_image_addr, file_size)
        };
        let mem_size = unsafe {
            // safe: set by the linker
            &__tls_mem_size__ as *const _ as usize
        };
        let align = unsafe {
            // safe: set by the linker
            &__tls_align__ as *const _ as usize
        };

        let tls_static_region = ThreadLocalStaticRegion::allocate(
            init_image,
            mem_size,
            align);

        TlsElf {
            static_region: tls_static_region
        }
    }

    /// Calls [`syscalls::set_thread_area`] with the address of this TlsElf's [`ThreadControlBlock`].
    ///
    /// # Safety
    ///
    /// The TlsElf should not be enabled_for_current_thread by any other thread.
    /// Having a TLS shared by multiple threads is UB.
    ///
    /// # Panics
    ///
    /// Panics if the syscall returned an error, as this is unrecoverable.
    pub unsafe fn enable_for_current_thread(&self) {
        unsafe {
            // safe: TlsElf is RAII so self is a valid well-formed TLS region.
            //       However, we cannot guarantee that it's not used by anybody else,
            //       so propagate this constraint.
            syscalls::set_thread_area(self.static_region.tcb() as *const _ as usize)
                .expect("Cannot set thread TLS pointer");
        }
    }
}

/// The `round` function, as defined in section 3.0:
///
/// ```text
///     round(x,y) = y * ⌈x/y⌉
/// ```
///
/// Just a poorly-named `align_up`.
fn tls_align_up(x: usize, y: usize) -> usize {
    y * div_ceil(x, y)
}

/// Elf TLS TCB
///
/// The variant II leaves the specification of the ThreadControlBlock (TCB) to the implementor,
/// with the only requirement that the first word in the TCB, pointed by `tp`, contains its own
/// address, i.e. is a pointer to itself (GNU variant).
///
/// We don't need to store anything else in the TCB, it's just the self pointer.
#[repr(C)]
#[derive(Debug)]
struct ThreadControlBlock {
    /// Pointer containing its own address.
    tp_self_ptr: *const ThreadControlBlock,
}

/// Represents an allocated thread local static region.
///
/// Because TLS regions have a really specific layout, we don't use Box and instead interact with
/// the allocator directly. This type is the equivalent of a Box, it stores the pointer to the
/// allocated memory, and deallocates it on Drop.
struct ThreadLocalStaticRegion {
    /// Pointer to the allocated memory
    ptr: usize,
    /// Layout of the allocated memory. Used when deallocating.
    layout: Layout,
    /// Offset of the TCB in this allocation.
    tcb_offset: usize,
}

impl ThreadLocalStaticRegion {
    /// Returns a pointer to the [ThreadControlBlock] in the allocated region.
    /// All TLS arithmetic are done relative to this pointer.
    ///
    /// For TLS to work, the value stored at this address should be the address itself, i.e.
    /// having a pointer pointing to itself.
    fn tcb(&self) -> &ThreadControlBlock {
        unsafe {
            // safe: - guaranteed to be aligned, and still in the allocation,
            //       - no one should ever have a mut reference to the ThreadControlBlock after its
            //         initialisation.
            &*((self.ptr + self.tcb_offset) as *const ThreadControlBlock)
        }
    }

    /// Allocates a ThreadLocalStaticRegion.
    ///
    /// The region's content is copied from the TLS initialisation image described by `block_src`,
    /// padded with 0s for `block_size`, to which is appended a [`ThreadControlBlock`].
    ///
    /// The ThreadLocalStaticRegion uses `PT_TLS`'s `p_align` field passed in `block_align`
    /// to compute its layout and total size.
    ///
    /// ### Alignment
    ///
    /// ```text
    ///
    ///         V----------------------V  tls_align_up(tls_size_1, align_1)
    ///
    ///                                +-- gs:0
    ///                                |
    ///         +----------------------|-- tlsoffset_1 = gs:0 - tls_align_up(tls_size_1, align_1)
    ///         |                      |
    ///         V                      V
    ///
    ///         j----------------~-----j---------j
    ///    ...  |    tls_size_1  | pad |   TCB   |
    ///         j----------------~-----j---------j
    ///
    ///    ^    ^                      ^
    ///    |    |                      |
    ///    |    |                      +-- TCB_align: Determines alignment of everything.
    ///    |    |                          = max(align_of::<TCB>(), align_1). e.g. : 16.
    ///    |    |
    ///    |    +------------------------- TCB_align - n * align_1
    ///    |                               => still aligned to align_1 because TCB is aligned to align_1.
    ///    |
    ///    +------------------------------ alloc_align == TCB_align
    ///                                    => &TCB = &alloc + tls_align_up(gs:0 - tls_offset_1, TCB_align)
    ///
    ///    ^---^                           alloc_pad
    ///
    /// ```
    #[allow(clippy::cast_ptr_alignment)]
    fn allocate(block_src: &[u8], block_size: usize, block_align: usize) -> Self {
        let tls_offset1 = tls_align_up(block_size, block_align);
        let tcb_align = usize::max(align_of::<ThreadControlBlock>(), block_align);
        let tcb_offset = tls_align_up(tls_offset1, tcb_align);
        let alloc_pad_size = tcb_offset - tls_offset1;
        let layout = Layout::from_size_align(
            tcb_offset + size_of::<ThreadControlBlock>(),
            tcb_align
        ).unwrap();
        let alloc = unsafe {
            // safe: layout.size >= sizeof::<TCB> -> layout.size != 0
            alloc_zeroed(layout)
        };
        assert!(!alloc.is_null(), "thread_locals: failed static area allocation");

        unsafe {
            // safe: everything is done within our allocation, u8 is always aligned.
            // copy data
            core::ptr::copy_nonoverlapping(
                block_src as *const [u8] as *const u8,
                alloc.add(alloc_pad_size),
                block_src.len()
            );
            // .tbss + pad are already set to 0 by alloc_zeroed.
            // write tcb
            core::ptr::write(
                alloc.add(tcb_offset) as *mut ThreadControlBlock,
                ThreadControlBlock {
                    tp_self_ptr: alloc.add(tcb_offset) as *const ThreadControlBlock
                }
            );
        };
        Self {
            ptr: alloc as usize,
            layout,
            tcb_offset
        }
    }
}

impl Drop for ThreadLocalStaticRegion {
    /// Dropping a ThreadLocalStaticRegion deallocates it.
    fn drop(&mut self) {
        unsafe {
            // safe: - self.ptr is obviously allocated.
            //       - self.layout is the same argument that was used for alloc.
            dealloc(self.ptr as *mut u8, self.layout)
        };
    }
}

impl Debug for ThreadLocalStaticRegion {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("ThreadLocalStaticRegion")
            .field("start_address", &self.ptr)
            .field("tcb_address", &self.tcb())
            .field("total_size", &self.layout.size())
            .finish()
    }
}
