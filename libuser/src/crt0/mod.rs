//! libuser CRT0
//! This module is a minimal RT0 handling the entry point of the application.
//! It handles relocation, clean the bss and then finally call start_main.

pub mod relocation;

/// Executable entrypoint. Handle relocations and calls real_start.
#[cfg(target_os = "sunrise")]
#[naked]
#[no_mangle]
#[link_section = ".text.crt0"]
pub unsafe extern fn start() {
    core::arch::asm!("
    0:
        call 2f
    1:
        // As x86 has variable instruction length, this is going to be the offset to the aslr base
        .int . - start
        .int module_header - start
    2:
        pop eax

        // Save our thread handle passed by the kernel
        // `esi` is callee-saved
        mov esi, edx

        // Save 1b address
        mov ecx, [eax + 4]

        // Compute ASLR base because hey we don't have a choice
        sub eax, [eax]
        mov ebx, eax

        // Compute mod0 offset
        add ebx, ecx

        // Relocate the module
        push ebx
        push eax
        call relocate_self

        // Clean .bss
        push ebx
        call clean_bss

        // Init TLS
        push esi
        call init_main_thread

        call real_start
    ", options(noreturn));
}

/// Clean module bss.
/// NOTE: Even if the bss should be cleared before calling anything in Rust, all functions used here are guaranteed to not use the bss.
#[cfg(target_os = "sunrise")]
#[no_mangle]
#[link_section = ".text.crt0"]
pub unsafe extern fn clean_bss(module_header: *const relocation::ModuleHeader) {
    let module_header_address = module_header as *mut u8;
    let module_header = &(*module_header);

    let bss_start_address = module_header_address.add(module_header.bss_start_off as usize) as *mut u8;
    let bss_end_address = module_header_address.add(module_header.bss_end_off as usize) as *mut u8;

    let count = bss_end_address as usize - bss_start_address as usize;
    core::ptr::write_bytes(bss_start_address, 0, count);
}
